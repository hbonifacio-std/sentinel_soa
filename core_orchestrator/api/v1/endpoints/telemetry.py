"""
Módulo del Endpoint REST para la Ingesta de Telemetría.

Mapea las rutas HTTP de FastAPI encargadas de recibir ráfagas de líneas de log,
procesarlas e inyectarlas en el pipeline de análisis temporal.
"""

import logging
from typing import List, Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status, BackgroundTasks

from core_orchestrator.models.log_event import LogEvent
from core_orchestrator.services.preprocessor import LogPreprocessor
from core_orchestrator.services.window_manager import WindowManager
from core_orchestrator.agent.runner import agent_runner

logger = logging.getLogger("core_orchestrator.api.telemetry")

router = APIRouter()
# Instanciamos el gestor de ventanas del ciclo actual (ej. intervalos de 60 segundos)
window_manager = WindowManager(window_duration_seconds=60)


async def _process_and_evaluate_windows():
    """
    Función interna auxiliar encargada de realizar el corte analítico
    y gatillar el ciclo de evaluación del Agente Orquestador.
    """
    if window_manager.should_flush():
        logger.info("El intervalo temporal ha expirado. Procesando ventanas agregadas...")
        aggregated_windows = window_manager.flush_and_aggregate()
        
        for window in aggregated_windows:
            # Despachamos el payload serializado nativo directamente al Agente
            # El Agente se encargará de interactuar de forma aislada con su servidor MCP
            await agent_runner.run_analysis(window.model_dump())


@router.post("/", status_code=status.HTTP_202_ACCEPTED)
async def ingest_single_event(event: LogEvent, background_tasks: BackgroundTasks):
    """
    Recibe un único evento de telemetría y lo enruta a las ventanas en memoria.
    Endpoint optimizado para pruebas PoC y simulaciones de baja cadencia.
    """
    logger.info(f"Petición de ingesta de evento único recibida: {event.model_dump_json()}")
    
    window_manager.add_log_event(event)
    
    # Delegamos de forma no bloqueante la verificación y ejecución de ventanas al backend
    background_tasks.add_task(_process_and_evaluate_windows)
    
    return {
        "status": "accepted",
        "event_buffered": event.model_dump()
    }


@router.post("/ingest/raw", status_code=status.HTTP_202_ACCEPTED)
async def ingest_raw_logs(lines: List[str], background_tasks: BackgroundTasks):
    """
    Recibe un arreglo masivo de líneas crudas de logs (Common/Combined Log Format).
    Realiza el parsing asíncrono y enruta los eventos hacia las ventanas en memoria.
    """
    if not lines:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="El cuerpo de la solicitud no contiene registros."
        )

    logger.info(f"Petición de ingesta cruda recibida con {len(lines)} registros.")
    
    parsed_count = 0
    for line in lines:
        log_model = LogPreprocessor.parse_raw_line(line)
        if log_model:
            window_manager.add_log_event(log_model)
            parsed_count += 1

    logger.debug(f"Parsing completado con éxito. Eventos válidos: {parsed_count}/{len(lines)}")

    # Delegamos de forma no bloqueante la verificación y ejecución de ventanas al backend
    background_tasks.add_task(_process_and_evaluate_windows)

    return {
        "status": "accepted",
        "processed_records": len(lines),
        "valid_events_buffered": parsed_count
    }


@router.post("/flush", status_code=status.HTTP_200_OK)
async def manual_flush_windows():
    """
    Fuerza manualmente un corte de ventana temporal y ejecuta inmediatamente el triaje del Agente.
    Endpoint crítico para automatizaciones, flujos CI/CD y pruebas de caja negra (PoC).
    Devuelve veredictos técnicos profesionales en formato JSON con máximo detalle.
    
    ✅ MEJORA: Respuesta enriquecida con estructura completa y contexto detallado.
    """
    import json as json_module
    
    logger.warning("Solicitud de Flush manual invocada desde la API externa.")
    try:
        aggregated_windows = window_manager.flush_and_aggregate()
        reports_generated = 0
        
        results = []
        threat_stats = {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "none_count": 0,
            "total_indicators": 0
        }
        
        for window in aggregated_windows:
            report_str = await agent_runner.run_analysis(window.model_dump())
            
            # El agente ya devuelve JSON directamente
            try:
                threat_assessment = json_module.loads(report_str)
            except json_module.JSONDecodeError:
                # Fallback si el parser falla
                logger.warning(f"No se pudo parsear JSON del reporte para IP {window.source_ip}, usando fallback completo")
                threat_assessment = {
                    "window_id": str(window.window_id),
                    "source_ip": window.source_ip,
                    "threat_detected": False,
                    "threat_level": "NONE",
                    "threat_score": 0,
                    "kill_chain_phase": None,
                    "indicators_found": [],
                    "reasoning_summary": "Error al procesar análisis",
                    "recommendation": "Revisar logs del servidor",
                    "error": "Parse error"
                }
            
            # ✅ MEJORA: Enriquecer con contexto de ventana temporal
            detailed_result = {
                "source_ip": window.source_ip,
                "window_info": {
                    "window_id": str(window.window_id),
                    "start_time": window.window_start_utc.isoformat(),
                    "end_time": window.window_end_utc.isoformat(),
                    "total_requests": window.total_requests,
                    "unique_uris": len(window.unique_uris_requested),
                    "unique_user_agents": len(window.user_agents_observed),
                    "requests_per_second": window.requests_per_second_avg
                },
                "threat_assessment": threat_assessment,
                "http_patterns": {
                    "methods_distribution": window.http_methods_distribution,
                    "response_codes_distribution": window.response_codes_distribution,
                    "user_agents": window.user_agents_observed[:5],  # Top 5
                    "sample_uris": window.unique_uris_requested[:5]  # Sample
                }
            }
            
            # Estadísticas para el summary
            threat_level = threat_assessment.get("threat_level", "NONE")
            if threat_level == "CRITICAL":
                threat_stats["critical_count"] += 1
            elif threat_level == "HIGH":
                threat_stats["high_count"] += 1
            elif threat_level == "MEDIUM":
                threat_stats["medium_count"] += 1
            elif threat_level == "LOW":
                threat_stats["low_count"] += 1
            else:
                threat_stats["none_count"] += 1
            
            threat_stats["total_indicators"] += len(threat_assessment.get("indicators_found", []))
            
            results.append(detailed_result)
            reports_generated += 1

        return {
            "status": "success",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "windows_flushed": len(aggregated_windows),
            "evaluations_triggered": reports_generated,
            "threat_summary": {
                "critical_threats": threat_stats["critical_count"],
                "high_threats": threat_stats["high_count"],
                "medium_threats": threat_stats["medium_count"],
                "low_threats": threat_stats["low_count"],
                "clean": threat_stats["none_count"],
                "total_unique_indicators": threat_stats["total_indicators"],
                "overall_threat_status": "🔴 CRITICAL" if threat_stats["critical_count"] > 0 
                                        else "🟠 HIGH" if threat_stats["high_count"] > 0
                                        else "🟡 MEDIUM" if threat_stats["medium_count"] > 0
                                        else "🟢 CLEAN"
            },
            "details": results
        }
    except Exception as exc:
        logger.error(f"Falla crítica en endpoint de flush manual: {str(exc)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno durante el vaciado síncrono: {str(exc)}"
        )
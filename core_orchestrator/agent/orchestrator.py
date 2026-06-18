"""
Módulo del Agente Orquestador Central Basado en Gemini.

Administra el bucle de razonamiento de IA, traduciendo los requerimientos
de seguridad en llamadas a herramientas MCP y consolidando el veredicto final.
"""

import logging
import json
from typing import Dict, Any, List

from core_orchestrator.models.alert_response import AlertResponseSchema
from core_orchestrator.services.database import db
import google.generativeai as genai


from core_orchestrator.config import orchestrator_settings as settings
from core_orchestrator.agent.mcp_client import MCPClientManager

logger = logging.getLogger("core_orchestrator.agent.orchestrator")


class GeminiOrchestratorAgent:
    """
    Controlador del Agente Gemini encargado de la orquestación e invocación
    de herramientas bajo el protocolo MCP.
    """

    def __init__(self, mcp_manager: MCPClientManager):
        """
        Inicializa el agente configurando la API Key y el cliente MCP asociado.
        """
        genai.configure(api_key=settings.gemini_api_key.get_secret_value())
        self.model_name = "gemini-3.1-flash-lite"
        self.mcp_manager = mcp_manager

        # Configuración de hiperparámetros para forzar respuestas técnicas estructuradas
        self.generation_config = {
            "temperature": 0.1,
            "top_p": 0.95,
            "max_output_tokens": 1500,
            "response_mime_type": "application/json",
            "response_schema": AlertResponseSchema,
        }

    async def get_redis_lock(self, lock_key: str, timeout: int = 10):
        """
        Adquiere un bloqueo distribuido usando Redis.
        """
        return db.redis_client.lock(lock_key, timeout=timeout)

    async def process_telemetry_window(self, telemetry_payload: Dict[str, Any]) -> str:
        """
        Inicia el ciclo de razonamiento analítico para una ventana temporal de telemetría.
        """
        source_ip = telemetry_payload.get("source_ip", "UNKNOWN")
        logger.info(
            f"Agente Orquestador activado para analizar la IP: {source_ip}")

        try:
            # --- PASO 0: Comprobar la caché de Redis ---
            cache_key = f"cache:analysis:{json.dumps(telemetry_payload, sort_keys=True, default=str)}"
            cached_result = await db.redis_client.get(cache_key)
            if cached_result:
                logger.info(
                    f"Resultado de análisis encontrado en caché para {source_ip}.")
                return cached_result.decode('utf-8')

            # --- PASO 1: Ejecución obligatoria de la primera herramienta analítica ---
            logger.info(
                f"Paso 1: Solicitando análisis de actividad web para {source_ip}")

            raw_analysis_result = await self.mcp_manager.call_tool(
                tool_name="analyze_web_activity",
                arguments=telemetry_payload
            )

            analysis_result: Dict[str, Any] = {}
            if hasattr(raw_analysis_result, "content") and raw_analysis_result.content:
                try:
                    analysis_result = json.loads(
                        raw_analysis_result.content[0].text)
                except (json.JSONDecodeError, IndexError, AttributeError):
                    logger.error(
                        f"No se pudo parsear el JSON de analyze_web_activity. Usando fallback vacío.")
                    analysis_result = {
                        "threat_detected": False, "threat_score": 0}
            else:
                analysis_result = raw_analysis_result if isinstance(
                    raw_analysis_result, dict) else {}

            logger.info(
                f"Análisis completado para {source_ip}: threat_detected={analysis_result.get('threat_detected')}, "
                f"score={analysis_result.get('threat_score', 'N/A')}%")

            # --- PASO 2: Si se detectó amenaza, obtener contexto histórico ---
            if analysis_result.get("threat_detected", False):
                logger.info(
                    f"Paso 2: Amenaza detectada. Solicitando contexto histórico para {source_ip}")

                raw_context_result = await self.mcp_manager.call_tool(
                    tool_name="get_threat_context",
                    arguments={"source_ip": source_ip, "limit": 5}
                )

                context_result: Dict[str, Any] = {}
                if hasattr(raw_context_result, "content") and raw_context_result.content:
                    try:
                        context_result = json.loads(
                            raw_context_result.content[0].text)
                    except (json.JSONDecodeError, IndexError, AttributeError):
                        context_result = {"history": []}
                else:
                    context_result = raw_context_result if isinstance(
                        raw_context_result, dict) else {}

                analysis_result["threat_history"] = context_result.get(
                    "history", [])
                logger.info(
                    f"Contexto histórico agregado: {len(context_result.get('history', []))} alertas previas")

            # --- PASO 3: Guardar el resultado en MongoDB y cachearlo en Redis ---
            final_report_json = json.dumps(
                analysis_result, indent=2, ensure_ascii=False, default=str)

            # Guardar en MongoDB
            await db.mongo_client.sentinel_soa.analysis_reports.insert_one(analysis_result)

            # Guardar en caché de Redis
            # Cache por 5 minutos
            await db.redis_client.set(cache_key, final_report_json, ex=300)

            logger.debug(
                f"Retornando análisis y guardándolo en la base de datos para {source_ip}")
            return final_report_json

        except Exception as exc:
            logger.error(
                f"Falla durante el ciclo de razonamiento del Agente Orquestador: {str(exc)}", exc_info=True)
            return json.dumps({
                "status": "error",
                "error": str(exc),
                "source_ip": source_ip,
                "threat_detected": False,
                "threat_level": "NONE"
            }, ensure_ascii=False)

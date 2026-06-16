"""
Módulo de la herramienta MCP para el análisis avanzado de actividad web.

Este archivo contiene la implementación de la herramienta 'analyze_web_activity',
la cual procesa ventanas agregadas de telemetría HTTP utilizando inteligencia artificial
para identificar fases tempranas del modelo Cyber Kill Chain.

Soporta múltiples proveedores LLM (Gemini, Ollama, etc.) mediante factory pattern.
"""

import logging
import json
from typing import Dict, Any, Optional

from mcp_servers.log_analysis_server.config import server_settings as settings
from mcp_servers.log_analysis_server.models.analysis_input import WebActivityWindowInput as AnalysisInput
from mcp_servers.log_analysis_server.models.analysis_output import ThreatAssessment as AnalysisOutput
from mcp_servers.log_analysis_server.services.gemini_client import GeminiClient
# Nota: PromptBuilder ya no se importa directamente aquí porque la lógica se encapsuló en los proveedores
from mcp_servers.log_analysis_server.services.heuristics_engine import ThreatHeuristics
from mcp_servers.log_analysis_server.store.alert_store import InMemoryAlertStore as AlertStore
from mcp_servers.log_analysis_server.llm_providers import create_llm_provider

# Configuración del logger local
logger = logging.getLogger(__name__)

# Instancia global del almacén de alertas
alert_store = AlertStore()


def _generate_recommendation(threat_level: str, source_ip: str, indicators: list) -> str:
    """Genera una recomendación de mitigación basada en el nivel de amenaza y indicadores específicos."""

    # ✅ MEJORA: Análisis de indicadores específicos para recomendaciones más dicientes
    has_sql_injection = any("SQL" in ind for ind in indicators)
    has_path_traversal = any("path traversal" in ind.lower() for ind in indicators)
    has_scanner = any("Scanner" in ind or "scanning" in ind.lower() for ind in indicators)
    has_admin_access = any("admin" in ind.lower() for ind in indicators)
    has_shell = any("shell" in ind.lower() or "webshell" in ind.lower() for ind in indicators)

    if threat_level == "CRITICAL":
        recommendation = (
            f"🔴 **NIVEL CRÍTICO - ACCIÓN INMEDIATA REQUERIDA**\n"
            f"IP de Origen: {source_ip}\n\n"
            f"**Nivel 1 (Immediatamente - 0-5 minutos):**\n"
        )
        if has_shell:
            recommendation += f"• BLOQUEAR INMEDIATAMENTE en WAF/Firewall. Evidencia de intento de webshell detectado.\n"
        elif has_sql_injection:
            recommendation += f"• BLOQUEAR INMEDIATAMENTE en WAF/Firewall. Ataque de inyección SQL en curso.\n"
        elif has_path_traversal:
            recommendation += f"• BLOQUEAR INMEDIATAMENTE en WAF/Firewall. Intento de acceso a archivos sensibles del sistema.\n"
        else:
            recommendation += f"• BLOQUEAR INMEDIATAMENTE la IP {source_ip} en todos los puntos de entrada (WAF/Firewall).\n"

        recommendation += (
            f"• Verificar si el ataque fue exitoso (revisar response codes 200/500).\n"
            f"• Preparar equipo de respuesta de incidentes.\n\n"
            f"**Nivel 2 (En paralelo - 5-30 minutos):**\n"
            f"• Ejecutar análisis forense: revisar logs de acceso de los últimos 24 horas.\n"
            f"• Correlacionar con otras IPs sospechosas o patrones similares.\n"
            f"• Verificar integridad de archivos del servidor (web.config, .env, etc).\n"
            f"• Revisar eventos de modificación de archivos en ACLs.\n\n"
            f"**Nivel 3 (Escalación - 30+ minutos):**\n"
            f"• Escalar a equipo de ciberseguridad y liderazgo de TI.\n"
            f"• Considerar snapshot del servidor para análisis de malware.\n"
            f"• Iniciar investigación de compromiso potencial.\n"
        )
    elif threat_level == "HIGH":
        recommendation = (
            f"🟠 **NIVEL ALTO - ACCIÓN URGENTE RECOMENDADA**\n"
            f"IP de Origen: {source_ip}\n\n"
            f"**Nivel 1 (Inmediatamente):**\n"
            f"• Bloquear la IP {source_ip} de forma temporal en el WAF/Firewall por 24 horas.\n"
        )
        if has_scanner:
            recommendation += f"• Implementar rate-limiting más agresivo. Se detectó patrón de enumeración/scanning.\n"
        if has_admin_access:
            recommendation += f"• Revisar urgentemente acceso a paneles administrativos.\n"
        recommendation += (
            f"\n**Nivel 2 (Próximas 2 horas):**\n"
            f"• Auditar todos los recursos solicitados por esta IP.\n"
            f"• Revisar logs de los últimos 24 horas de esta fuente.\n"
            f"• Verificar si endpoints administrativos están protegidos (autenticación + 2FA).\n"
            f"• Confirmar que WAF rules están activadas para inyección SQL/XSS.\n\n"
            f"**Nivel 3 (Vigilancia continuada):**\n"
            f"• Monitorear comportamiento futuro de esta IP por próximos 7 días.\n"
            f"• Considerar bloqueo permanente si persisten intentos.\n"
        )
    elif threat_level == "MEDIUM":
        recommendation = (
            f"🟡 **NIVEL MEDIO - MONITOREO RECOMENDADO**\n"
            f"IP de Origen: {source_ip}\n\n"
            f"**Acciones Recomendadas:**\n"
            f"• Aumentar monitoreo de la IP {source_ip}. Comportamiento sospechoso detectado.\n"
            f"• Implementar rate-limiting en endpoints web.\n"
            f"• Revisar logs recientes (últimas 6 horas).\n"
            f"• Considerar bloqueo temporal de 24-48 horas si se repite patrón.\n"
            f"• Verificar que WAF/IDS está capturando eventos y alertando correctamente.\n"
        )
    else:
        recommendation = (
            f"🟢 **NIVEL BAJO/BENIGNO**\n"
            f"Tráfico clasificado como benigno o sospecha muy baja. "
            f"Continuar con monitoreo rutinario estándar.\n"
            f"No se requiere acción inmediata.\n"
        )

    return recommendation


class LLMAnalyzer:
    """
    Encapsula la lógica de invocación del proveedor LLM.

    Soporta múltiples proveedores (Gemini, Ollama, etc.) basado en configuración.
    Proporciona un método agnóstico de análisis que funciona con cualquier proveedor.
    """

    _provider = None

    @classmethod
    def _get_provider(cls):
        """Obtener o crear el proveedor LLM configurado."""
        if cls._provider is None:
            config = settings.get_provider_config()
            cls._provider = create_llm_provider(settings.llm_provider, config)
            logger.info(f"Proveedor LLM inicializado: {settings.llm_provider}")
        return cls._provider

    @classmethod
    async def analyze_with_context(cls, telemetry: Any, history: list) -> Dict[str, Any]:
        """
        Realiza el análisis solicitando el prompt específico al proveedor activo
        y llamando al modelo.
        """
        try:
            provider = cls._get_provider()
            logger.debug(f"Enviando análisis a proveedor: {provider.provider_name}")

            # 🔥 CAMBIO CLAVE: El proveedor genera su propio prompt situacional de forma polimórfica
            prompt = provider.build_analysis_prompt(telemetry, history)

            # Invocar el proveedor con el prompt generado
            response_text = await provider.call_model(prompt)

            # Validar respuesta
            validated_response = await provider.validate_response(response_text)

            # Convertir a diccionario
            return validated_response.model_dump()

        except Exception as exc:
            logger.error(f"Error en LLMAnalyzer.analyze_with_context: {str(exc)}", exc_info=True)
            raise


async def execute_analyze_web_activity(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ejecuta el análisis heurístico y de IA sobre una ventana de actividad web sospechosa.
    """
    try:
        # 1. Validación estática estricta mediante el modelo Pydantic v2
        analysis_input = AnalysisInput(**arguments)
        source_ip = analysis_input.source_ip
        window_id = analysis_input.window_id
        logger.info(f"Iniciando herramienta 'analyze_web_activity' para IP: {source_ip} (Ventana: {window_id})")

        # ========================================================================
        # 2. ANÁLISIS HEURÍSTICO DETERMINISTA (Baseline de confianza)
        # ========================================================================
        logger.debug(f"[HEURÍSTICAS] Ejecutando motor determinista para {source_ip}...")
        heuristic_score, heuristic_indicators, heuristic_reasoning = ThreatHeuristics.analyze(analysis_input)
        logger.info(f"[HEURÍSTICAS] Score: {heuristic_score}/100 | Indicadores: {len(heuristic_indicators)}")

        # ========================================================================
        # 3. ENRIQUECIMIENTO DE CONTEXTO TEMPORAL: historial de alertas previas
        # ========================================================================
        threat_history = alert_store.get_history_by_ip(source_ip, limit=5)
        logger.debug(f"Historial de alertas previas para {source_ip}: {len(threat_history)} registros")

        # ========================================================================
        # 4. ENVÍO DE DATOS DIRECTOS AL PROVEEDOR LLM (Lógica interna delegada)
        # ========================================================================
        logger.debug(f"Enviando payload de telemetría de {source_ip} a {settings.llm_provider} API.")

        # Try LLM analysis, fallback to pure heuristics if it fails
        raw_assessment = None
        try:
            # 🔥 CAMBIO CLAVE: Ya no construimos el prompt aquí afuera. Delegamos la telemetría y el
            # historial directamente al LLMAnalyzer para que el proveedor decida cómo empaquetarlo.
            raw_assessment = await LLMAnalyzer.analyze_with_context(
                telemetry=analysis_input,
                history=threat_history
            )
            logger.debug(
                f"Respuesta del LLM recibida: {json.dumps(raw_assessment, indent=2, ensure_ascii=False)[:300]}...")
        except Exception as llm_err:
            logger.warning(f"LLM analysis falló, usando fallback de heurísticas: {str(llm_err)}")
            raw_assessment = None

        # ========================================================================
        # 5. CONSTRUCCIÓN DEL VEREDICTO HÍBRIDO (HEURÍSTICAS + LLM OPCIONAL)
        # ========================================================================

        # Si el LLM falló o no devolvió respuesta, usar puramente heurísticas
        if raw_assessment is None:
            logger.info(f"Usando análisis puramente heurístico para {source_ip}")

            # Determinar threat_level basado en heuristic_score
            if heuristic_score >= 70:
                threat_level = "CRITICAL" if heuristic_score >= 90 else "HIGH"
                threat_detected = True
                kill_chain_phase = "Reconnaissance"
            elif heuristic_score >= 40:
                threat_level = "MEDIUM"
                threat_detected = True
                kill_chain_phase = "Reconnaissance"
            elif heuristic_score >= 20:
                threat_level = "LOW"
                threat_detected = True
                kill_chain_phase = None
            else:
                threat_level = "NONE"
                threat_detected = False
                kill_chain_phase = None

            raw_assessment = {
                "window_id": str(window_id),
                "threat_detected": threat_detected,
                "threat_level": threat_level,
                "threat_score": heuristic_score,
                "kill_chain_phase": kill_chain_phase,
                "indicators_found": heuristic_indicators[:10],
                "reasoning_summary": heuristic_reasoning[:500],
                "recommendation": _generate_recommendation(threat_level, source_ip, heuristic_indicators)
            }
        else:
            # El LLM devolvió una respuesta, enriquecerla con heurísticas

            # Asegurar que threat_score existe
            if "threat_score" not in raw_assessment:
                logger.warning(f"LLM no devolvió threat_score, usando valor heurístico: {heuristic_score}")
                raw_assessment["threat_score"] = heuristic_score

            # Validar coherencia entre threat_detected y threat_score
            threat_score = raw_assessment.get("threat_score", heuristic_score)
            threat_detected = raw_assessment.get("threat_detected", False)

            # Entrecruzar lógica
            if threat_score >= 70 and not threat_detected:
                logger.warning(f"Inconsistencia: threat_score={threat_score} pero threat_detected=False. Corrigiendo.")
                raw_assessment["threat_detected"] = True
                raw_assessment["threat_level"] = "HIGH"

            if threat_score < 20 and threat_detected:
                logger.warning(f"Inconsistencia: threat_score={threat_score} pero threat_detected=True. Corrigiendo.")
                raw_assessment["threat_detected"] = False
                raw_assessment["threat_level"] = "NONE"

            # Enriquecer con indicadores heurísticos si es necesario
            if not raw_assessment.get("indicators_found") or len(raw_assessment.get("indicators_found", [])) == 0:
                logger.debug(f"Enriqueciendo indicadores vacíos con heurísticas")
                raw_assessment["indicators_found"] = heuristic_indicators[:10]

        # Validación e instanciación del modelo output
        analysis_output = AnalysisOutput(**raw_assessment)

        # ========================================================================
        # 6. PERSISTENCIA DE ALERTAS IF DETECTED
        # ========================================================================
        if analysis_output.threat_detected:
            logger.warning(
                f"[⚠ ALERTA GENERADA] Amenaza detectada de {source_ip}. "
                f"Nivel: {analysis_output.threat_level} | Score: {analysis_output.threat_score}% | "
                f"Fase: {analysis_output.kill_chain_phase}"
            )
            alert_store.add_assessment(source_ip, analysis_output)
        else:
            logger.info(
                f"[✓ LIMPIO] No se detectaron amenazas para {source_ip} (score: {analysis_output.threat_score}%)")

        # Retornamos el diccionario primitivo validado exigido por el protocolo MCP
        result = analysis_output.model_dump()
        logger.debug(
            f"Resultado final para {source_ip}: threat_detected={result.get('threat_detected')}, score={result.get('threat_score')}%")

        return result

    except ValueError as val_err:
        logger.error(f"Error de validación de esquemas en 'analyze_web_activity': {str(val_err)}")
        raise ValueError(f"Argumentos inválidos para la herramienta: {str(val_err)}") from val_err

    except Exception as exc:
        logger.critical(f"Falla crítica inesperada en la herramienta analítica: {str(exc)}", exc_info=True)
        raise Exception(f"Error interno en la ejecución de la herramienta analítica: {str(exc)}") from exc
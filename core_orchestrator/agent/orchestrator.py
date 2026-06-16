"""
Módulo del Agente Orquestador Central Basado en Gemini.

Administra el bucle de razonamiento de IA, traduciendo los requerimientos
de seguridad en llamadas a herramientas MCP y consolidando el veredicto final.
"""

import logging
import json
from typing import Dict, Any, List

from core_orchestrator.models.alert_response import AlertResponseSchema
import google.generativeai as genai
from google.generativeai.types import GenerateContentResponse

from core_orchestrator.config import orchestrator_settings as settings
from core_orchestrator.agent.prompts import ORCHESTRATOR_SYSTEM_PROMPT
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

    async def process_telemetry_window(self, telemetry_payload: Dict[str, Any]) -> str:
        """
        Inicia el ciclo de razonamiento analítico para una ventana temporal de telemetría.

        Args:
            telemetry_payload (Dict[str, Any]): Datos de la ventana agregada por el WindowManager.

        Returns:
            str: Reporte analítico final en formato JSON para integración automatizada.
        """
        source_ip = telemetry_payload.get("source_ip", "UNKNOWN")
        logger.info(f"Agente Orquestador activado para analizar la IP: {source_ip}")

        try:
            # --- PASO 1: Ejecución obligatoria de la primera herramienta analítica ---
            logger.info(f"Paso 1: Solicitando análisis de actividad web para {source_ip}")

            # Invocamos la herramienta a través de nuestro cliente MCP
            raw_analysis_result = await self.mcp_manager.call_tool(
                tool_name="analyze_web_activity",
                arguments=telemetry_payload
            )

            # [CORRECCIÓN] Extraer y deserializar el contenido de CallToolResult a Dict
            analysis_result: Dict[str, Any] = {}
            if hasattr(raw_analysis_result, "content") and raw_analysis_result.content:
                try:
                    # FastMCP empaqueta la respuesta en un TextContent dentro de una lista (.content[0].text)
                    analysis_result = json.loads(raw_analysis_result.content[0].text)
                except (json.JSONDecodeError, IndexError, AttributeError):
                    logger.error(f"No se pudo parsear el JSON de analyze_web_activity. Usando fallback vacío.")
                    analysis_result = {"threat_detected": False, "threat_score": 0}
            else:
                # Fallback en caso de que ya venga como diccionario o formato inesperado
                analysis_result = raw_analysis_result if isinstance(raw_analysis_result, dict) else {}

            logger.info(
                f"Análisis completado para {source_ip}: threat_detected={analysis_result.get('threat_detected')}, "
                f"score={analysis_result.get('threat_score', 'N/A')}%")

            # --- PASO 2: Si se detectó amenaza, obtener contexto histórico ---
            threat_detected = analysis_result.get("threat_detected", False)
            if threat_detected:
                logger.info(f"Paso 2: Amenaza detectada. Solicitando contexto histórico para {source_ip}")

                raw_context_result = await self.mcp_manager.call_tool(
                    tool_name="get_threat_context",
                    arguments={"source_ip": source_ip, "limit": 5}
                )

                # [CORRECCIÓN] Hacemos el mismo desempaquetado para el contexto histórico
                context_result: Dict[str, Any] = {}
                if hasattr(raw_context_result, "content") and raw_context_result.content:
                    try:
                        context_result = json.loads(raw_context_result.content[0].text)
                    except (json.JSONDecodeError, IndexError, AttributeError):
                        context_result = {"history": []}
                else:
                    context_result = raw_context_result if isinstance(raw_context_result, dict) else {}

                # Enriquecer el resultado con contexto histórico (ahora seguro porque analysis_result es un dict)
                analysis_result["threat_history"] = context_result.get("history", [])
                logger.info(f"Contexto histórico agregado: {len(context_result.get('history', []))} alertas previas")

            # --- PASO 3: Retornar el JSON del análisis directo (estructura profesional y completa) ---
            logger.debug(f"Retornando análisis directo en JSON para {source_ip}")
            return json.dumps(analysis_result, indent=2, ensure_ascii=False, default=str)

        except Exception as exc:
            logger.error(f"Falla durante el ciclo de razonamiento del Agente Orquestador: {str(exc)}", exc_info=True)
            return json.dumps({
                "status": "error",
                "error": str(exc),
                "source_ip": source_ip,
                "threat_detected": False,
                "threat_level": "NONE"
            }, ensure_ascii=False)
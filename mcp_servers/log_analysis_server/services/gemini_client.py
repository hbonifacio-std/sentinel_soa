"""
Módulo del Cliente API de Gemini para el Servidor de Análisis MCP.

NOTA: Este módulo está siendo refactorizado como parte de la generalización de proveedores.
Para nuevo código, usar directamente GeminiProvider a través del factory pattern.

Abstrae las llamadas al modelo fundacional de Google y fuerza respuestas 
estructuradas en formato JSON para la evaluación de amenazas perimetrales.
"""

import asyncio
import json
import logging
from typing import Dict, Any

from mcp_servers.log_analysis_server.config import server_settings as settings
from mcp_servers.log_analysis_server.llm_providers import create_llm_provider, LLMException

logger = logging.getLogger("mcp_servers.log_analysis_server.gemini_client")


class GeminiClient:
    """
    Cliente de bajo nivel encargado de interactuar con la API de Google Gemini,
    garantizando respuestas técnicas en formatos JSON validados.
    
    DEPRECATED: Para nuevo código, usar el factory pattern:
        from mcp_servers.log_analysis_server.llm_providers import create_llm_provider
        provider = create_llm_provider('gemini', config)
    
    Este cliente mantiene compatibilidad hacia atrás pero delegará a GeminiProvider
    cuando sea posible.
    """

    # Configuramos el modelo y los hiperparámetros analíticos perimetrales
    _MODEL_NAME = settings.gemini_model
    _MAX_TOKENS = settings.gemini_max_output_tokens
    _provider = None  # Cache del proveedor

    @classmethod
    def _get_or_create_provider(cls):
        """
        Obtener o crear el proveedor Gemini singleton.
        
        Returns:
            GeminiProvider: Instancia del proveedor Gemini
            
        Raises:
            LLMException: Si hay error en la inicialización
        """
        if cls._provider is None:
            config = settings.get_provider_config()
            cls._provider = create_llm_provider('gemini', config)
        return cls._provider

    @classmethod
    async def generate_structured_assessment(cls, prompt: str) -> Dict[str, Any]:
        """
        Envía un prompt analítico a Gemini y retorna un diccionario JSON estructurado.
        Ejecuta la llamada de red de forma no bloqueante utilizando hilos del sistema.

        Args:
            prompt (str): Texto completo con las métricas y el historial construido por PromptBuilder.

        Returns:
            Dict[str, Any]: Diccionario con el veredicto desglosado (threat_detected, threat_level, etc.).
            
        Raises:
            LLMException: Si hay error en la comunicación con Gemini
        """
        try:
            # Obtener el proveedor Gemini
            provider = cls._get_or_create_provider()
            
            logger.debug(f"Despachando solicitud asíncrona a la API de Gemini ({cls._MODEL_NAME}).")
            
            # Invocar al proveedor con el prompt
            response_text = await provider.call_model(prompt, cls._MAX_TOKENS)
            
            # Parsear y validar respuesta
            try:
                parsed_json = json.loads(response_text.strip())
                logger.debug("Respuesta parseada correctamente de Gemini")
                return parsed_json
            except json.JSONDecodeError as json_err:
                logger.error(f"Falla al parsear el JSON generado por Gemini. Contenido crudo: {response_text[:500]} | Error: {str(json_err)}")
                return cls._get_fallback_error_response("La IA no generó un formato JSON válido.")

        except LLMException as llm_err:
            logger.error(f"Excepción LLM en Gemini Client: {str(llm_err)}")
            return cls._get_fallback_error_response(f"Falla de comunicación con Gemini: {str(llm_err)}")
            
        except Exception as exc:
            logger.error(f"Excepción inesperada en Gemini Client: {str(exc)}", exc_info=True)
            return cls._get_fallback_error_response(f"Falla inesperada: {str(exc)}")

    @classmethod
    def _get_fallback_error_response(cls, error_msg: str) -> Dict[str, Any]:
        """
        Genera un diccionario de contingencia seguro en caso de fallas críticas en el LLM,
        evitando el colapso del pipeline o falsos negativos por caídas del servicio.
        """
        return {
            "threat_detected": False,
            "threat_level": "None",
            "kill_chain_phase": "None",
            "attack_vector_identified": "Benign/Error",
            "threat_score": 0.0,
            "justification_summary": f"Falla de procesamiento en el nodo MCP de Inteligencia Artificial. Detalles: {error_msg}"
        }
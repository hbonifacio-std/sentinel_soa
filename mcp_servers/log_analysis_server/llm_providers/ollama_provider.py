"""
Módulo del adaptador Ollama para la interfaz LLM genérica.

Implementa LLMProviderInterface para Ollama (modelos LLM locales), permitiendo
ejecutar análisis sin dependencias de APIs externas y sin costos.
"""

import asyncio
import json
import logging
from typing import Any, Dict, Optional, List

import httpx
from pydantic import ValidationError

from mcp_servers.log_analysis_server.llm_providers.base import (
    LLMProviderInterface,
    LLMResponse,
    LLMException,
)
from mcp_servers.log_analysis_server.services.prompt_builder import AnalysisPromptBuilder

logger = logging.getLogger("mcp_servers.log_analysis_server.llm_providers.ollama_provider")


class OllamaProvider(LLMProviderInterface):
    """
    Adaptador de Ollama para el framework LLM genérico.
    
    Permite ejecutar modelos de LLM locales (Mistral, Llama2, etc.) sin
    dependencias de APIs externas, ideal para desarrollo y testing.
    
    Requiere que Ollama esté ejecutándose (típicamente en Docker):
        docker run -d -p 11434:11434 ollama/ollama
        docker exec <container_id> ollama pull mistral
    """

    _PROVIDER_NAME = "ollama"
    _TIMEOUT_SECONDS = 300  # 5 minutos por defecto

    def __init__(self, config: Dict[str, Any]):
        """
        Inicializar el proveedor Ollama con configuración específica.
        
        Args:
            config (Dict[str, Any]): Debe contener:
                - ollama_base_url: URL base de Ollama (default: http://localhost:11434)
                - ollama_model: Nombre del modelo (default: mistral)
                - ollama_timeout_seconds: Timeout para requests (default: 300)
        """
        super().__init__(config)
        self._base_url = config.get("ollama_base_url", "http://localhost:11434").rstrip("/")
        self._model_name = config.get("ollama_model", "mistral")
        self._timeout = config.get("ollama_timeout_seconds", self._TIMEOUT_SECONDS)
        self._client = None
        
        logger.info(f"OllamaProvider inicializado para modelo: {self._model_name} en {self._base_url}")

    def _get_client(self) -> httpx.AsyncClient:
        """
        Obtener o crear cliente HTTP asincrónico para Ollama.
        
        Returns:
            httpx.AsyncClient: Cliente con timeout configurado
        """
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    def build_analysis_prompt(self, telemetry: Any, history: List[Any]) -> str:
        """Genera el payload JSON ultra reducido aprovechando el Modelfile pre-cargado."""
        return AnalysisPromptBuilder.build_optimized_json_prompt(telemetry, history)

    async def call_model(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """
        Invocar a Ollama con el prompt proporcionado.
        
        Realiza request HTTP a la API de Ollama (/api/generate endpoint) y
        retorna la respuesta como string.
        
        Args:
            prompt (str): Prompt estructurado para análisis
            max_tokens (Optional[int]): Número máximo de tokens (ignorado por Ollama en este endpoint)
            
        Returns:
            str: Respuesta del modelo como string
            
        Raises:
            LLMException: Si hay error en la comunicación con Ollama
        """
        client = self._get_client()
        url = f"{self._base_url}/api/generate"
        
        payload = {
            "model": self._model_name,
            "prompt": prompt,
            "stream": False,  # No usar streaming para respuestas estructuradas
            "format": "json",  # Solicitar formato JSON
        }

        try:
            logger.debug(f"Enviando request a Ollama: {url}")
            
            response = await client.post(url, json=payload)
            response.raise_for_status()
            
            result = response.json()

            generated_text = result.get("response", "")
            logger.info(generated_text)
            if not generated_text:
                logger.error("Ollama retornó respuesta vacía")
                raise LLMException("Respuesta vacía de Ollama")
            
            logger.debug("Respuesta recibida de Ollama exitosamente")
            return generated_text.strip()
            
        except httpx.HTTPError as http_err:
            logger.error(f"Error HTTP en Ollama: {str(http_err)}")
            raise LLMException(f"Error HTTP en Ollama: {str(http_err)}") from http_err
            
        except Exception as exc:
            logger.error(f"Error en llamada a Ollama: {str(exc)}", exc_info=True)
            raise LLMException(f"Falla en Ollama: {str(exc)}") from exc

    async def validate_response(self, response: str) -> LLMResponse:
        """
        Validar y parsear la respuesta de Ollama.
        
        Convierte la respuesta a JSON y la valida contra el schema LLMResponse.
        
        Args:
            response (str): Respuesta de Ollama
            
        Returns:
            LLMResponse: Objeto validado
            
        Raises:
            LLMException: Si hay error de parsing o validación
        """
        try:
            # Ollama a veces envuelve JSON en texto, intentar extraer
            parsed = json.loads(response)
            logger.debug("JSON parseado exitosamente")
            
            # Validar con Pydantic
            validated = LLMResponse(**parsed)
            logger.debug("Respuesta validada según schema LLMResponse")
            return validated
            
        except json.JSONDecodeError as json_err:
            logger.error(f"Error parseando JSON de Ollama: {str(json_err)}")
            raise LLMException(f"JSON inválido de Ollama: {str(json_err)}") from json_err
            
        except ValidationError as val_err:
            logger.error(f"Error validando schema de respuesta: {str(val_err)}")
            raise LLMException(f"Respuesta no cumple schema: {str(val_err)}") from val_err
            
        except Exception as exc:
            logger.error(f"Error inesperado en validate_response: {str(exc)}")
            raise LLMException(f"Error inesperado: {str(exc)}") from exc

    @property
    def provider_name(self) -> str:
        """Retorna 'ollama' como identificador único del proveedor."""
        return self._PROVIDER_NAME

    @property
    def model_name(self) -> str:
        """Retorna el nombre del modelo Ollama siendo usado."""
        return self._model_name

    async def health_check(self) -> bool:
        """
        Verificar disponibilidad de Ollama.
        
        Realiza llamada al endpoint /api/tags para verificar que el servicio
        está disponible y que el modelo está descargado.
        
        Returns:
            bool: True si Ollama está disponible y el modelo existe, False en caso contrario
        """
        client = self._get_client()
        url = f"{self._base_url}/api/tags"
        
        try:
            logger.info("Ejecutando health check de Ollama")
            
            response = await client.get(url)
            response.raise_for_status()
            
            data = response.json()
            models = [m.get("name", "") for m in data.get("models", [])]
            
            # Verificar que el modelo existe
            model_found = any(self._model_name in m for m in models)
            
            if model_found:
                logger.info(f"Health check OK: modelo {self._model_name} disponible en Ollama")
                return True
            else:
                logger.warning(f"Health check: modelo {self._model_name} no encontrado. Modelos disponibles: {models}")
                return False
                
        except Exception as exc:
            logger.error(f"Health check de Ollama falló: {str(exc)}")
            return False

    async def close(self):
        """Cerrar conexión con Ollama."""
        if self._client:
            await self._client.aclose()
            self._client = None

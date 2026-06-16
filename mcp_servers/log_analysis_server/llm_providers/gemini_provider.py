"""
Módulo del adaptador Gemini para la interfaz LLM genérica.

Implementa LLMProviderInterface para Google Gemini, encapsulando toda la lógica
específica de Gemini API y manteniéndola agnóstica del resto del sistema.
"""

import asyncio
import copy
import json
import logging
from typing import Any, Dict, Optional, List

import google.generativeai as genai
from google.generativeai.types import generation_types
from pydantic import ValidationError

from mcp_servers.log_analysis_server.llm_providers.base import (
    LLMProviderInterface,
    LLMResponse,
    LLMException,
)
from mcp_servers.log_analysis_server.services.prompt_builder import AnalysisPromptBuilder

logger = logging.getLogger("mcp_servers.log_analysis_server.llm_providers.gemini_provider")


class GeminiProvider(LLMProviderInterface):
    """
    Adaptador de Google Gemini para el framework LLM genérico.
    
    Encapsula todas las particularidades de la API de Google Gemini,
    incluyendo autenticación, configuración de generación, y manejo de errores.
    """

    _PROVIDER_NAME = "gemini"

    def __init__(self, config: Dict[str, Any]):
        """
        Inicializar el proveedor Gemini con configuración específica.
        
        Args:
            config (Dict[str, Any]): Debe contener:
                - gemini_api_key: Clave de autenticación para Google Gemini
                - gemini_model: Nombre del modelo (default: gemini-1.5-flash)
                - gemini_max_output_tokens: Tokens máximos de salida (default: 1024)
        """
        super().__init__(config)
        self._api_key = config.get("gemini_api_key")
        self._model_name = config.get("gemini_model", "gemini-3.5-flash")
        self._max_tokens = config.get("gemini_max_output_tokens", 4160)
        
        if not self._api_key:
            raise LLMException("gemini_api_key es requerida en la configuración")
        
        # Configurar la API de Gemini de forma tardía (lazy)
        self._model = None
        logger.info(f"GeminiProvider inicializado para modelo: {self._model_name}")

    def build_analysis_prompt(self, telemetry: Any, history: List[Any]) -> str:
        """Genera el prompt clásico extendido requerido para Gemini."""
        return AnalysisPromptBuilder.build_full_prompt(telemetry, history)

    async def call_model(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """
        Invocar a Google Gemini con el prompt proporcionado.
        Compatible con especificaciones estrictas de Gemini 2.5+.
        """
        # 1. Forzar un mínimo saludable de tokens para evitar truncado de JSONs
        current_max_tokens = max_tokens or self._max_tokens
        if current_max_tokens < 2048:
            current_max_tokens = 4160  # Asignar espacio holgado para el análisis de logs

        # 2. Inicialización limpia y robusta del modelo base
        if self._model is None:
            genai.configure(api_key=self._api_key)

            # En Gemini 2.5+ es vital definir el mime_type desde la raíz
            self._base_config = generation_types.GenerationConfig(
                temperature=0.1,
                response_mime_type="application/json",
                response_schema=LLMResponse.to_dict_schema()
            )

            self._model = genai.GenerativeModel(
                model_name=self._model_name,
                generation_config=self._base_config
            )

        try:
            logger.debug(f"Enviando prompt a Gemini ({self._model_name})")

            # 3. Clonar y mutar la configuración exclusivamente para esta llamada
            runtime_config =copy.copy(self._base_config)
            runtime_config.max_output_tokens = current_max_tokens

            # 4. Invocación segura usando lambda para prevenir problemas de firma con hilos
            response = await asyncio.to_thread(
                lambda: self._model.generate_content(
                    prompt,
                    generation_config=runtime_config
                )
            )

            if not response or not response.text:
                logger.error("Gemini retornó respuesta vacía")
                raise LLMException("Respuesta vacía de Gemini API")

            logger.debug("Respuesta recibida de Gemini exitosamente")
            return response.text.strip()

        except Exception as exc:
            logger.error(f"Error en llamada a Gemini API: {str(exc)}", exc_info=True)
            raise LLMException(f"Falla en Gemini API: {str(exc)}") from exc

    async def validate_response(self, response: str) -> LLMResponse:
        """
        Validar y parsear la respuesta de Gemini.
        
        Realiza conversión de JSON string a LLMResponse y maneja casos donde
        el JSON está malformado.
        
        Args:
            response (str): Respuesta JSON de Gemini
            
        Returns:
            LLMResponse: Objeto validado
            
        Raises:
            LLMException: Si hay error de parsing o validación
        """
        try:
            """Valida y parsea la respuesta recibida del LLM."""

            # ════════════════════════════════════════════════════════════════════
            # IMPRESIÓN DE DEPURACIÓN (Añade estas líneas)
            # ════════════════════════════════════════════════════════════════════
            print("\n" + "=" * 80)
            print("RECONOCIMIENTO DE RESPUESTA CRUDA DE GEMINI:")
            print("=" * 80)
            # Alternativa elegante usando el logger existente en tu archivo
            logger.info(f"Contenido crudo recibido de Gemini:\n{response}")
            print("=" * 80 + "\n")
            # ════════════════════════════════════════════════════════════════════
            parsed = json.loads(response)
            logger.debug("JSON parseado exitosamente")
            
            # Intentar validar con Pydantic
            validated = LLMResponse(**parsed)
            logger.debug("Respuesta validada según schema LLMResponse")
            return validated
            
        except json.JSONDecodeError as json_err:
            logger.error(f"Error parseando JSON de Gemini: {str(json_err)}")
            raise LLMException(f"JSON inválido de Gemini: {str(json_err)}") from json_err
            
        except ValidationError as val_err:
            logger.error(f"Error validando schema de respuesta: {str(val_err)}")
            raise LLMException(f"Respuesta no cumple schema: {str(val_err)}") from val_err
            
        except Exception as exc:
            logger.error(f"Error inesperado en validate_response: {str(exc)}")
            raise LLMException(f"Error inesperado: {str(exc)}") from exc

    @property
    def provider_name(self) -> str:
        """Retorna 'gemini' como identificador único del proveedor."""
        return self._PROVIDER_NAME

    @property
    def model_name(self) -> str:
        """Retorna el nombre exacto del modelo Gemini siendo usado."""
        return self._model_name

    async def health_check(self) -> bool:
        """
        Verificar disponibilidad de Gemini API.
        
        Realiza una llamada mínima al modelo para verificar autenticación
        y disponibilidad del servicio.
        
        Returns:
            bool: True si está disponible, False en caso contrario
        """
        try:
            logger.info("Ejecutando health check de Gemini")
            
            # Inicializar si es necesario
            if self._model is None:
                genai.configure(api_key=self._api_key)
                generation_config = {
                    "temperature": 0.1,
                    "max_output_tokens": 4160,
                    "response_mime_type": "application/json",
                }
                self._model = genai.GenerativeModel(
                    model_name=self._model_name,
                    generation_config=generation_config
                )
            
            # Realizar llamada mínima
            test_prompt = '{"test": true}'
            response = await asyncio.to_thread(
                self._model.generate_content,
                f'Responde con JSON válido: {test_prompt}'
            )
            
            if response and response.text:
                logger.info("Health check de Gemini exitoso")
                return True
            else:
                logger.warning("Health check de Gemini: respuesta vacía")
                return False
                
        except Exception as exc:
            logger.error(f"Health check de Gemini falló: {str(exc)}")
            return False

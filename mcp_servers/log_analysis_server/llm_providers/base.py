"""
Módulo de interfaz abstracta para proveedores de LLM.

Define el contrato que deben cumplir todos los proveedores de modelos de lenguaje
(Gemini, Ollama, Claude, OpenAI, etc.) para garantizar compatibilidad e intercambiabilidad.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
import logging

logger = logging.getLogger("mcp_servers.log_analysis_server.llm_providers.base")


class LLMResponse(BaseModel):
    """
    Respuesta estructurada común a todos los proveedores LLM.
    Garantiza que independientemente del proveedor, la salida sigue el mismo esquema.
    """
    window_id: Optional[str] = None
    threat_detected: bool
    threat_level: str  # NONE | LOW | MEDIUM | HIGH | CRITICAL
    kill_chain_phase: Optional[str] = None  # Reconnaissance | Weaponization | etc.
    indicators_found: Optional[List[str]] = None
    reasoning_summary: str
    recommendation: str
    threat_score: Optional[float] = None
    threat_score: Optional[float] = None # Cambiado a float para consistencia con LLM output
    attack_vector_identified: Optional[str] = None
    justification_summary: Optional[str] = None

    class Config:
        extra = "allow"  # Puedes mantener tu flexibilidad para otros LLMs

    @classmethod
    def to_dict_schema(cls) -> Dict[str, Any]:
        """
        Construye manualmente el JSON Schema exacto que requiere la SDK de Gemini,
        evitando las incompatibilidades generadas por Pydantic V2 de forma directa.
        """
        return {
            "type": "OBJECT",
            "properties": {
                "window_id": {
                    "type": "STRING",
                    "nullable": True
                },
                "threat_detected": {
                    "type": "BOOLEAN"
                },
                "threat_level": {
                    "type": "STRING"  # Valores esperados: NONE | LOW | MEDIUM | HIGH | CRITICAL
                },
                "kill_chain_phase": {
                    "type": "STRING",
                    "nullable": True  # Reconnaissance | Weaponization | etc.
                },
                "indicators_found": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"},
                    "nullable": True
                },
                "reasoning_summary": {
                    "type": "STRING"
                },
                "recommendation": {
                    "type": "STRING"
                },
                "threat_score": {
                    "type": "NUMBER",
                    "nullable": True
                },
                "attack_vector_identified": {
                    "type": "STRING",
                    "nullable": True
                },
                "justification_summary": {
                    "type": "STRING",
                    "nullable": True
                }
            },
            "required": [
                "threat_detected",
                "threat_level",
                "reasoning_summary",
                "recommendation"
            ]
        }


class LLMProviderInterface(ABC):
    """
    Interfaz abstracta que define el contrato para todos los proveedores LLM.
    
    Cada implementación concreta (Gemini, Ollama, Claude, OpenAI) debe heredar
    de esta clase e implementar todos los métodos abstractos.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Inicializar el proveedor con configuración específica.
        
        Args:
            config (Dict[str, Any]): Diccionario con variables de configuración
                (puede incluir API keys, URLs base, modelos, timeouts, etc.)
        """
        self.config = config
        logger.debug(f"Inicializando proveedor LLM con configuración: {self._sanitize_config(config)}")

    @abstractmethod
    def build_analysis_prompt(self, telemetry: Any, history: List[Any]) -> str:
        """
        Genera de forma dinámica el prompt adaptado a la naturaleza del proveedor.

        Cada proveedor concreto decidirá internamente si construye un prompt
        extendido descriptivo (ej. Gemini) o un payload JSON optimizado (ej. Ollama).

        Args:
            telemetry (Any): Datos de la ventana de telemetría actual.
            history (List[Any]): Historial de alertas previas de la IP.

        Returns:
            str: El string del prompt listo para ser enviado a call_model().
        """
        pass
    @abstractmethod
    async def call_model(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """
        Invocar el modelo LLM con el prompt proporcionado.
        
        Debe retornar la respuesta como string JSON válido que pueda ser parseado
        por validate_response().
        
        Args:
            prompt (str): Prompt completo con contexto, instrucciones y datos a analizar
            max_tokens (Optional[int]): Límite de tokens en la respuesta (si aplica)
            
        Returns:
            str: Respuesta JSON como string
            
        Raises:
            LLMException: Si hay error en la llamada al modelo (timeout, auth, etc.)
        """
        pass

    @abstractmethod
    async def validate_response(self, response: str) -> LLMResponse:
        """
        Validar y parsear la respuesta del modelo a LLMResponse estructurado.
        
        Asegura que la respuesta cumple con el esquema esperado y maneja
        desviaciones o errores en el formato.
        
        Args:
            response (str): String JSON de respuesta del modelo
            
        Returns:
            LLMResponse: Objeto validado con respuesta estructurada
            
        Raises:
            ValidationError: Si JSON no cumple schema de LLMResponse
        """
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """
        Nombre único del proveedor (lowercase).
        
        Ejemplos: 'gemini', 'ollama', 'claude', 'openai'
        
        Returns:
            str: Nombre del proveedor
        """
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """
        Nombre del modelo específico siendo utilizado.
        
        Ejemplos: 'gemini-1.5-flash', 'mistral', 'claude-3-sonnet'
        
        Returns:
            str: Nombre del modelo
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Verificar que el proveedor está disponible y funcional.
        
        Debe realizar una llamada mínima (sin costos significativos) para
        verificar conectividad, autenticación y disponibilidad del servicio.
        
        Returns:
            bool: True si el proveedor está disponible, False en caso contrario
        """
        pass

    @staticmethod
    def _sanitize_config(config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remover datos sensibles (API keys, passwords) de la configuración
        para logging seguro.
        
        Args:
            config (Dict[str, Any]): Configuración original
            
        Returns:
            Dict[str, Any]: Configuración con datos sensibles enmascarados
        """
        sensitive_keys = {'api_key', 'api_key', 'secret', 'password', 'token', 'key'}
        sanitized = {}
        for k, v in config.items():
            if any(sensitive in k.lower() for sensitive in sensitive_keys):
                sanitized[k] = "***REDACTED***"
            else:
                sanitized[k] = v
        return sanitized


class LLMException(Exception):
    """
    Excepción genérica para errores relacionados con proveedores LLM.
    
    Hereda de Exception y puede ser capturada específicamente para manejo
    de errores de comunicación con servicios LLM.
    """
    pass

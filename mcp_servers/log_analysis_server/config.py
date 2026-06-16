"""Módulo de configuración para el Servidor MCP de Análisis de Logs.

Utiliza pydantic-settings para leer de manera robusta y tipada las variables
de entorno que son **heredadas del proceso padre (Core Orchestrator)**.
Este módulo no carga su propio archivo .env, asegurando que la configuración
esté centralizada en el orquestador.
"""

from typing import Optional
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogAnalysisServerSettings(BaseSettings):
    """Encapsula la configuración del entorno para el nodo de análisis MCP.
    
    Lee las variables de entorno que el Core Orchestrator le proporciona al
    iniciarlo como un subproceso.
    """

    # ========== CONFIGURACIÓN DEL PROVEEDOR LLM ==========
    
    llm_provider: str = Field(
        default="gemini",
        validation_alias="LLM_PROVIDER",
        description="Proveedor LLM a utilizar, heredado del orquestador."
    )
    
    # ========== CONFIGURACIÓN GEMINI (Default) ==========
    
    # Al utilizar SecretStr, evitamos que la API key se exponga accidentalmente en los logs
    gemini_api_key: Optional[SecretStr] = Field(
        default=None,
        validation_alias="GEMINI_API_KEY",
        description="Clave secreta para la API de Google Gemini, heredada."
    )
    
    gemini_model: str = Field(
        default="gemini-3.5-flash",
        validation_alias="GEMINI_MODEL",
        description="Versión exacta del modelo Gemini a invocar para las heurísticas."
    )
    
    gemini_max_output_tokens: int = Field(
        default=4160,
        validation_alias="GEMINI_MAX_OUTPUT_TOKENS",
        gt=0,
        description="Límite máximo de tokens de salida permitidos en el veredicto del agente Gemini."
    )
    
    # ========== CONFIGURACIÓN OLLAMA (Local) ==========
    
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        validation_alias="OLLAMA_BASE_URL",
        description="URL base del servidor Ollama, heredada."
    )
    
    ollama_model: str = Field(
        default="mistral",
        validation_alias="OLLAMA_MODEL",
        description="Nombre del modelo Ollama a utilizar (ej: mistral, llama2, neural-chat)"
    )
    
    ollama_timeout_seconds: int = Field(
        default=300,
        validation_alias="OLLAMA_TIMEOUT_SECONDS",
        gt=0,
        description="Timeout en segundos para requests a Ollama"
    )

    # Configuración interna del parseador de Pydantic Settings
    model_config = SettingsConfigDict(
        # NO se especifica env_file para forzar la lectura desde el entorno del sistema.
        # Esto es crucial para que herede la configuración del proceso padre.
        extra="ignore"
    )
    
    @field_validator('llm_provider')
    @classmethod
    def validate_provider(cls, v: str) -> str:
        """Valida que el proveedor sea uno de los soportados."""
        valid_providers = ['gemini', 'ollama']
        v_lower = v.lower().strip()
        if v_lower not in valid_providers:
            raise ValueError(f"LLM_PROVIDER debe ser uno de {valid_providers}, obtuvo: {v}")
        return v_lower

    def get_provider_config(self) -> dict:
        """
        Retorna un diccionario con la configuración específica del proveedor seleccionado.
        
        Este método facilita pasar la configuración correcta al factory de proveedores.
        
        Returns:
            dict: Configuración específica del proveedor
        """
        config = {
            'gemini_api_key': self.gemini_api_key.get_secret_value() if self.gemini_api_key else None,
            'gemini_model': self.gemini_model,
            'gemini_max_output_tokens': self.gemini_max_output_tokens,
            'ollama_base_url': self.ollama_base_url,
            'ollama_model': self.ollama_model,
            'ollama_timeout_seconds': self.ollama_timeout_seconds,
        }
        return config


# Instancia única (Singleton) expuesta para el acceso centralizado de recursos del servidor
try:
    server_settings = LogAnalysisServerSettings()
except Exception as e:
    import sys
    import logging
    # Configurar logging para enviar errores a stderr, evitando contaminar stdout.
    logging.basicConfig(
        level=logging.ERROR,
        stream=sys.stderr,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True
    )
    logger = logging.getLogger("MCP_SERVER_CONFIG")
    logger.error(
        "Fallo crítico en la inicialización del Servidor MCP. No se encontraron las "
        f"variables de entorno requeridas heredadas del orquestador. Detalles: {e}"
    )
    # Fail-fast: detenemos el subproceso stdio inmediatamente para notificar al Host
    sys.exit(1)
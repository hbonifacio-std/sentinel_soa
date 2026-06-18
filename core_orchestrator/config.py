"""Módulo de configuración centralizada del Core Orchestrator.

Utiliza pydantic-settings para la ingesta y tipado estricto de variables de entorno
que regulan los puertos perimetrales REST, los umbrales de las ventanas temporales
de logs y las rutas de inicialización de subprocesos MCP.
"""

import os
from typing import Optional
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class OrchestratorSettings(BaseSettings):
    """Estructura de datos tipada para la gestión del entorno operacional del Host.

    Valida en tiempo de arranque el cumplimiento de variables imperativas de red y
    lógica de umbrales preventivos.
    """

    # --- Configuración de Red e Interfaces ---
    api_port: int = Field(
        default=8000,
        validation_alias="API_PORT",
        description="Puerto TCP en el cual se expondrán los endpoints HTTP/REST perimetrales."
    )

    # --- Configuración del Subproceso Interno MCP ---
    mcp_log_analysis_server_cmd: str = Field(
        default="python mcp_servers/log_analysis_server/server.py",
        validation_alias="MCP_LOG_ANALYSIS_SERVER_CMD",
        description="Comando de sistema operativo para ejecutar el servidor MCP local a través de stdio."
    )

    # --- Umbrales de Lógica de Detección y Ventanas ---
    window_threshold_requests: int = Field(
        default=200,
        validation_alias="WINDOW_THRESHOLD_REQUESTS",
        gt=0,
        description="Número mínimo de peticiones por ventana temporal de una IP para forzar el análisis de IA."
    )

    window_duration_seconds: int = Field(
        default=60,
        validation_alias="WINDOW_DURATION_SECONDS",
        gt=0,
        description="Duración en segundos de la ventana de tiempo para el agrupamiento de telemetría."
    )

    max_alerts_in_memory: int = Field(
        default=500,
        validation_alias="MAX_ALERTS_IN_MEMORY",
        gt=0,
        le=5000,
        description="Capacidad límite del búfer circular en memoria RAM para almacenar alertas previas."
    )

    # ========== CONFIGURACIÓN MULTI-PROVEEDOR LLM (CENTRALIZADA) ==========
    # El Core Orchestrator es ahora la única fuente de verdad para la configuración
    # del proveedor de IA, y la pasará al subproceso MCP a través del entorno.

    llm_provider: str = Field(
        default="gemini",
        validation_alias="LLM_PROVIDER",
        description="Proveedor LLM a utilizar: 'gemini' (default) | 'ollama'"
    )

    # --- Gemini (Google) ---
    gemini_api_key: Optional[SecretStr] = Field(
        default=None,
        validation_alias="GEMINI_API_KEY",
        description="Clave de acceso para la API de Gemini."
    )

    gemini_model: str = Field(
        default="gemini-3.5-flash",
        validation_alias="GEMINI_MODEL",
        description="Versión del modelo Gemini a invocar."
    )

    gemini_max_output_tokens: int = Field(
        default=1024,
        validation_alias="GEMINI_MAX_OUTPUT_TOKENS",
        gt=0,
        description="Límite máximo de tokens de salida para Gemini."
    )

    # --- Ollama (Local Docker) ---
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        validation_alias="OLLAMA_BASE_URL",
        description="URL base del servidor Ollama."
    )

    ollama_model: str = Field(
        default="mistral",
        validation_alias="OLLAMA_MODEL",
        description="Nombre del modelo Ollama a utilizar."
    )

    ollama_timeout_seconds: int = Field(
        default=300,
        validation_alias="OLLAMA_TIMEOUT_SECONDS",
        gt=0,
        description="Timeout en segundos para requests a Ollama."
    )

    @field_validator("mcp_log_analysis_server_cmd")
    @classmethod
    def validate_command_structure(cls, v: str) -> str:
        """Sanea y valida de forma básica la presencia del ejecutable base."""
        cleaned = v.strip()
        if not cleaned:
            raise ValueError(
                "El comando de ejecución de herramientas MCP no puede estar vacío.")
        return cleaned

    @field_validator('llm_provider')
    @classmethod
    def validate_provider(cls, v: str) -> str:
        """Validar que el proveedor sea uno de los soportados."""
        valid_providers = [
            'gemini', 'ollama']  # Ampliar a medida que se añadan más
        v_lower = v.lower().strip()
        if v_lower not in valid_providers:
            raise ValueError(
                f"LLM_PROVIDER debe ser uno de {valid_providers}, obtuvo: {v}")
        return v_lower

    @field_validator('gemini_api_key', mode='before')
    def validate_gemini_key(cls, v, values):
        if values.data.get('llm_provider') == 'gemini' and not v:
            raise ValueError(
                "GEMINI_API_KEY es requerida cuando LLM_PROVIDER es 'gemini'")
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


# Inicialización de la configuración a nivel de módulo (Fail-Fast activo)
try:
    orchestrator_settings = OrchestratorSettings()
except Exception as e:
    import sys
    import logging
    logging.basicConfig(level=logging.ERROR)
    logger = logging.getLogger("ORCHESTRATOR_CONFIG")
    logger.error(
        f"Fallo crítico al iniciar Core Orchestrator: Verifique el archivo .env o "
        f"las variables de entorno requeridas. Detalles: {e}"
    )
    sys.exit(1)

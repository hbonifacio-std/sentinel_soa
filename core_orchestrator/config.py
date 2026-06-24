"""Centralized configuration module for the Core Orchestrator.

Uses pydantic-settings for robust ingestion and strict typing of environment variables
that regulate perimeter REST ports, log time window thresholds,
and MCP subprocess initialization paths.
"""

from typing import Optional
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class OrchestratorSettings(BaseSettings):
    """Typed data structure for managing the Host's operational environment.

    Validates at startup the compliance of imperative network variables and
    preventive threshold logic.
    """

    # --- Network and Interface Configuration ---
    api_port: int = Field(
        default=8000,
        validation_alias="API_PORT",
        description="TCP port on which the perimeter HTTP/REST endpoints will be exposed."
    )

    # --- Internal MCP Subprocess Configuration ---
    mcp_log_analysis_server_cmd: str = Field(
        default="python mcp_servers/log_analysis_server/server.py",
        validation_alias="MCP_LOG_ANALYSIS_SERVER_CMD",
        description="OS command to run the local MCP server via stdio."
    )

    # --- Detection Logic Thresholds and Windows ---
    window_threshold_requests: int = Field(
        default=50,
        validation_alias="WINDOW_THRESHOLD_REQUESTS",
        gt=0,
        description="Minimum number of requests per time window from an IP to force AI analysis."
    )

    window_duration_seconds: int = Field(
        default=60,
        validation_alias="WINDOW_DURATION_SECONDS",
        gt=0,
        description="Duration in seconds of the time window for telemetry grouping."
    )

    max_alerts_in_memory: int = Field(
        default=500,
        validation_alias="MAX_ALERTS_IN_MEMORY",
        gt=0,
        le=5000,
        description="Circular buffer capacity limit in RAM for storing previous alerts."
    )

    # ========== MULTI-PROVIDER LLM CONFIGURATION (CENTRALIZED) ==========
    # The Core Orchestrator is now the single source of truth for the AI provider
    # configuration, and will pass it to the MCP subprocess via the environment.

    llm_provider: str = Field(
        default="gemini",
        validation_alias="LLM_PROVIDER",
        description="LLM provider to use: 'gemini' (default) | 'ollama'"
    )

    # --- Gemini (Google) ---
    gemini_api_key: Optional[SecretStr] = Field(
        default=None,
        validation_alias="GEMINI_API_KEY",
        description="Access key for the Gemini API."
    )

    gemini_model: str = Field(
        default="gemini-3.5-flash",
        validation_alias="GEMINI_MODEL",
        description="Version of the Gemini model to invoke."
    )

    gemini_max_output_tokens: int = Field(
        default=1024,
        validation_alias="GEMINI_MAX_OUTPUT_TOKENS",
        gt=0,
        description="Maximum output token limit for Gemini."
    )

    # --- Ollama (Local Docker) ---
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        validation_alias="OLLAMA_BASE_URL",
        description="Base URL of the Ollama server."
    )

    ollama_model: str = Field(
        default="mistral",
        validation_alias="OLLAMA_MODEL",
        description="Name of the Ollama model to use."
    )

    ollama_timeout_seconds: int = Field(
        default=900,
        validation_alias="OLLAMA_TIMEOUT_SECONDS",
        gt=0,
        description="Timeout in seconds for requests to Ollama."
    )

    # --- OpenAI Configuration ---
    openai_api_key: Optional[SecretStr] = Field(
        default=None,
        validation_alias="OPENAI_API_KEY",
        description="Access key for the OpenAI API."
    )

    openai_model: str = Field(
        default="gpt-4o-mini",
        validation_alias="OPENAI_MODEL",
        description="Version of the OpenAI model to invoke."
    )

    openai_max_output_tokens: int = Field(
        default=4096,
        validation_alias="OPENAI_MAX_OUTPUT_TOKENS",
        gt=0,
        description="Maximum output token limit for OpenAI."
    )

    openai_timeout_seconds: int = Field(
        default=60,
        validation_alias="OPENAI_TIMEOUT_SECONDS",
        gt=0,
        description="Timeout in seconds for OpenAI requests."
    )

    # --- GROQ Configuration ---
    groq_api_key: Optional[SecretStr] = Field(
        default=None,
        validation_alias="GROQ_API_KEY",
        description="Access key for the GROQ API."
    )

    groq_model: str = Field(
        default="mixtral-8x7b-32768",
        validation_alias="GROQ_MODEL",
        description="Version of the GROQ model to invoke."
    )

    groq_max_output_tokens: int = Field(
        default=4096,
        validation_alias="GROQ_MAX_OUTPUT_TOKENS",
        gt=0,
        description="Maximum output token limit for GROQ."
    )

    groq_timeout_seconds: int = Field(
        default=60,
        validation_alias="GROQ_TIMEOUT_SECONDS",
        gt=0,
        description="Timeout in seconds for GROQ requests."
    )

    # --- Security Configuration (HMAC, JWT, CORS) ---
    hmac_replay_window_seconds: int = Field(
        default=300,
        validation_alias="HMAC_REPLAY_WINDOW_SECONDS",
        gt=0,
        description="Time window in seconds for HMAC timestamp validation (replay attack prevention)."
    )

    jwt_secret_key: SecretStr = Field(
        default=SecretStr("dev-secret-key-change-in-production"),
        validation_alias="JWT_SECRET_KEY",
        description="Secret key for JWT token signing and verification."
    )

    jwt_algorithm: str = Field(
        default="HS256",
        validation_alias="JWT_ALGORITHM",
        description="Algorithm used for JWT token signing."
    )

    jwt_expiration_minutes: int = Field(
        default=60,
        validation_alias="JWT_EXPIRATION_MINUTES",
        gt=0,
        description="JWT token expiration time in minutes."
    )

    allowed_cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:8000",
        validation_alias="ALLOWED_CORS_ORIGINS",
        description="Comma-separated list of allowed CORS origins."
    )

    bootstrap_on_startup: bool = Field(
        default=True,
        validation_alias="BOOTSTRAP_ON_STARTUP",
        description="Enable idempotent local bootstrap for users and telemetry clients during startup."
    )

    @field_validator("mcp_log_analysis_server_cmd")
    @classmethod
    def validate_command_structure(cls, v: str) -> str:
        """Sanitizes and validates the presence of the base executable."""
        cleaned = v.strip()
        if not cleaned:
            raise ValueError(
                "The MCP tool execution command cannot be empty.")
        return cleaned

    @field_validator('llm_provider')
    @classmethod
    def validate_provider(cls, v: str) -> str:
        """Validates that the provider is one of the supported ones."""
        valid_providers = [
            'gemini', 'ollama', 'openai', 'groq']  # Extend as more providers are added
        v_lower = (v or '').lower().strip() or 'ollama'
        if v_lower not in valid_providers:
            raise ValueError(
                f"LLM_PROVIDER must be one of {valid_providers}, got: {v}")
        return v_lower

    @field_validator('gemini_api_key', mode='before')
    def validate_gemini_key(cls, v, values):
        if values.data.get('llm_provider') == 'gemini' and not v:
            raise ValueError(
                "GEMINI_API_KEY is required when LLM_PROVIDER is 'gemini'")
        return v

    @field_validator('openai_api_key', mode='before')
    def validate_openai_key(cls, v, values):
        if values.data.get('llm_provider') == 'openai' and not v:
            raise ValueError(
                "OPENAI_API_KEY is required when LLM_PROVIDER is 'openai'")
        return v

    @field_validator('groq_api_key', mode='before')
    def validate_groq_key(cls, v, values):
        if values.data.get('llm_provider') == 'groq' and not v:
            raise ValueError(
                "GROQ_API_KEY is required when LLM_PROVIDER is 'groq'")
        return v

    def get_cors_origins(self) -> list[str]:
        """Parse comma-separated CORS origins from config."""
        return [origin.strip() for origin in self.allowed_cors_origins.split(",") if origin.strip()]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


# Module-level configuration initialization (Fail-Fast active)
try:
    orchestrator_settings = OrchestratorSettings()
except Exception as e:
    import sys
    import logging
    logging.basicConfig(level=logging.ERROR)
    logger = logging.getLogger("ORCHESTRATOR_CONFIG")
    logger.error(
        f"Critical failure starting Core Orchestrator: Check the .env file or "
        f"required environment variables. Details: {e}")
    sys.exit(1)

"""Centralized configuration module for the Core Orchestrator.

Uses pydantic-settings for robust ingestion and strict typing of environment variables
that regulate perimeter REST ports, log time window thresholds,
and MCP subprocess initialization paths.
"""

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

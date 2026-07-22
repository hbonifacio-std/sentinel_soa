"""Centralized configuration module for the Core Orchestrator.

Uses pydantic-settings for robust ingestion and strict typing of environment variables
that regulate perimeter REST ports, log time window thresholds,
and MCP subprocess initialization paths.
"""

from urllib.parse import urlparse
from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
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

    app_env: str = Field(
        default="development",
        validation_alias="APP_ENV",
        description="Execution environment (development, staging, production, test)."
    )

    secret_source: str = Field(
        default="env",
        validation_alias="SECRET_SOURCE",
        description="Secret origin provider (env, vault, aws_secrets_manager, gcp_secret_manager, azure_key_vault)."
    )

    secret_rotation_days: int = Field(
        default=30,
        validation_alias="SECRET_ROTATION_DAYS",
        gt=0,
        le=365,
        description="Maximum secret age in days before mandatory rotation."
    )

    require_https_in_production: bool = Field(
        default=True,
        validation_alias="REQUIRE_HTTPS_IN_PRODUCTION",
        description="If true, production rejects plain HTTP origins."
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

    @field_validator("app_env")
    @classmethod
    def validate_app_env(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed = {"development", "staging", "production", "test"}
        if normalized not in allowed:
            raise ValueError(
                f"APP_ENV must be one of {sorted(allowed)}, got '{value}'.")
        return normalized

    @field_validator("secret_source")
    @classmethod
    def validate_secret_source(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed = {
            "env",
            "vault",
            "aws_secrets_manager",
            "gcp_secret_manager",
            "azure_key_vault",
        }
        if normalized not in allowed:
            raise ValueError(
                f"SECRET_SOURCE must be one of {sorted(allowed)}, got '{value}'.")
        return normalized

    @field_validator("jwt_secret_key")
    @classmethod
    def validate_jwt_secret_key_strength(
        cls,
        value: SecretStr,
        info: ValidationInfo,
    ) -> SecretStr:
        secret = value.get_secret_value().strip()
        if not secret:
            raise ValueError("JWT_SECRET_KEY cannot be empty.")

        app_env = (info.data.get("app_env") or "development").lower()
        lowered = secret.lower()
        placeholder_markers = (
            "<generar_",
            "<set_",
            "your-super-secret-key-here",
            "replace-me",
            "changeme",
        )
        if app_env == "production":
            if len(secret) < 32:
                raise ValueError(
                    "JWT_SECRET_KEY must be at least 32 characters in production.")
            if secret.startswith("<") or any(marker in lowered for marker in placeholder_markers):
                raise ValueError(
                    "JWT_SECRET_KEY cannot be a placeholder in production.")
        return value

    @field_validator("allowed_cors_origins")
    @classmethod
    def validate_allowed_cors_origins(cls, value: str, info: ValidationInfo) -> str:
        origins = [origin.strip() for origin in value.split(",") if origin.strip()]
        if not origins:
            raise ValueError("ALLOWED_CORS_ORIGINS must define at least one origin.")
        app_env = (info.data.get("app_env") or "development").lower()
        require_https = bool(info.data.get("require_https_in_production", True))
        for origin in origins:
            if "*" in origin:
                raise ValueError("Wildcard origins are not allowed in ALLOWED_CORS_ORIGINS.")
            parsed = urlparse(origin)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"Invalid origin in ALLOWED_CORS_ORIGINS: {origin}")
            if (
                app_env == "production"
                and require_https
                and parsed.scheme != "https"
                and parsed.hostname not in {"localhost", "127.0.0.1"}
            ):
                raise ValueError(
                    f"ALLOWED_CORS_ORIGINS must use https in production. Invalid origin: {origin}")
        return ",".join(origins)

    @model_validator(mode="after")
    def validate_production_secret_policy(self) -> "OrchestratorSettings":
        if self.app_env != "production":
            return self
        if self.secret_source == "env":
            raise ValueError(
                "SECRET_SOURCE cannot be 'env' in production. Use a managed secret provider.")
        if self.secret_rotation_days > 90:
            raise ValueError(
                "SECRET_ROTATION_DAYS must be 90 days or less in production.")
        if not self.require_https_in_production:
            raise ValueError(
                "REQUIRE_HTTPS_IN_PRODUCTION must remain enabled in production.")
        return self

    def get_cors_origins(self) -> list[str]:
        """Parse comma-separated CORS origins from config."""
        return [origin.strip() for origin in self.allowed_cors_origins.split(",") if origin.strip()]

    def get_trusted_hosts(self) -> list[str]:
        hosts: set[str] = {"localhost", "127.0.0.1"}
        # Agregar Docker network hosts
        hosts.add("core")
        hosts.add("172.18.0.0/16")  # Docker default bridge network
        for origin in self.get_cors_origins():
            parsed = urlparse(origin)
            if parsed.hostname:
                hosts.add(parsed.hostname)
        return sorted(hosts)

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

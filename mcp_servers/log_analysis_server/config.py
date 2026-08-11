"""Runtime configuration for the MCP telemetry intelligence server."""

from __future__ import annotations

import logging
import sys
from typing import Literal, Optional

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AllowedCollectionName = Literal["raw_telemetry", "reports"]


class LogAnalysisServerSettings(BaseSettings):
    """Centralized settings loaded from inherited environment variables."""

    app_env: str = Field(default="development", validation_alias="APP_ENV")
    secret_source: str = Field(default="env", validation_alias="SECRET_SOURCE")

    mongo_host: str = Field(default="localhost", validation_alias="MONGO_HOST")
    mongo_port: int = Field(default=27017, validation_alias="MONGO_PORT", gt=0)
    mongo_user: Optional[str] = Field(default=None, validation_alias="MONGO_USER")
    mongo_password: Optional[SecretStr] = Field(default=None, validation_alias="MONGO_PASSWORD")
    mongo_auth_source: str = Field(default="admin", validation_alias="MONGO_AUTH_SOURCE")
    mongo_db_name: str = Field(default="sentinel_soa", validation_alias="MONGO_DB_NAME")

    raw_telemetry_collection: AllowedCollectionName = Field(
        default="raw_telemetry",
        validation_alias="MONGO_RAW_TELEMETRY_COLLECTION",
    )
    reports_collection: AllowedCollectionName = Field(
        default="reports",
        validation_alias="MONGO_REPORTS_COLLECTION",
    )

    max_query_limit: int = Field(default=500, validation_alias="MCP_MAX_QUERY_LIMIT", ge=1, le=5000)
    mongo_server_selection_timeout_ms: int = Field(
        default=5000,
        validation_alias="MONGO_SERVER_SELECTION_TIMEOUT_MS",
        gt=0,
    )
    mongo_connect_timeout_ms: int = Field(default=5000, validation_alias="MONGO_CONNECT_TIMEOUT_MS", gt=0)
    mongo_socket_timeout_ms: int = Field(default=15000, validation_alias="MONGO_SOCKET_TIMEOUT_MS", gt=0)

    model_config = SettingsConfigDict(extra="ignore")

    @field_validator("app_env")
    @classmethod
    def validate_app_env(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed = {"development", "staging", "production", "test"}
        if normalized not in allowed:
            raise ValueError(f"APP_ENV must be one of {sorted(allowed)}, got '{value}'.")
        return normalized

    @field_validator("secret_source")
    @classmethod
    def validate_secret_source(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed = {"env", "vault", "aws_secrets_manager", "gcp_secret_manager", "azure_key_vault"}
        if normalized not in allowed:
            raise ValueError(f"SECRET_SOURCE must be one of {sorted(allowed)}, got '{value}'.")
        return normalized

    @field_validator("mongo_db_name")
    @classmethod
    def validate_mongo_db_name(cls, value: str) -> str:
        normalized = value.strip()
        if normalized != "sentinel_soa":
            raise ValueError("MONGO_DB_NAME must be exactly 'sentinel_soa' for MCP least-privilege policy.")
        return normalized

    @model_validator(mode="after")
    def validate_production_secret_policy(self) -> "LogAnalysisServerSettings":
        if self.app_env == "production" and self.secret_source == "env":
            raise ValueError("SECRET_SOURCE cannot be 'env' in production. Use a managed secret provider.")
        return self

    def build_mongo_uri(self) -> str:
        """Build the Mongo connection URI using inherited credentials."""
        if self.mongo_user and self.mongo_password:
            password = self.mongo_password.get_secret_value()
            return (
                f"mongodb://{self.mongo_user}:{password}@{self.mongo_host}:{self.mongo_port}/"
                f"{self.mongo_db_name}?authSource={self.mongo_auth_source}"
            )
        return f"mongodb://{self.mongo_host}:{self.mongo_port}/{self.mongo_db_name}"


try:
    server_settings = LogAnalysisServerSettings()
except Exception as exc:
    logging.basicConfig(
        level=logging.ERROR,
        stream=sys.stderr,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        force=True,
    )
    logger = logging.getLogger("MCP_SERVER_CONFIG")
    logger.error("Critical failure initializing MCP server settings: %s", exc)
    sys.exit(1)
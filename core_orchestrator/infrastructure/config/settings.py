import sys
import logging
from typing import Self

from pydantic import Field, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .database_settings import MongoSettings, RedisSettings
from .network_settings import NetworkSettings
from .security_settings import SecuritySettings
from .mcp_settings import MCPSettings
from .detection_settings import DetectionSettings
from .tenat_auth_config import TenantAuthConfig
from ...domain.exceptions.config_exceptions import MissingEnvironmentVariableError, InvalidEnvironmentVariableError

logger = logging.getLogger("ORCHESTRATOR_CONFIG")


class OrchestratorSettings(BaseSettings):
    """
    Handles the settings and configuration required for the application's
    orchestration layer.

    This class serves as a single point of configuration for various
    application settings, such as network, security, tenant authentication,
    multi-cloud provider (MCP), detection mechanisms, and database
    integration. It provides validation to ensure that the application is
    configured securely, especially in production environments.

    Attributes:
        network (NetworkSettings): Holds configuration related to the
            application's networking requirements, including environment
            and protocols
        security (SecuritySettings): Contains security-related settings,
            such as secret management and rotation policies
        tenant_config (TenantAuthConfig): Configuration for tenant-specific
            authentication mechanisms
        mcp (MCPSettings): Settings for multi-cloud provider integrations
        detection (DetectionSettings): Specifies detection-related
            configurations, such as alerting and monitoring
        database_mongodb (MongoSettings): Contains configuration details for
            MongoDB integration
        database_redis (RedisSettings): Contains configuration details for
            Redis integration

    Methods:
        validate_production_secret_policy() -> Self:
            Validates settings when the application environment is set to
            production. Ensures that secret management, rotation policies,
            and security protocols comply with production requirements.
    """

    network: NetworkSettings = Field(default_factory=NetworkSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    tenant_config: TenantAuthConfig = Field(default_factory=TenantAuthConfig)
    mcp: MCPSettings = Field(default_factory=MCPSettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    database_mongodb: MongoSettings = Field(default_factory=MongoSettings)
    database_redis:RedisSettings = Field(default_factory=RedisSettings)

    @model_validator(mode="after")
    def validate_production_secret_policy(self) -> Self:
        """
        Validates production secret policy after the object is initialized. This method ensures
        that specific security and network configurations meet the required standards when the
        application environment is set to "production". It enforces rules related to secret
        source management, secret rotation policies, and HTTPS requirements in production.

        Raises:
            ValueError: If the secret source is configured as "env" in production.
            ValueError: If the secret rotation days exceed 90 days in production.
            ValueError: If HTTPS is not required in production.

        Returns:
            Self: The instance of the current object after validation.
        """
        app_env = str(self.network.app_env).lower()

        if app_env == "production":
            secret_source = str(self.security.secret_source).lower()
            if secret_source == "env":
                raise ValueError(
                    "SECRET_SOURCE cannot be 'env' in production. Use a managed secret provider."
                )

            if self.security.secret_rotation_days > 90:
                raise ValueError(
                    "SECRET_ROTATION_DAYS must be 90 days or less in production."
                )

            if not self.network.require_https_in_production:
                raise ValueError(
                    "REQUIRE_HTTPS_IN_PRODUCTION must remain enabled in production."
                )

        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


def load_orchestrator_settings() -> OrchestratorSettings:
    """Loads and validates Orchestrator settings.

    Translates internal Pydantic ValidationError exceptions into explicit
    infrastructure domain exceptions (MissingEnvironmentVariableError or
    InvalidEnvironmentVariableError).
    """
    try:
        return OrchestratorSettings()
    except ValidationError as exc:
        for error in exc.errors():
            # Extract the field name or target variable from the error location tuple
            field_name = str(error["loc"][-1]) if error["loc"] else "UNKNOWN_ENV"
            error_type = error["type"]
            msg = error["msg"]

            # 1. Missing required variable
            if "missing" in error_type:
                raise MissingEnvironmentVariableError(variable_name=field_name) from exc

            # 2. Invalid format, value, constraint, or type mismatch
            input_val = str(error.get("input", "N/A"))
            raise InvalidEnvironmentVariableError(
                variable_name=field_name,
                current_value=input_val,
                reason=msg,
            ) from exc

        raise InvalidEnvironmentVariableError(
                variable_name="UNKNOWN_ENV",
                current_value="N/A",
                reason="Unknown validation error",
            ) from exc


try:
    orchestrator_settings: OrchestratorSettings = load_orchestrator_settings()
    logger.info("Orchestrator settings loaded successfully.")
except (MissingEnvironmentVariableError, InvalidEnvironmentVariableError) as config_err:
    logging.basicConfig(level=logging.ERROR)
    logger.critical("Critical configuration failure on application startup:")
    logger.critical(str(config_err))
    sys.exit(1)
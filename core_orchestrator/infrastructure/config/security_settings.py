
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings

from core_orchestrator.domain.exceptions.config_exceptions import MissingEnvironmentVariableError


class SecuritySettings(BaseSettings):
    secret_source: str = Field(default="env", validation_alias="SECRET_SOURCE")
    secret_rotation_days: int = Field(default=30, validation_alias="SECRET_ROTATION_DAYS", gt=0, le=365)
    hmac_replay_window_seconds: int = Field(default=300, validation_alias="HMAC_REPLAY_WINDOW_SECONDS", gt=0)
    jwt_secret_key: SecretStr = Field(validation_alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", validation_alias="JWT_ALGORITHM")
    jwt_expiration_minutes: int = Field(default=60, validation_alias="JWT_EXPIRATION_MINUTES", gt=0)
    jwt_expiration_refresh_days: int = Field(default=7, validation_alias="JWT_EXPIRATION_DAY_REFRESH", gt=0)

    @field_validator("jwt_secret_key")
    @classmethod
    def validate_jwt_secret_key_strength(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value().strip()
        if not secret:
            raise MissingEnvironmentVariableError ("JWT_SECRET_KEY cannot be empty.")
        return value
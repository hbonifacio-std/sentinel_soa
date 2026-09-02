
from pydantic import Field, ValidationInfo, field_validator
from pydantic_settings import BaseSettings
from urllib.parse import urlparse

class NetworkSettings(BaseSettings):
    api_port: int = Field(default=8000, validation_alias="API_PORT")
    app_env: str = Field(default="development", validation_alias="APP_ENV")
    require_https_in_production: bool = Field(default=True, validation_alias="REQUIRE_HTTPS_IN_PRODUCTION")
    allowed_cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:8000",
        validation_alias="ALLOWED_CORS_ORIGINS"
    )

    @field_validator("app_env")
    @classmethod
    def validate_app_env(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed = {"development", "staging", "production", "test"}
        if normalized not in allowed:
            raise ValueError(f"APP_ENV must be one of {sorted(allowed)}, got '{value}'.")
        return normalized

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
                raise ValueError(f"ALLOWED_CORS_ORIGINS must use https in production. Invalid origin: {origin}")
        return ",".join(origins)
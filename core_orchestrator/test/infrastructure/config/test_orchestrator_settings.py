import pytest
from pydantic import ValidationError

from core_orchestrator.infrastructure.config.config import OrchestratorSettings


def test_defaults_allow_development_http_origins(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "a" * 40)
    settings = OrchestratorSettings(_env_file=None)
    assert settings.app_env == "development"
    assert settings.secret_source == "env"


def test_production_rejects_env_secret_source(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "a" * 40)
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SECRET_SOURCE", "env")
    monkeypatch.setenv("ALLOWED_CORS_ORIGINS", "https://soc.example.com")
    with pytest.raises(ValidationError, match="SECRET_SOURCE cannot be 'env'"):
        OrchestratorSettings(_env_file=None)


def test_production_rejects_http_cors_origin(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "a" * 40)
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SECRET_SOURCE", "vault")
    monkeypatch.setenv("ALLOWED_CORS_ORIGINS", "http://soc.example.com")
    with pytest.raises(ValidationError, match="must use https"):
        OrchestratorSettings(_env_file=None)


def test_production_rejects_placeholder_jwt_secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "<GENERAR_VALOR_SEGURO_token_urlsafe_32>")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SECRET_SOURCE", "vault")
    monkeypatch.setenv("ALLOWED_CORS_ORIGINS", "https://soc.example.com")
    with pytest.raises(ValidationError, match="cannot be a placeholder"):
        OrchestratorSettings(_env_file=None)

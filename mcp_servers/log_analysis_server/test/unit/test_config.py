import pytest
from pydantic import ValidationError

from mcp_servers.log_analysis_server.config import LogAnalysisServerSettings, server_settings


def test_log_analysis_server_settings_defaults() -> None:
    settings = LogAnalysisServerSettings()
    assert settings.mongo_db_name == "sentinel_soa"
    assert settings.raw_telemetry_collection == "raw_telemetry"
    assert settings.reports_collection == "reports"
    assert settings.max_query_limit >= 1


def test_db_scope_rejects_non_sentinel_database(monkeypatch) -> None:
    monkeypatch.setenv("MONGO_DB_NAME", "other_db")
    with pytest.raises(ValidationError, match="must be exactly 'sentinel_soa'"):
        LogAnalysisServerSettings()


def test_production_requires_managed_secret_source(monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SECRET_SOURCE", "env")
    with pytest.raises(ValidationError, match="SECRET_SOURCE cannot be 'env'"):
        LogAnalysisServerSettings()


def test_server_settings_singleton() -> None:
    assert server_settings is not None
    assert isinstance(server_settings, LogAnalysisServerSettings)

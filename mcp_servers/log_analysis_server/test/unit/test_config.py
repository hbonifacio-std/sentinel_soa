import pytest
from pydantic import SecretStr
from mcp_servers.log_analysis_server.config import ModelDefinition, LogAnalysisServerSettings, server_settings

def test_model_definition_parsing():
    model = ModelDefinition(
        provider="ollama",
        model_name="test-model",
        max_output_tokens=100,
        max_input_tokens=200
    )
    assert model.provider == "ollama"
    assert model.model_name == "test-model"
    assert model.max_output_tokens == 100
    assert model.max_input_tokens == 200

def test_log_analysis_server_settings_defaults():
    settings = LogAnalysisServerSettings()
    assert settings.default_model_id == "qwen2_5_coder7"
    assert "qwen2_5_coder7" in settings.available_models
    assert settings.ollama_base_url == "http://localhost:11434"

def test_validate_ollama_base_url(monkeypatch):
    monkeypatch.setenv("OLLAMA_BASE_URL", "")
    settings = LogAnalysisServerSettings()
    assert settings.ollama_base_url == "http://ollama:11434"
    
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://custom-ollama:11434")
    settings_custom = LogAnalysisServerSettings()
    assert settings_custom.ollama_base_url == "http://custom-ollama:11434"

def test_get_provider_config(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-secret")
    monkeypatch.setenv("GROQ_API_KEY", "groq-secret")
    settings = LogAnalysisServerSettings()
    prov_config = settings.get_provider_config()
    assert prov_config["gemini_api_key"] == "gemini-secret"
    assert prov_config["openai_api_key"] == "openai-secret"
    assert prov_config["groq_api_key"] == "groq-secret"


def test_server_settings_singleton():
    assert server_settings is not None
    assert isinstance(server_settings, LogAnalysisServerSettings)

"""
Unit tests for all LLM providers.
External dependencies (openai, groq, google-generativeai) are mocked
at the sys.modules level so no real packages need to be installed.
"""
import sys
import json
import asyncio
import importlib
from unittest.mock import MagicMock, AsyncMock, patch, PropertyMock
import pytest

# ---------------------------------------------------------------------------
# Stub all third-party SDK modules before any provider is imported
# ---------------------------------------------------------------------------
_OPENAI_STUB = MagicMock()
_OPENAI_STUB.AsyncOpenAI = MagicMock
sys.modules.setdefault('openai', _OPENAI_STUB)

_GROQ_STUB = MagicMock()
_GROQ_STUB.AsyncGroq = MagicMock
sys.modules.setdefault('groq', _GROQ_STUB)

_GENAI_STUB = MagicMock()
_GENAI_TYPES_STUB = MagicMock()
sys.modules.setdefault('google.generativeai', _GENAI_STUB)
sys.modules.setdefault('google.generativeai.types', _GENAI_TYPES_STUB)

# Now import providers safely
from mcp_servers.log_analysis_server.llm_providers import create_llm_provider  # noqa: E402
from mcp_servers.log_analysis_server.llm_providers.base import LLMResponse, LLMException  # noqa: E402
from mcp_servers.log_analysis_server.llm_providers.gemini_provider import GeminiProvider  # noqa: E402
from mcp_servers.log_analysis_server.llm_providers.ollama_provider import OllamaProvider  # noqa: E402
from mcp_servers.log_analysis_server.llm_providers.response_normalizer import normalize_llm_decision
from mcp_servers.log_analysis_server.services.json_utils import extract_json_object  # noqa: E402
from mcp_servers.log_analysis_server.llm_providers.openai_provider import OpenAIProvider  # noqa: E402
from mcp_servers.log_analysis_server.llm_providers.groq_provider import GroqProvider  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_BASE_CONFIG = {
    "gemini_api_key": "test-gemini-key",
    "ollama_base_url": "http://localhost:11434",
    "ollama_timeout_seconds": 30,
    "openai_api_key": "test-openai-key",
    "openai_max_output_tokens": 4096,
    "openai_timeout_seconds": 30,
    "groq_api_key": "test-groq-key",
    "groq_max_output_tokens": 4096,
    "groq_timeout_seconds": 30,
}


# ---------------------------------------------------------------------------
# 1. LLMResponse model
# ---------------------------------------------------------------------------
def test_llm_response_ignores_extra_fields():
    resp = LLMResponse.model_validate({
        "threat_score": 42,
        "reasoning_summary": "Test",
        "recommendation": "Do nothing",
        "extra_field": "should be dropped",
    })
    assert resp.threat_score == 42
    assert not hasattr(resp, "extra_field")


def test_llm_response_schema_structure():
    schema = LLMResponse.to_dict_schema()
    assert schema["type"] == "OBJECT"
    for field in ("threat_score", "reasoning_summary", "recommendation"):
        assert field in schema["properties"]
        assert field in schema["required"]


# ---------------------------------------------------------------------------
# 2. Factory
# ---------------------------------------------------------------------------
def test_factory_creates_ollama():
    prov = create_llm_provider("ollama", "mistral", 4096, _BASE_CONFIG)
    assert isinstance(prov, OllamaProvider)
    assert prov.provider_name == "ollama"
    assert prov.model_name == "mistral"


def test_factory_creates_gemini():
    prov = create_llm_provider("gemini", "gemini-3.5-flash", 4096, _BASE_CONFIG)
    assert isinstance(prov, GeminiProvider)
    assert prov.provider_name == "gemini"


def test_factory_creates_openai():
    prov = create_llm_provider("openai", "gpt-3.5-turbo", 4096, _BASE_CONFIG)
    assert isinstance(prov, OpenAIProvider)
    assert prov.provider_name == "openai"


def test_factory_creates_groq():
    prov = create_llm_provider("groq", "llama-3.3-70b-versatile", 4096, _BASE_CONFIG, max_input_tokens=1000)
    assert isinstance(prov, GroqProvider)
    assert prov.provider_name == "groq"


def test_factory_raises_for_unknown_provider():
    with pytest.raises(LLMException):
        create_llm_provider("unknown_provider", "model", 4096, _BASE_CONFIG)


# ---------------------------------------------------------------------------
# 3. GeminiProvider
# ---------------------------------------------------------------------------
def test_gemini_provider_raises_without_api_key():
    with pytest.raises(LLMException):
        GeminiProvider(model_name="gemini-3.5-flash", api_key=None)


def test_gemini_provider_properties():
    prov = GeminiProvider(model_name="gemini-3.5-flash", api_key="key")
    assert prov.provider_name == "gemini"
    assert prov.model_name == "gemini-3.5-flash"


@pytest.mark.asyncio
async def test_gemini_call_model():
    prov = GeminiProvider(model_name="gemini-3.5-flash", api_key="key")
    json_payload = '{"threat_score": 30, "reasoning_summary": "Gemini summary", "recommendation": "Gemini recommendation"}'

    mock_response = MagicMock()
    mock_response.text = json_payload

    mock_model = MagicMock()
    mock_model.generate_content.return_value = mock_response

    with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
        prov._model = mock_model
        result = await prov.call_model("test prompt")

    assert "threat_score" in result
    validated = await prov.validate_response(result)
    assert validated.threat_score == 30


# ---------------------------------------------------------------------------
# 4. OllamaProvider
# ---------------------------------------------------------------------------
def test_ollama_provider_properties():
    prov = OllamaProvider(model_name="mistral", base_url="http://localhost:11434")
    assert prov.provider_name == "ollama"
    assert prov.model_name == "mistral"


def test_ollama_get_client_reuses_single_instance():
    prov = OllamaProvider(model_name="mistral", base_url="http://localhost:11434")
    first_client = prov._get_client()
    second_client = prov._get_client()
    assert first_client is second_client


def test_ollama_extract_json_object_direct():
    raw = '{"threat_score": 55, "reasoning_summary": "r", "recommendation": "rec"}'
    assert extract_json_object(raw)["threat_score"] == 55


def test_ollama_extract_json_object_fenced():
    raw = '```json\n{"threat_score": 60, "reasoning_summary": "r", "recommendation": "rec"}\n```'
    assert extract_json_object(raw)["threat_score"] == 60


def test_ollama_extract_json_object_substring():
    raw = 'some prefix {"threat_score": 65, "reasoning_summary": "r", "recommendation": "rec"} suffix'
    assert extract_json_object(raw)["threat_score"] == 65


def test_ollama_normalize_response_alias_mapping():
    normalized = normalize_llm_decision({
        "score": 70,
        "summary": "Aliases test",
        "mitigation": "Do something",
    }, use_fallback_defaults=True)
    assert normalized["threat_score"] == 70
    assert normalized["reasoning_summary"] == "Aliases test"
    assert normalized["recommendation"] == "Do something"


@pytest.mark.asyncio
async def test_ollama_call_model_and_validate():
    prov = OllamaProvider(model_name="mistral", base_url="http://localhost:11434")
    json_payload = '{"threat_score": 45, "reasoning_summary": "Ollama r", "recommendation": "Ollama rec"}'

    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.raise_for_status = MagicMock()
    mock_http_response.json.return_value = {
        "response": json_payload
    }

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_http_response)

    with patch.object(prov, "_get_client", return_value=mock_client):
        result = await prov.call_model("test prompt")

    assert "threat_score" in result
    validated = await prov.validate_response(result)
    assert validated.threat_score == 45


@pytest.mark.asyncio
async def test_ollama_call_model_raises_on_http_error():
    prov = OllamaProvider(model_name="mistral", base_url="http://localhost:11434")
    import httpx
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

    with patch.object(prov, "_get_client", return_value=mock_client):
        with pytest.raises(LLMException):
            await prov.call_model("test prompt")


# ---------------------------------------------------------------------------
# 5. OpenAIProvider
# ---------------------------------------------------------------------------
def test_openai_provider_properties():
    prov = OpenAIProvider(model_name="gpt-3.5-turbo", api_key="openai-key")
    assert prov.provider_name == "openai"
    assert prov.model_name == "gpt-3.5-turbo"


@pytest.mark.asyncio
async def test_openai_call_model_and_validate():
    prov = OpenAIProvider(model_name="gpt-3.5-turbo", api_key="openai-key")
    json_payload = '{"threat_score": 55, "reasoning_summary": "OpenAI r", "recommendation": "OpenAI rec"}'

    mock_completion = MagicMock()
    mock_completion.choices = [MagicMock()]
    mock_completion.choices[0].message.content = json_payload

    mock_client = MagicMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_completion)
    prov._client = mock_client

    result = await prov.call_model("test prompt")

    assert "threat_score" in result
    validated = await prov.validate_response(result)
    assert validated.threat_score == 55


# ---------------------------------------------------------------------------
# 6. GroqProvider
# ---------------------------------------------------------------------------
def test_groq_provider_properties():
    prov = GroqProvider(model_name="llama3", api_key="groq-key")
    assert prov.provider_name == "groq"
    assert prov.model_name == "llama3"


@pytest.mark.asyncio
async def test_groq_call_model_and_validate():
    prov = GroqProvider(model_name="llama3", api_key="groq-key")
    json_payload = '{"threat_score": 65, "reasoning_summary": "Groq r", "recommendation": "Groq rec"}'

    mock_completion = MagicMock()
    mock_completion.choices = [MagicMock()]
    mock_completion.choices[0].message.content = json_payload

    mock_client = MagicMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_completion)
    prov._client = mock_client

    result = await prov.call_model("test prompt")

    assert "threat_score" in result
    validated = await prov.validate_response(result)
    assert validated.threat_score == 65

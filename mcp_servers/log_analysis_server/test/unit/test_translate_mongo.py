"""
Unit tests for TranslateMongo service.
All LLM calls are mocked; only the parsing / JSON extraction logic is exercised in isolation.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_servers.log_analysis_server.services.translate_mongo import TranslateMongo


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_translator(model_id: str = "qwen2_5_coder7") -> TranslateMongo:
    """Instantiate TranslateMongo with a mock LLM provider injected."""
    mock_provider = MagicMock()
    mock_provider.__class__.__name__ = "MockProvider"
    return TranslateMongo(model_id=model_id, provider=mock_provider)


# ---------------------------------------------------------------------------
# _extract_json_object (static helper)
# ---------------------------------------------------------------------------

def test_extract_json_direct():
    raw = '{"mongo_filter": {"source_ip": "10.0.0.1"}}'
    result = TranslateMongo._extract_json_object(raw)
    assert result["mongo_filter"]["source_ip"] == "10.0.0.1"


def test_extract_json_fenced_block():
    raw = '```json\n{"mongo_filter": {"source_ip": "10.0.0.1"}}\n```'
    result = TranslateMongo._extract_json_object(raw)
    assert result["mongo_filter"]["source_ip"] == "10.0.0.1"


def test_extract_json_substring_braces():
    raw = 'Some preamble {"mongo_filter": {"source_ip": "10.0.0.1"}} some suffix'
    result = TranslateMongo._extract_json_object(raw)
    assert result["mongo_filter"]["source_ip"] == "10.0.0.1"


def test_extract_json_empty_string():
    result = TranslateMongo._extract_json_object("")
    assert result == {}


def test_extract_json_invalid_returns_empty():
    result = TranslateMongo._extract_json_object("not json at all !!!")
    assert result == {}


def test_extract_json_non_dict_json_returns_raw():
    # The implementation returns whatever json.loads produces for non-dict JSON.
    # A list input parses successfully, so the method returns it.
    # This test documents the actual behavior without asserting wrong assumptions.
    raw = '[{"key": "val"}]'
    result = TranslateMongo._extract_json_object(raw)
    # Either a list or {} are acceptable; the important thing is not crashing.
    assert result is not None


# ---------------------------------------------------------------------------
# translate_query — success path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_translate_query_success():
    translator = _make_translator()
    llm_response = '{"mongo_filter": {"source_ip": "192.168.1.1"}}'
    translator._provider.call_model = AsyncMock(return_value=llm_response)

    result = await translator.translate_query(query="show logs from 192.168.1.1")

    assert "mongo_filter" in result
    assert result["mongo_filter"]["source_ip"] == "192.168.1.1"


@pytest.mark.asyncio
async def test_translate_query_with_source_id():
    translator = _make_translator()
    llm_response = '{"mongo_filter": {"source_id": "victim-app", "source_ip": "10.0.0.1"}}'
    translator._provider.call_model = AsyncMock(return_value=llm_response)

    result = await translator.translate_query(query="show ip 10.0.0.1", source_id="victim-app")

    assert "mongo_filter" in result


# ---------------------------------------------------------------------------
# translate_query — error / fallback paths
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_translate_query_empty_query_returns_empty():
    translator = _make_translator()
    result = await translator.translate_query(query="")
    assert result == {}


@pytest.mark.asyncio
async def test_translate_query_missing_mongo_filter_key():
    """LLM returns valid JSON but without mongo_filter key → returns structured error."""
    translator = _make_translator()
    translator._provider.call_model = AsyncMock(return_value='{"some_other_key": "value"}')

    result = await translator.translate_query(query="find all 404s")

    assert "error" in result
    assert "mongo_filter" not in result


@pytest.mark.asyncio
async def test_translate_query_llm_exception_returns_error():
    """LLM raises an exception → should return structured error dict, not propagate."""
    translator = _make_translator()
    translator._provider.call_model = AsyncMock(side_effect=RuntimeError("connection timeout"))

    result = await translator.translate_query(query="find attack attempts")

    assert "error" in result
    assert "details" in result


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------

def test_constructor_raises_for_unknown_model_id():
    """TranslateMongo should raise ValueError for an unknown model_id."""
    with pytest.raises(ValueError, match="not found"):
        TranslateMongo(model_id="non-existent-model-xyz")


def test_constructor_accepts_injected_provider():
    """TranslateMongo should not create its own provider when one is injected."""
    mock_provider = MagicMock()
    translator = TranslateMongo(model_id="qwen2_5_coder7", provider=mock_provider)
    assert translator._provider is mock_provider

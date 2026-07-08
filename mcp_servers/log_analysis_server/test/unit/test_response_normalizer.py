"""Unit tests for shared LLM response normalization."""

import json

import pytest

from mcp_servers.log_analysis_server.llm_providers.response_normalizer import (
    normalize_llm_decision,
    parse_llm_decision_response,
)


def test_normalize_llm_decision_alias_mapping():
    normalized = normalize_llm_decision({
        "score": 70,
        "summary": "Aliases test",
        "mitigation": "Do something",
    })
    assert normalized["threat_score"] == 70
    assert normalized["reasoning_summary"] == "Aliases test"
    assert normalized["recommendation"] == "Do something"


def test_normalize_llm_decision_fallback_defaults():
    normalized = normalize_llm_decision({}, use_fallback_defaults=True)
    assert normalized["threat_score"] == 0
    assert "Partial LLM output received" in normalized["reasoning_summary"]
    assert "Strengthen layered detection controls" in normalized["recommendation"]


def test_normalize_llm_decision_without_defaults_uses_empty_strings():
    normalized = normalize_llm_decision({})
    assert normalized["reasoning_summary"] == ""
    assert normalized["recommendation"] == ""


def test_parse_llm_decision_response_fenced_json():
    raw = '```json\n{"threat_score": 60, "reasoning_summary": "r", "recommendation": "rec"}\n```'
    parsed = parse_llm_decision_response(raw)
    assert parsed["threat_score"] == 60
    assert parsed["reasoning_summary"] == "r"


def test_parse_llm_decision_response_with_aliases():
    raw = '{"score": 55, "summary": "ok", "recommended_action": "patch"}'
    parsed = parse_llm_decision_response(raw)
    assert parsed["threat_score"] == 55
    assert parsed["reasoning_summary"] == "ok"
    assert parsed["recommendation"] == "patch"


def test_parse_llm_decision_response_invalid_json_raises():
    with pytest.raises(json.JSONDecodeError):
        parse_llm_decision_response("not json")

"""Regression tests for minimal LLM output contract across providers and orchestration."""

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from mcp_servers.log_analysis_server.llm_providers.base import LLMResponse
from mcp_servers.log_analysis_server.llm_providers.ollama_provider import OllamaProvider
from mcp_servers.log_analysis_server.store.alert_store import alert_store
from mcp_servers.log_analysis_server.tools.analyze_activity import LLMAnalyzer, execute_analyze_web_activity


@pytest.fixture(autouse=True)
def isolated_alert_store():
    """Ensure store isolation to avoid cross-test pollution."""
    alert_store.clear_all()
    yield
    alert_store.clear_all()


def _build_arguments() -> dict:
    now = datetime.now(timezone.utc)
    return {
        "window_id": str(uuid4()),
        "source_id": "victim-app-01",
        "source_ip": "172.18.0.77",
        "window_start_utc": now.isoformat(),
        "window_end_utc": (now + timedelta(seconds=60)).isoformat(),
        "total_requests": 12,
        "unique_uris_requested": ["/auth/login", "/api/products"],
        "user_agents_observed": ["Mozilla/5.0", "python-requests/2.31.0"],
        "requests_per_second_avg": 0.2,
    }


def test_llm_response_ignores_extras_and_keeps_only_three_fields():
    response = LLMResponse.model_validate(
        {
            "threat_score": 78,
            "reasoning_summary": "Correlation indicates staged probing toward auth flow.",
            "recommendation": "Strengthen authentication telemetry correlation and adaptive controls.",
            "threat_level": "HIGH",
            "indicators_found": ["SQL_INJECTION_PROBE"],
        }
    )

    dumped = response.model_dump()

    assert set(dumped.keys()) == {"threat_score", "reasoning_summary", "recommendation"}


def test_ollama_normalization_returns_canonical_three_fields_only():
    normalized = OllamaProvider._normalize_response(
        {
            "score": 64,
            "summary": "Automated scan evolves into focused credential abuse.",
            "mitigation": "Harden auth workflows and improve anomaly detections.",
            "threat_level": "HIGH",
            "window_id": "should-be-ignored",
        }
    )

    assert set(normalized.keys()) == {"threat_score", "reasoning_summary", "recommendation"}
    assert normalized["threat_score"] == 64


def test_execute_analyze_web_activity_computes_backend_fields_from_minimal_llm(monkeypatch):
    async def fake_analyze_with_context(cls, telemetry, history):
        return {
            "threat_score": 10,
            "reasoning_summary": "Low-intent noise with limited persistence evidence.",
            "recommendation": "Tune recon-detection thresholds for low-volume probes.",
            "threat_level": "CRITICAL",
            "window_id": "should-not-propagate",
        }

    monkeypatch.setattr(LLMAnalyzer, "analyze_with_context", classmethod(fake_analyze_with_context))

    result = asyncio.run(execute_analyze_web_activity(_build_arguments()))

    assert result["threat_score"] == 10
    assert result["threat_detected"] is False
    # Threat level must be derived by backend policy, not trusted from LLM extras.
    assert result["threat_level"] == "NONE"
    assert isinstance(result["targeted_asset"], str)
    assert result["targeted_asset"]


"""
Unit tests for the helper functions in analyze_activity.py and threat_context.py.
Also tests the execute_analyze_web_activity pipeline with a mocked LLMAnalyzer.
"""
import asyncio
import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from unittest.mock import patch, AsyncMock, MagicMock

from mcp_servers.log_analysis_server.tools.analyze_activity import (
    _llm_signature_suffix,
    _append_llm_signature,
    _extract_llm_decision_fields,
    _normalize_score,
    _clean_indicator_text,
    _is_raw_path_indicator,
    _normalize_indicator_label,
    _derive_threat_level,
    _build_targeted_asset,
    _enrich_with_mitre_dictionary,
    _extract_rules_bundle,
    generate_recommendation,
    execute_analyze_web_activity,
    LLMAnalyzer,
    AnalysisDependencies,
    DEFAULT_DEPS,
)
from mcp_servers.log_analysis_server.services.heuristics_engine import ThreatHeuristics
from mcp_servers.log_analysis_server.models.analysis_input import WebActivityWindowInput
from mcp_servers.log_analysis_server.tools.threat_context import (
    ThreatContextRequest,
    execute_get_threat_context,
)
from mcp_servers.log_analysis_server.store.alert_store import alert_store


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_arguments(**overrides):
    now = datetime.now(timezone.utc)
    defaults = dict(
        window_id=str(uuid4()),
        source_id="victim-app-01",
        source_ip="10.0.0.1",
        window_start_utc=now.isoformat(),
        window_end_utc=(now + timedelta(seconds=60)).isoformat(),
        total_requests=5,
        unique_uris_requested=["/api/products"],
        user_agents_observed=["Mozilla/5.0"],
        requests_per_second_avg=0.1,
    )
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# _llm_signature_suffix
# ---------------------------------------------------------------------------

def test_llm_signature_suffix_builds_correctly():
    assert _llm_signature_suffix("openai", "gpt-4o") == "(openai-gpt-4o)"


def test_llm_signature_suffix_empty_provider():
    assert _llm_signature_suffix("", "gpt-4o") == ""


def test_llm_signature_suffix_empty_model():
    assert _llm_signature_suffix("openai", "") == ""


# ---------------------------------------------------------------------------
# _append_llm_signature
# ---------------------------------------------------------------------------

def test_append_llm_signature_appends_once():
    result = _append_llm_signature("Analysis", "openai", "gpt-4o")
    assert result == "Analysis (openai-gpt-4o)"


def test_append_llm_signature_no_duplicate():
    result = _append_llm_signature("Analysis (openai-gpt-4o)", "openai", "gpt-4o")
    assert result.count("(openai-gpt-4o)") == 1


def test_append_llm_signature_empty_text():
    result = _append_llm_signature("", "openai", "gpt-4o")
    assert result == ""


# ---------------------------------------------------------------------------
# _extract_llm_decision_fields
# ---------------------------------------------------------------------------

def test_extract_llm_decision_fields_keeps_only_three():
    raw = {
        "threat_score": 50,
        "reasoning_summary": "Test",
        "recommendation": "Act",
        "extra_field": "drop me",
    }
    result = _extract_llm_decision_fields(raw)
    assert set(result.keys()) == {"threat_score", "reasoning_summary", "recommendation"}


def test_extract_llm_decision_fields_none_input():
    assert _extract_llm_decision_fields(None) == {}


def test_extract_llm_decision_fields_non_dict():
    assert _extract_llm_decision_fields("not a dict") == {}


# ---------------------------------------------------------------------------
# _normalize_score
# ---------------------------------------------------------------------------

def test_normalize_score_clamps_to_0_100():
    assert _normalize_score(-10, 0) == 0
    assert _normalize_score(150, 100) == 100


def test_normalize_score_normal_float():
    assert _normalize_score(45.7, 0) == 46


def test_normalize_score_invalid_falls_to_default():
    assert _normalize_score("not a number", 30) == 30


# ---------------------------------------------------------------------------
# _clean_indicator_text
# ---------------------------------------------------------------------------

def test_clean_indicator_text_strips_emoji():
    result = _clean_indicator_text("🔴 SQL injection detected")
    assert result.startswith("SQL")


def test_clean_indicator_text_empty():
    assert _clean_indicator_text("") == ""


def test_clean_indicator_text_preserves_path():
    result = _clean_indicator_text("/api/admin")
    assert result == "/api/admin"


# ---------------------------------------------------------------------------
# _is_raw_path_indicator
# ---------------------------------------------------------------------------

def test_is_raw_path_indicator_true_for_slash_prefix():
    assert _is_raw_path_indicator("/etc/passwd") is True


def test_is_raw_path_indicator_true_for_traversal():
    assert _is_raw_path_indicator("../etc/passwd") is True


def test_is_raw_path_indicator_false_for_label():
    assert _is_raw_path_indicator("SQL_INJECTION_PROBE") is False


# ---------------------------------------------------------------------------
# _normalize_indicator_label
# ---------------------------------------------------------------------------

def test_normalize_indicator_path_traversal_uri():
    assert _normalize_indicator_label("/../../etc/passwd") == "PATH_TRAVERSAL_PROBE"


def test_normalize_indicator_env_file():
    assert _normalize_indicator_label("/.env") == "SENSITIVE_RESOURCE_ENUMERATION"


def test_normalize_indicator_sql_text():
    assert _normalize_indicator_label("SQL injection pattern detected") == "SQL_INJECTION_PROBE"


def test_normalize_indicator_scanner_text():
    assert _normalize_indicator_label("nikto scanner detected") == "AUTOMATED_SCANNER_FINGERPRINT"


def test_normalize_indicator_404_text():
    assert _normalize_indicator_label("High 404 error ratio") == "HIGH_404_ENUMERATION_RATIO"


def test_normalize_indicator_auth_text():
    assert _normalize_indicator_label("Multiple 403 access denied") == "AUTHENTICATION_OR_AUTHORIZATION_PROBING"


def test_normalize_indicator_rps_text():
    assert _normalize_indicator_label("High RPS detected: 15.00 requests/second") == "ANOMALOUS_REQUEST_RATE"


def test_normalize_indicator_unknown_returns_cleaned():
    result = _normalize_indicator_label("Some unusual metric label")
    assert isinstance(result, str)
    assert len(result) > 0


# ---------------------------------------------------------------------------
# _derive_threat_level
# ---------------------------------------------------------------------------

def test_derive_threat_level_critical():
    assert _derive_threat_level(90) == "CRITICAL"
    assert _derive_threat_level(100) == "CRITICAL"


def test_derive_threat_level_high():
    assert _derive_threat_level(70) == "HIGH"


def test_derive_threat_level_medium():
    assert _derive_threat_level(40) == "MEDIUM"


def test_derive_threat_level_low():
    assert _derive_threat_level(20) == "LOW"


def test_derive_threat_level_none():
    assert _derive_threat_level(0) == "NONE"
    assert _derive_threat_level(19) == "NONE"


# ---------------------------------------------------------------------------
# _build_targeted_asset
# ---------------------------------------------------------------------------

def test_build_targeted_asset_formats_uris():
    inp = WebActivityWindowInput(**_base_arguments(unique_uris_requested=["/api/a", "/api/b", "/api/c"]))
    result = _build_targeted_asset(inp)
    assert "victim-app" in result
    assert "/api/a" in result


# ---------------------------------------------------------------------------
# _enrich_with_mitre_dictionary
# ---------------------------------------------------------------------------

def test_enrich_mitre_no_threat_sets_none_fields():
    assessment = {
        "threat_detected": False,
        "indicators_found": [],
        "source_ip": "10.0.0.1",
    }
    result = _enrich_with_mitre_dictionary(assessment)
    assert result["mitre_tactic"] is None
    assert result["suggested_mitigations"] == []


def test_enrich_mitre_sql_injection_maps_correctly():
    assessment = {
        "threat_detected": True,
        "indicators_found": ["SQL_INJECTION_PROBE"],
        "source_ip": "10.0.0.1",
    }
    result = _enrich_with_mitre_dictionary(assessment)
    assert result["mitre_tactic"] == "Initial Access"
    assert any(m["action"] == "block_ip" for m in result["suggested_mitigations"])


def test_enrich_mitre_path_traversal():
    assessment = {
        "threat_detected": True,
        "indicators_found": ["PATH_TRAVERSAL_PROBE"],
        "source_ip": "10.0.0.2",
    }
    result = _enrich_with_mitre_dictionary(assessment)
    assert "T1190" in result["mitre_technique_id"]


def test_enrich_mitre_unknown_indicator_uses_fallback():
    assessment = {
        "threat_detected": True,
        "indicators_found": ["TOTALLY_UNKNOWN_INDICATOR"],
        "source_ip": "10.0.0.3",
    }
    result = _enrich_with_mitre_dictionary(assessment)
    assert result["mitre_tactic"] == "Reconnaissance"


# ---------------------------------------------------------------------------
# _extract_rules_bundle
# ---------------------------------------------------------------------------

def test_extract_rules_bundle_none_input():
    result = _extract_rules_bundle({"window_id": "x"})
    assert result is None


def test_extract_rules_bundle_invalid_type():
    result = _extract_rules_bundle({"rules_bundle": "not a dict"})
    assert result is None


# ---------------------------------------------------------------------------
# execute_analyze_web_activity — full pipeline with mocked LLMAnalyzer
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_store():
    alert_store.clear_all()
    yield
    alert_store.clear_all()


@pytest.mark.asyncio
async def test_execute_analyze_web_activity_clean_traffic():
    """Clean traffic with low score should produce NONE level, not persist alert."""
    async def fake_analyze(self, telemetry, history):
        return {
            "threat_score": 5,
            "reasoning_summary": "Nothing suspicious",
            "recommendation": "Continue monitoring",
        }

    with patch.object(LLMAnalyzer, "analyze_with_context", fake_analyze):
        result = await execute_analyze_web_activity(_base_arguments())

    assert result["threat_detected"] is False
    assert result["threat_level"] == "NONE"
    assert result["threat_score"] == 5


@pytest.mark.asyncio
async def test_execute_analyze_web_activity_high_score():
    """High heuristic + LLM score should trigger threat detection."""
    async def fake_analyze(self, telemetry, history):
        return {
            "threat_score": 85,
            "reasoning_summary": "SQL injection attempt detected",
            "recommendation": "Block IP",
        }

    args = _base_arguments(
        unique_uris_requested=["/api/users?id=1' OR 1=1--"],
        user_agents_observed=["sqlmap/1.7.8"],
    )

    with patch.object(LLMAnalyzer, "analyze_with_context", fake_analyze):
        result = await execute_analyze_web_activity(args)

    assert result["threat_detected"] is True
    assert result["threat_score"] >= 30


@pytest.mark.asyncio
async def test_execute_analyze_web_activity_includes_required_keys():
    """Output must always include all required fields."""
    async def fake_analyze(self, telemetry, history):
        return {
            "threat_score": 0,
            "reasoning_summary": "Benign",
            "recommendation": "None",
        }

    with patch.object(LLMAnalyzer, "analyze_with_context", fake_analyze):
        result = await execute_analyze_web_activity(_base_arguments())

    required_keys = {
        "window_id", "source_id", "source_ip", "threat_detected",
        "threat_level", "threat_score", "indicators_found",
        "reasoning_summary", "recommendation", "targeted_asset",
        "mitre_tactic", "mitre_technique", "suggested_mitigations",
    }
    assert required_keys.issubset(set(result.keys()))


# ---------------------------------------------------------------------------
# execute_get_threat_context
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execute_get_threat_context_empty_store():
    request = ThreatContextRequest(source_ip="1.2.3.4", limit=10)
    result = await execute_get_threat_context(request)
    assert result["source_ip"] == "1.2.3.4"
    assert result["history"] == []
    assert result["alerts_found"] == 0


@pytest.mark.asyncio
async def test_execute_get_threat_context_raises_on_empty_ip():
    with pytest.raises((ValueError, Exception)):
        request = ThreatContextRequest(source_ip="  ", limit=5)
        await execute_get_threat_context(request)


# ---------------------------------------------------------------------------
# generate_recommendation tests (Fase 3: Coverage for CRITICAL/HIGH/MEDIUM)
# ---------------------------------------------------------------------------

def test_generate_recommendation_critical_level_with_sql_injection():
    """CRITICAL level with SQL injection indicator."""
    recommendation = generate_recommendation(
        threat_level="CRITICAL",
        source_ip="192.168.1.100",
        indicators=["SQL_INJECTION_PROBE", "AUTOMATED_SCANNER_FINGERPRINT"]
    )
    assert "🔴 **CRITICAL LEVEL" in recommendation
    assert "SQL injection attack in progress" in recommendation
    assert "192.168.1.100" in recommendation
    assert "Level 1" in recommendation
    assert "Level 2" in recommendation
    assert "Level 3" in recommendation


def test_generate_recommendation_critical_level_with_path_traversal():
    """CRITICAL level with path traversal indicator."""
    recommendation = generate_recommendation(
        threat_level="CRITICAL",
        source_ip="10.0.0.50",
        indicators=["PATH_TRAVERSAL_PROBE"]
    )
    assert "🔴 **CRITICAL LEVEL" in recommendation
    assert "BLOCK IMMEDIATELY" in recommendation
    assert "10.0.0.50" in recommendation
    assert "file integrity" in recommendation.lower()


def test_generate_recommendation_high_level_with_scanner():
    """HIGH level with scanner fingerprint."""
    recommendation = generate_recommendation(
        threat_level="HIGH",
        source_ip="203.0.113.45",
        indicators=["Scanner activity detected"]
    )
    assert "🟠 **HIGH LEVEL" in recommendation
    assert "rate-limiting" in recommendation
    assert "203.0.113.45" in recommendation
    assert "24 hours" in recommendation


def test_generate_recommendation_high_level_with_auth_probing():
    """HIGH level with authentication probing."""
    recommendation = generate_recommendation(
        threat_level="HIGH",
        source_ip="198.51.100.10",
        indicators=["AUTHENTICATION_OR_AUTHORIZATION_PROBING"]
    )
    assert "🟠 **HIGH LEVEL" in recommendation
    assert "198.51.100.10" in recommendation


def test_generate_recommendation_medium_level():
    """MEDIUM level recommendation."""
    recommendation = generate_recommendation(
        threat_level="MEDIUM",
        source_ip="172.16.0.1",
        indicators=["ANOMALOUS_REQUEST_RATE"]
    )
    assert "🟡 **MEDIUM LEVEL" in recommendation
    assert "MONITORING RECOMMENDED" in recommendation
    assert "rate-limiting" in recommendation
    assert "172.16.0.1" in recommendation


def test_generate_recommendation_low_level():
    """LOW or NONE threat level."""
    recommendation = generate_recommendation(
        threat_level="LOW",
        source_ip="1.1.1.1",
        indicators=[]
    )
    assert "🟢 **LOW/BENIGN LEVEL" in recommendation
    assert "benign" in recommendation.lower()
    assert "No immediate action required" in recommendation


def test_generate_recommendation_with_webshell_indicator():
    """CRITICAL level with webshell attempt."""
    recommendation = generate_recommendation(
        threat_level="CRITICAL",
        source_ip="evil.attacker.com",
        indicators=["WEBSHELL_UPLOAD_ATTEMPT"]
    )
    assert "🔴" in recommendation
    assert "webshell attempt detected" in recommendation


# ---------------------------------------------------------------------------
# Dependency Injection tests (Fase 4)
# ---------------------------------------------------------------------------

def test_analysis_dependencies_default():
    """Default AnalysisDependencies uses production singletons."""
    deps = AnalysisDependencies.default()
    assert deps.alert_store is not None
    assert deps.threat_heuristics_class is ThreatHeuristics


def test_default_deps_singleton():
    """DEFAULT_DEPS is a module-level singleton."""
    assert DEFAULT_DEPS is not None
    assert DEFAULT_DEPS.alert_store is not None
    assert DEFAULT_DEPS.threat_heuristics_class is ThreatHeuristics


@pytest.mark.asyncio
async def test_execute_analyze_web_activity_with_mock_deps():
    """Test execute_analyze_web_activity with injected mock dependencies (no monkeypatch)."""
    from unittest.mock import MagicMock, AsyncMock

    # Create mock dependencies
    mock_alert_store = MagicMock()
    mock_alert_store.get_history_by_ip.return_value = []
    mock_alert_store.add_assessment.return_value = None

    mock_deps = AnalysisDependencies(
        alert_store=mock_alert_store,
        threat_heuristics_class=ThreatHeuristics,
    )

    # Execute with mock deps (no monkeypatch needed!)
    result = await execute_analyze_web_activity(
        _base_arguments(),
        deps=mock_deps,
    )

    # Verify the mock was called
    assert mock_alert_store.get_history_by_ip.called
    assert mock_alert_store.add_assessment.called
    assert result["threat_detected"] is not None


@pytest.mark.asyncio
async def test_execute_analyze_web_activity_uses_default_deps_when_none():
    """Test that execute_analyze_web_activity defaults to DEFAULT_DEPS when deps=None."""
    # Call with deps=None explicitly (or omitted, which defaults to None)
    result = await execute_analyze_web_activity(_base_arguments(), deps=None)

    # Should work without error and use production dependencies
    assert "threat_detected" in result
    assert "threat_score" in result

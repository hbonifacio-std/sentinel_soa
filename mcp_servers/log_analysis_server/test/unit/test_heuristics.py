"""
Unit tests for ThreatHeuristics engine.
All private methods and public analyze() flow are tested in isolation
without any external LLM or network dependency.
"""
import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from unittest.mock import patch

from mcp_servers.log_analysis_server.models.analysis_input import WebActivityWindowInput
from mcp_servers.log_analysis_server.models.rules_bundle import RulesBundle
from mcp_servers.log_analysis_server.services.heuristics_engine import ThreatHeuristics


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _base_telemetry(**overrides) -> WebActivityWindowInput:
    """Returns a minimal, clean-traffic telemetry object. Override as needed."""
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
        http_methods_distribution={"GET": 5},
        response_codes_distribution={"200": 5},
    )
    defaults.update(overrides)
    return WebActivityWindowInput(**defaults)


def _clean_rules() -> RulesBundle:
    """Build a minimal RulesBundle with realistic defaults."""
    from shared.rules_seed import build_seed_bundle_payload
    return RulesBundle.from_cache_dict(build_seed_bundle_payload())


# ---------------------------------------------------------------------------
# _analyze_user_agents
# ---------------------------------------------------------------------------

def test_ua_clean_traffic_returns_zero():
    score, indicators = ThreatHeuristics._analyze_user_agents(
        ["Mozilla/5.0 (Windows NT 10.0)"],
        {"sqlmap": 40, "nikto": 35},
    )
    assert score == 0
    assert indicators == []


def test_ua_sqlmap_detected():
    score, indicators = ThreatHeuristics._analyze_user_agents(
        ["sqlmap/1.7.8"],
        {"sqlmap": 40, "nikto": 35},
    )
    assert score == 40
    assert any("sqlmap" in i.lower() or "SQL" in i for i in indicators)


def test_ua_nikto_detected():
    score, indicators = ThreatHeuristics._analyze_user_agents(
        ["Nikto/2.1.6"],
        {"sqlmap": 40, "nikto": 35},
    )
    assert score == 35
    assert any("nikto" in i.lower() or "Nikto" in i for i in indicators)


def test_ua_multiple_scanners():
    score, _ = ThreatHeuristics._analyze_user_agents(
        ["sqlmap/1.7.8", "Nikto/2.1.6"],
        {"sqlmap": 40, "nikto": 35},
    )
    assert score >= 75


# ---------------------------------------------------------------------------
# _analyze_sensitive_uris
# ---------------------------------------------------------------------------

def test_sensitive_uri_clean():
    score, indicators = ThreatHeuristics._analyze_sensitive_uris(
        ["/api/products", "/api/users"],
        {"/.env": 30, "/.git": 25},
    )
    assert score == 0
    assert indicators == []


def test_sensitive_uri_env_file():
    score, indicators = ThreatHeuristics._analyze_sensitive_uris(
        ["/.env", "/api/users"],
        {"/.env": 30, "/.git": 25},
    )
    assert score == 30
    assert len(indicators) == 1


def test_sensitive_uri_multiple():
    score, indicators = ThreatHeuristics._analyze_sensitive_uris(
        ["/.env", "/.git/config"],
        {"/.env": 30, "/.git": 25},
    )
    assert score == 55
    assert len(indicators) == 2


# ---------------------------------------------------------------------------
# _analyze_response_codes
# ---------------------------------------------------------------------------

def test_response_codes_clean():
    score, _ = ThreatHeuristics._analyze_response_codes({"200": 10}, total=10)
    assert score == 0


def test_response_codes_high_404_ratio():
    score, indicators = ThreatHeuristics._analyze_response_codes({"404": 7, "200": 3}, total=10)
    assert score == 30
    assert any("404" in i for i in indicators)


def test_response_codes_moderate_404_ratio():
    score, indicators = ThreatHeuristics._analyze_response_codes({"404": 5, "200": 5}, total=10)
    assert score == 15


def test_response_codes_5xx_errors():
    score, indicators = ThreatHeuristics._analyze_response_codes({"500": 4, "200": 6}, total=10)
    assert score == 10
    assert any("5xx" in i for i in indicators)


def test_response_codes_403_access_denied():
    score, indicators = ThreatHeuristics._analyze_response_codes({"403": 6, "200": 4}, total=10)
    assert score == 10
    assert any("403" in i for i in indicators)


# ---------------------------------------------------------------------------
# _analyze_requests_per_second
# ---------------------------------------------------------------------------

def test_rps_normal():
    score, _ = ThreatHeuristics._analyze_requests_per_second(rps=0.5, total_requests=5)
    assert score == 0


def test_rps_high():
    score, indicators = ThreatHeuristics._analyze_requests_per_second(rps=15.0, total_requests=150)
    assert score == 25
    assert any("RPS" in i or "rps" in i.lower() for i in indicators)


def test_rps_moderate():
    score, indicators = ThreatHeuristics._analyze_requests_per_second(rps=7.0, total_requests=70)
    assert score == 10


def test_rps_burst_many_requests_slow():
    score, indicators = ThreatHeuristics._analyze_requests_per_second(rps=2.0, total_requests=100)
    assert score == 15
    assert any("Burst" in i for i in indicators)


# ---------------------------------------------------------------------------
# _analyze_http_methods
# ---------------------------------------------------------------------------

def test_http_methods_normal():
    score, _ = ThreatHeuristics._analyze_http_methods({"GET": 10, "POST": 2})
    assert score == 0


def test_http_methods_suspicious_delete():
    score, indicators = ThreatHeuristics._analyze_http_methods({"DELETE": 1, "GET": 5})
    assert score >= 10
    assert any("DELETE" in i for i in indicators)


def test_http_methods_post_without_get():
    score, indicators = ThreatHeuristics._analyze_http_methods({"POST": 10, "GET": 0})
    assert score == 15
    assert any("POST" in i for i in indicators)


def test_http_methods_trace_and_options():
    score, indicators = ThreatHeuristics._analyze_http_methods({"TRACE": 1, "OPTIONS": 1, "GET": 5})
    assert score >= 20


# ---------------------------------------------------------------------------
# _analyze_injection_patterns
# ---------------------------------------------------------------------------

def test_injection_clean_uri():
    score, _ = ThreatHeuristics._analyze_injection_patterns(
        ["/api/products"],
        sql_patterns=["' OR 1=1", "UNION SELECT"],
        traversal_patterns=["../", "%2e%2e"],
    )
    assert score == 0


def test_injection_sql_detected():
    score, indicators = ThreatHeuristics._analyze_injection_patterns(
        ["/api/users?id=1' OR 1=1--"],
        sql_patterns=["' OR 1=1", "UNION SELECT"],
        traversal_patterns=["../", "%2e%2e"],
    )
    assert score >= 30
    assert any("SQL" in i or "sql" in i.lower() for i in indicators)


def test_injection_path_traversal():
    score, indicators = ThreatHeuristics._analyze_injection_patterns(
        ["/api/files?path=../../etc/passwd"],
        sql_patterns=["' OR 1=1"],
        traversal_patterns=["../", "%2e%2e"],
    )
    assert score >= 40
    assert any("traversal" in i.lower() or "Path" in i for i in indicators)


def test_injection_url_encoded_sql():
    score, indicators = ThreatHeuristics._analyze_injection_patterns(
        ["/api/users?id=1%27 OR 1=1--"],
        sql_patterns=["' OR 1=1"],
        traversal_patterns=["../"],
    )
    assert score >= 30


# ---------------------------------------------------------------------------
# analyze() — full pipeline
# ---------------------------------------------------------------------------

def test_analyze_clean_traffic():
    telemetry = _base_telemetry()
    rules = _clean_rules()
    score, indicators, reasoning = ThreatHeuristics.analyze(telemetry, rules_bundle=rules)
    assert score == 0
    assert indicators == []
    assert "No threat indicators detected" in reasoning


def test_analyze_high_rps_triggers_score():
    telemetry = _base_telemetry(requests_per_second_avg=15.0, total_requests=900)
    rules = _clean_rules()
    score, indicators, reasoning = ThreatHeuristics.analyze(telemetry, rules_bundle=rules)
    assert score > 0
    assert any("RPS" in i or "rps" in i.lower() for i in indicators)


def test_analyze_sql_injection_uri():
    telemetry = _base_telemetry(
        unique_uris_requested=["/api/users?id=1' OR 1=1--", "/api/products"]
    )
    rules = _clean_rules()
    score, indicators, _ = ThreatHeuristics.analyze(telemetry, rules_bundle=rules)
    assert score >= 30


def test_analyze_scanner_user_agent():
    telemetry = _base_telemetry(user_agents_observed=["sqlmap/1.7.8"])
    rules = _clean_rules()
    score, indicators, _ = ThreatHeuristics.analyze(telemetry, rules_bundle=rules)
    assert score >= 30


def test_analyze_sensitive_env_uri():
    telemetry = _base_telemetry(unique_uris_requested=["/.env", "/.git/config"])
    rules = _clean_rules()
    score, indicators, _ = ThreatHeuristics.analyze(telemetry, rules_bundle=rules)
    assert score > 0


def test_analyze_score_capped_at_100():
    """Even a worst-case payload must not exceed 100."""
    telemetry = _base_telemetry(
        requests_per_second_avg=50.0,
        total_requests=5000,
        unique_uris_requested=["/../../../etc/passwd", "/api/users?id=1' OR 1=1--", "/.env"],
        user_agents_observed=["sqlmap/1.7.8", "Nikto/2.1.6"],
        response_codes_distribution={"404": 90, "200": 10},
        http_methods_distribution={"DELETE": 3, "TRACE": 2, "POST": 10},
    )
    rules = _clean_rules()
    score, _, _ = ThreatHeuristics.analyze(telemetry, rules_bundle=rules)
    assert score <= 100


def test_analyze_uses_default_rules_when_none():
    """analyze() should not raise when rules_bundle is None."""
    telemetry = _base_telemetry()
    score, indicators, reasoning = ThreatHeuristics.analyze(telemetry, rules_bundle=None)
    assert isinstance(score, int)
    assert 0 <= score <= 100

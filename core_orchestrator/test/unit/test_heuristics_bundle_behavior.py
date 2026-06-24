"""Extra unit tests for ThreatHeuristics behavior with injected rules bundles."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from mcp_servers.log_analysis_server.models.analysis_input import WebActivityWindowInput
from mcp_servers.log_analysis_server.models.rules_bundle import RulesBundle
from mcp_servers.log_analysis_server.services.heuristics_engine import ThreatHeuristics


def _base_window(uri: str) -> WebActivityWindowInput:
    now = datetime.now(timezone.utc)
    return WebActivityWindowInput(
        window_id=uuid4(),
        source_id="unit-test",
        source_ip="10.0.0.10",
        window_start_utc=now,
        window_end_utc=now + timedelta(seconds=30),
        total_requests=1,
        unique_uris_requested=[uri],
        http_methods_distribution={"GET": 1},
        response_codes_distribution={"404": 1},
        user_agents_observed=["Mozilla/5.0"],
        requests_per_second_avg=0.03,
    )


def test_injected_bundle_controls_sql_score():
    window = _base_window("/search?q=' OR 1=1--")
    bundle = RulesBundle(
        sql_injection_patterns=["' OR 1=1--"],
        path_traversal_patterns=[],
        sql_injection_score=55,
        path_traversal_score=0,
        version_hash="unit_sql",
    )

    score, indicators, _ = ThreatHeuristics.analyze(window, rules_bundle=bundle)

    assert score >= 55
    assert any("SQL injection" in indicator for indicator in indicators)


def test_injected_bundle_detects_encoded_path_traversal():
    window = _base_window("/download?path=..%2f..%2fetc/passwd")
    bundle = RulesBundle(
        sql_injection_patterns=[],
        path_traversal_patterns=["../", "..%2f"],
        sql_injection_score=0,
        path_traversal_score=60,
        version_hash="unit_traversal",
    )

    score, indicators, _ = ThreatHeuristics.analyze(window, rules_bundle=bundle)

    assert score >= 60
    assert any("Path traversal" in indicator for indicator in indicators)


"""
Compatibility tests for ThreatHeuristics with injected RulesBundle.

Ensures output is identical between default hardcoded rules and injected bundle.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from core_orchestrator.models.rule_schema import rules_to_bundle
from core_orchestrator.test.conftest import load_seed_rules
from mcp_servers.log_analysis_server.models.analysis_input import WebActivityWindowInput
from mcp_servers.log_analysis_server.models.rules_bundle import RulesBundle
from mcp_servers.log_analysis_server.services.heuristics_engine import ThreatHeuristics


def _attack_window() -> WebActivityWindowInput:
    now = datetime.now(timezone.utc)
    return WebActivityWindowInput(
        window_id=uuid4(),
        source_id="test-source",
        source_ip="10.0.0.66",
        window_start_utc=now,
        window_end_utc=now + timedelta(seconds=60),
        total_requests=9,
        unique_uris_requested=[
            "/etc/passwd",
            "/admin",
            "/.git/config",
            "/wp-login.php",
            "/.env",
        ],
        http_methods_distribution={"GET": 9},
        response_codes_distribution={"404": 8, "403": 1},
        user_agents_observed=["Nikto-Scanner/2.1"],
        requests_per_second_avg=0.15,
    )


def _benign_window() -> WebActivityWindowInput:
    now = datetime.now(timezone.utc)
    return WebActivityWindowInput(
        window_id=uuid4(),
        source_id="test-source",
        source_ip="192.168.1.100",
        window_start_utc=now,
        window_end_utc=now + timedelta(seconds=60),
        total_requests=3,
        unique_uris_requested=["/index.html", "/assets/style.css", "/favicon.ico"],
        http_methods_distribution={"GET": 3},
        response_codes_distribution={"200": 3},
        user_agents_observed=["Mozilla/5.0"],
        requests_per_second_avg=0.05,
    )


def _sql_injection_window() -> WebActivityWindowInput:
    now = datetime.now(timezone.utc)
    return WebActivityWindowInput(
        window_id=uuid4(),
        source_id="test-source",
        source_ip="10.0.0.99",
        window_start_utc=now,
        window_end_utc=now + timedelta(seconds=30),
        total_requests=2,
        unique_uris_requested=["/search?q=' OR 1=1--"],
        http_methods_distribution={"GET": 2},
        response_codes_distribution={"404": 2},
        user_agents_observed=["Mozilla/5.0"],
        requests_per_second_avg=0.1,
    )


def _seed_bundle() -> RulesBundle:
    core_bundle = rules_to_bundle(load_seed_rules(), version_hash="test_seed")
    return RulesBundle.from_cache_dict(core_bundle.to_cache_dict())


def test_heuristics_output_identical_with_default_rules():
    window = _attack_window()
    default = ThreatHeuristics.analyze(window)
    injected = ThreatHeuristics.analyze(window, rules_bundle=ThreatHeuristics._get_default_rules())
    assert default == injected


def test_heuristics_with_custom_rules_bundle(seed_rules):
    window = _attack_window()
    bundle = _seed_bundle()
    score, indicators, reasoning = ThreatHeuristics.analyze(window, rules_bundle=bundle)
    assert score >= 70
    assert len(indicators) > 0
    assert "Heuristic analysis" in reasoning


def test_heuristics_fallback_no_rules_bundle():
    window = _benign_window()
    score, indicators, _ = ThreatHeuristics.analyze(window)
    assert score < 20
    assert len(indicators) == 0


def test_ua_analysis_with_db_rules():
    window = _attack_window()
    bundle = _seed_bundle()
    score, indicators, _ = ThreatHeuristics.analyze(window, rules_bundle=bundle)
    assert any("nikto" in i.lower() or "Scanning" in i for i in indicators)
    assert score > 0


def test_uri_analysis_with_db_rules():
    window = _attack_window()
    bundle = _seed_bundle()
    _, indicators, _ = ThreatHeuristics.analyze(window, rules_bundle=bundle)
    assert any("sensitive path" in i.lower() for i in indicators)


def test_injection_pattern_detection_consistency():
    window = _sql_injection_window()
    default = ThreatHeuristics.analyze(window)
    injected = ThreatHeuristics.analyze(window, rules_bundle=_seed_bundle())
    assert default[0] == injected[0]
    assert any("SQL injection" in i for i in default[1])


def test_rules_injection_scoring_unchanged():
    window = _attack_window()
    s_default, ind_default, _ = ThreatHeuristics.analyze(window)
    s_injected, ind_injected, _ = ThreatHeuristics.analyze(
        window, rules_bundle=ThreatHeuristics._get_default_rules()
    )
    assert s_default == s_injected
    assert len(ind_default) == len(ind_injected)


def test_version_hash_tracking_in_bundle():
    bundle = _seed_bundle()
    assert bundle.version_hash == "test_seed"

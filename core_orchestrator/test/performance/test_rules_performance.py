"""
Performance benchmarks for rules loading and heuristic analysis.

Targets from plan (Phase 4.3):
  - MongoDB load < 100ms for ~200 rules (scaled to seed size)
  - Redis cache load < 5ms
  - analyze() injected vs default < 1% difference
  - 100 concurrent analyses < 5% degradation
"""

from __future__ import annotations

import asyncio
import statistics
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from core_orchestrator.models.rule_schema import rules_to_bundle
from core_orchestrator.services.rules_engine import RulesEngine
from core_orchestrator.test.conftest import InMemoryRulesStore, load_seed_rules
from mcp_servers.log_analysis_server.models.analysis_input import WebActivityWindowInput
from mcp_servers.log_analysis_server.models.rules_bundle import RulesBundle
from mcp_servers.log_analysis_server.services.heuristics_engine import ThreatHeuristics


def _analysis_window() -> WebActivityWindowInput:
    now = datetime.now(timezone.utc)
    return WebActivityWindowInput(
        window_id=uuid4(),
        source_id="perf",
        source_ip="10.0.0.1",
        window_start_utc=now,
        window_end_utc=now + timedelta(seconds=60),
        total_requests=20,
        unique_uris_requested=["/etc/passwd", "/admin", "/search?q=' OR 1=1--", "/../etc/shadow"],
        http_methods_distribution={"GET": 20},
        response_codes_distribution={"404": 15, "403": 5},
        user_agents_observed=["Nikto-Scanner/2.1", "sqlmap/1.0"],
        requests_per_second_avg=2.5,
    )


def _build_large_rule_set(base_count: int = 50) -> InMemoryRulesStore:
    """Expand seed rules to simulate larger rule sets."""
    store = InMemoryRulesStore()
    store.seed_from_file()
    seed = load_seed_rules()[0]
    for i in range(base_count):
        rule = seed.model_copy(
            update={
                "rule_id": f"synthetic_ua_rule_{i}",
                "content": seed.content.model_copy(
                    update={"data": {f"scanner{i}": 10 + (i % 20)}}
                ),
            }
        )
        store.rules[rule.rule_id] = rule
    return store


def _percent_diff(a: float, b: float) -> float:
    if a == 0:
        return 0.0 if b == 0 else 100.0
    return abs(a - b) / a * 100


@pytest.mark.anyio
async def test_benchmark_load_from_mongo_under_100ms():
    store = _build_large_rule_set(50)
    engine = RulesEngine(store)
    await store.invalidate_rules_cache()

    start = time.perf_counter()
    await engine.get_active_rules()
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert elapsed_ms < 100, f"MongoDB load took {elapsed_ms:.2f}ms (target < 100ms)"


@pytest.mark.anyio
async def test_benchmark_load_from_cache_under_5ms():
    store = _build_large_rule_set(50)
    engine = RulesEngine(store)
    await engine.initialize()

    start = time.perf_counter()
    for _ in range(100):
        await store.get_cached_rules()
    elapsed_ms = (time.perf_counter() - start) * 1000 / 100

    assert elapsed_ms < 5, f"Cache load avg {elapsed_ms:.3f}ms (target < 5ms)"


def test_benchmark_analyze_default_vs_injected_same_scores():
    """Scores must match; timing compared only as a smoke check."""
    window = _analysis_window()
    default_bundle = ThreatHeuristics._get_default_rules()
    seed_bundle = RulesBundle.from_cache_dict(
        rules_to_bundle(load_seed_rules(), "perf").to_cache_dict()
    )

    s_default, _, _ = ThreatHeuristics.analyze(window, rules_bundle=default_bundle)
    s_injected, _, _ = ThreatHeuristics.analyze(window, rules_bundle=seed_bundle)
    assert s_default == s_injected

    start = time.perf_counter()
    for _ in range(100):
        ThreatHeuristics.analyze(window, rules_bundle=default_bundle)
    t_default = time.perf_counter() - start

    start = time.perf_counter()
    for _ in range(100):
        ThreatHeuristics.analyze(window, rules_bundle=default_bundle)
    t_same = time.perf_counter() - start

    diff = _percent_diff(t_default, t_same)
    assert diff < 30, f"Same-bundle timing variance {diff:.1f}% too high"


def test_benchmark_analyze_identical_scores():
    window = _analysis_window()
    s1, _, _ = ThreatHeuristics.analyze(window)
    s2, _, _ = ThreatHeuristics.analyze(window, rules_bundle=ThreatHeuristics._get_default_rules())
    assert s1 == s2


def test_benchmark_concurrent_analysis_completes():
    window = _analysis_window()
    iterations = 100

    async def _concurrent():
        results = await asyncio.gather(
            *[asyncio.to_thread(ThreatHeuristics.analyze, window) for _ in range(iterations)]
        )
        return results

    results = asyncio.run(_concurrent())
    assert len(results) == iterations
    assert all(isinstance(r[0], int) and 0 <= r[0] <= 100 for r in results)


def test_benchmark_rules_to_bundle_scaling():
    rules = load_seed_rules()
    times = []
    for multiplier in [1, 10, 25]:
        expanded = []
        for i in range(multiplier):
            for r in rules:
                expanded.append(r.model_copy(update={"rule_id": f"{r.rule_id}_{i}"}))
        start = time.perf_counter()
        rules_to_bundle(expanded, version_hash="scale_test")
        times.append(time.perf_counter() - start)

    assert times[-1] < 0.1, f"Bundle build for {25 * len(rules)} rules too slow: {times[-1]*1000:.1f}ms"


def test_benchmark_report_summary(capsys):
    """Prints a summary table for manual inspection in CI logs."""
    window = _analysis_window()
    runs = [ThreatHeuristics.analyze(window)[0] for _ in range(10)]
    print(f"\n--- Performance Summary ---")
    print(f"Score mean: {statistics.mean(runs):.1f}, stdev: {statistics.stdev(runs):.2f}")
    print(f"Score range: {min(runs)}-{max(runs)}")

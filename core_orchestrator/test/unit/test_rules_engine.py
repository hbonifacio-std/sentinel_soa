"""Unit tests for RulesEngine."""

from __future__ import annotations

import asyncio

import pytest

from core_orchestrator.models.rule_schema import RuleVersion, build_default_rules_bundle, hash_version, rules_to_bundle
from core_orchestrator.services.rules_engine import RulesEngine
from core_orchestrator.test.conftest import InMemoryRulesStore, load_seed_rules


@pytest.fixture
def engine(in_memory_db) -> RulesEngine:
    return RulesEngine(in_memory_db)


@pytest.mark.anyio
async def test_initialize_loads_rules_from_mongo(engine, in_memory_db):
    ok = await engine.initialize()
    assert ok is True
    bundle = await engine.get_active_rules()
    assert len(bundle.malicious_ua_keywords) == 29
    assert len(bundle.sensitive_uris) == 44


@pytest.mark.anyio
async def test_get_active_rules_uses_cache(engine, in_memory_db):
    await engine.initialize()
    in_memory_db.rules.clear()
    bundle = await engine.get_active_rules()
    assert len(bundle.malicious_ua_keywords) == 29


@pytest.mark.anyio
async def test_get_active_rules_ignores_invalid_cached_bundle(engine, in_memory_db):
    await in_memory_db.cache_rules(
        rules_to_bundle([], version_hash="bad_cache")
    )
    bundle = await engine.get_active_rules()
    assert bundle.version_hash != "bad_cache"
    assert len(bundle.malicious_ua_keywords) == 29


@pytest.mark.anyio
async def test_reload_rules_refreshes_from_mongo(engine, in_memory_db):
    await engine.initialize()
    await in_memory_db.invalidate_rules_cache()
    ua_rule = in_memory_db.rules["malicious_ua_keywords_v1"]
    updated = ua_rule.model_copy(
        update={
            "content": ua_rule.content.model_copy(
                update={"data": {**ua_rule.content.data, "newscanner": 25}}
            )
        }
    )
    in_memory_db.rules[ua_rule.rule_id] = updated

    await engine.reload_rules()
    bundle = await engine.get_active_rules()
    assert "newscanner" in bundle.malicious_ua_keywords


@pytest.mark.anyio
async def test_fallback_when_mongo_unavailable():
    store = InMemoryRulesStore()
    store._fail_mongo = True
    engine = RulesEngine(store)
    await engine.initialize()
    bundle = await engine.get_active_rules()
    assert bundle.version_hash == build_default_rules_bundle().version_hash
    assert "nikto" in bundle.malicious_ua_keywords
    health = await engine.health_check()
    assert health.source == "fallback"


@pytest.mark.anyio
async def test_deploy_version_activates_and_caches(engine, in_memory_db):
    await engine.initialize()
    version_hash = "v1_initial_migrated_rules"
    bundle = await engine.deploy_version(version_hash)
    assert bundle.version_hash == version_hash
    cached = await in_memory_db.get_cached_rules()
    assert cached is not None
    assert cached.version_hash == version_hash
    active = await in_memory_db.get_active_version()
    assert active is not None
    assert active.is_active is True


@pytest.mark.anyio
async def test_deploy_version_raises_for_missing_rules(engine, in_memory_db):
    in_memory_db.versions["bad_version"] = RuleVersion(
        version_hash="bad_version",
        created_at=load_seed_rules()[0].created_at,
        rules_included=["nonexistent_rule"],
    )
    with pytest.raises(ValueError, match="not found"):
        await engine.deploy_version("bad_version")


@pytest.mark.anyio
async def test_deploy_version_raises_on_validator_failure(engine, in_memory_db, monkeypatch):
    class _Result:
        valid = False
        errors = ["forced validation failure"]

    monkeypatch.setattr(
        "core_orchestrator.services.rule_validator.RuleValidator.validate_rules",
        lambda _rules: _Result(),
    )

    with pytest.raises(ValueError, match="forced validation failure"):
        await engine.deploy_version("v1_initial_migrated_rules")


@pytest.mark.anyio
async def test_health_check_reports_cache_source(engine):
    await engine.initialize()
    health = await engine.health_check()
    assert health.status == "healthy"
    assert health.cached is True
    assert health.source == "cache"


@pytest.mark.anyio
async def test_get_rules_stats(engine):
    await engine.initialize()
    stats = await engine.get_rules_stats()
    assert stats.total_active_rules == 4
    assert stats.cached is True


@pytest.mark.anyio
async def test_concurrent_get_active_rules(engine):
    await engine.initialize()

    async def _fetch():
        return await engine.get_active_rules()

    results = await asyncio.gather(*[_fetch() for _ in range(20)])
    hashes = {r.version_hash for r in results}
    assert len(hashes) == 1


@pytest.mark.anyio
async def test_rules_to_bundle_maps_all_categories(seed_rules):
    bundle = rules_to_bundle(seed_rules, version_hash=hash_version(seed_rules))
    assert bundle.malicious_ua_keywords
    assert bundle.sensitive_uris
    assert bundle.sql_injection_patterns
    assert bundle.path_traversal_patterns

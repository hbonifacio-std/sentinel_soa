"""
End-to-end integration tests for the rules management API.

Uses in-memory database mocks — no Docker required.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from core_orchestrator.models.rule_schema import build_default_rules_bundle, hash_version
from core_orchestrator.services.rules_engine import get_rules_engine
from core_orchestrator.test.conftest import load_seed_rules


@pytest.fixture
async def rules_client(patch_rules_db):
    from core_orchestrator.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


def _new_rule_payload(rule_id: str = "custom_ua_rule_v1") -> dict:
    template = load_seed_rules()[0].model_dump(mode="json")
    template["rule_id"] = rule_id
    template["content"]["data"] = {"customscanner": 22}
    template["metadata"]["change_reason"] = "E2E test rule"
    return template


@pytest.mark.anyio
async def test_e2e_list_rules(rules_client):
    resp = await rules_client.get("/api/v1/rules")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 4
    assert len(body["rules"]) == 4


@pytest.mark.anyio
async def test_e2e_create_validate_activate_flow(rules_client, patch_rules_db):
    """E2E 1: Create rule → Validate → Activate → Verify cache."""
    payload = _new_rule_payload()
    create = await rules_client.post("/api/v1/rules", json=payload)
    assert create.status_code == 201

    all_rules = list(patch_rules_db.rules.values())
    validate = await rules_client.post(
        "/api/v1/rules/validate",
        json={"rules": [r.model_dump(mode="json") for r in all_rules]},
    )
    assert validate.status_code == 200
    assert validate.json()["valid"] is True

    version = await rules_client.post(
        "/api/v1/rules/versions",
        json={
            "rules_included": [r.rule_id for r in all_rules],
            "changelog": "E2E version with custom rule",
            "deployed_by": "test@e2e",
        },
    )
    assert version.status_code == 201
    version_hash = version.json()["version_hash"]

    activate = await rules_client.post(f"/api/v1/rules/versions/activate/{version_hash}")
    assert activate.status_code == 200
    assert activate.json()["active_version"] == version_hash

    cached = await patch_rules_db.get_cached_rules()
    assert cached is not None
    assert "customscanner" in cached.malicious_ua_keywords


@pytest.mark.anyio
async def test_e2e_update_rule_and_new_version(rules_client, patch_rules_db):
    """E2E 2: Update rule → Validate → Activate new version."""
    rule_id = "malicious_ua_keywords_v1"
    update = await rules_client.patch(
        f"/api/v1/rules/{rule_id}",
        json={
            "description": "Updated UA keywords",
            "content": {
                "type": "keyword_mapping",
                "data": {**load_seed_rules()[0].content.data, "updatedtool": 18},
                "match_strategy": "substring_case_insensitive",
            },
        },
    )
    assert update.status_code == 200

    rules = await patch_rules_db.list_active_rules()
    validate = await rules_client.post(
        "/api/v1/rules/validate",
        json={"rules": [r.model_dump(mode="json") for r in rules]},
    )
    assert validate.json()["valid"] is True

    vhash = hash_version(rules)
    version = await rules_client.post(
        "/api/v1/rules/versions",
        json={"rules_included": [r.rule_id for r in rules], "deployed_by": "test@e2e"},
    )
    assert version.status_code == 201
    await rules_client.post(f"/api/v1/rules/versions/activate/{version.json()['version_hash']}")
    cached = await patch_rules_db.get_cached_rules()
    assert "updatedtool" in cached.malicious_ua_keywords


@pytest.mark.anyio
async def test_e2e_rollback_to_previous_version(rules_client, patch_rules_db):
    """E2E 3: Rollback by activating a previous version."""
    original_hash = "v1_initial_migrated_rules"
    rules = await patch_rules_db.list_active_rules()
    new_version = await rules_client.post(
        "/api/v1/rules/versions",
        json={"rules_included": [r.rule_id for r in rules], "changelog": "temp version"},
    )
    new_hash = new_version.json()["version_hash"]
    await rules_client.post(f"/api/v1/rules/versions/activate/{new_hash}")

    rollback = await rules_client.post(f"/api/v1/rules/versions/activate/{original_hash}")
    assert rollback.status_code == 200
    assert rollback.json()["active_version"] == original_hash


@pytest.mark.anyio
async def test_e2e_cache_invalidation_after_version_change(rules_client, patch_rules_db):
    """E2E 4: Cache invalidation after version change."""
    engine = get_rules_engine()
    await engine.initialize()
    old_cache = await patch_rules_db.get_cached_rules()
    assert old_cache is not None

    rules = await patch_rules_db.list_active_rules()
    version = await rules_client.post(
        "/api/v1/rules/versions",
        json={"rules_included": [r.rule_id for r in rules]},
    )
    await rules_client.post(f"/api/v1/rules/versions/activate/{version.json()['version_hash']}")

    new_cache = await patch_rules_db.get_cached_rules()
    assert new_cache is not None
    assert new_cache.version_hash == version.json()["version_hash"]


@pytest.mark.anyio
async def test_e2e_audit_log_tracking(rules_client, patch_rules_db):
    """E2E 5: Audit log records CREATE, UPDATE, ACTIVATE."""
    await rules_client.post("/api/v1/rules", json=_new_rule_payload("audit_test_rule"))
    await rules_client.patch(
        "/api/v1/rules/audit_test_rule",
        json={"description": "patched"},
    )
    rules = await patch_rules_db.list_active_rules()
    version = await rules_client.post(
        "/api/v1/rules/versions",
        json={"rules_included": [r.rule_id for r in rules]},
    )
    await rules_client.post(f"/api/v1/rules/versions/activate/{version.json()['version_hash']}")

    resp = await rules_client.get("/api/v1/rules/audit-log")
    assert resp.status_code == 200
    actions = {e["action"] for e in resp.json()["entries"]}
    assert "CREATE" in actions
    assert "UPDATE" in actions
    assert "ACTIVATE" in actions


@pytest.mark.anyio
async def test_e2e_concurrent_rule_reads(rules_client):
    """E2E 6: Concurrent reads remain consistent."""
    import asyncio

    async def _get():
        return await rules_client.get("/api/v1/rules")

    responses = await asyncio.gather(*[_get() for _ in range(10)])
    totals = {r.json()["total"] for r in responses}
    assert len(totals) == 1


@pytest.mark.anyio
async def test_e2e_database_failure_fallback(patch_rules_db):
    """E2E 7: MongoDB failure → fallback to hardcoded rules."""
    from core_orchestrator.services import rules_engine as rules_engine_mod
    from core_orchestrator.services.rules_engine import RulesEngine

    await patch_rules_db.invalidate_rules_cache()
    patch_rules_db._fail_mongo = True
    rules_engine_mod._rules_engine = None
    engine = RulesEngine(patch_rules_db)
    await engine.initialize()
    bundle = await engine.get_active_rules()
    assert bundle.version_hash == build_default_rules_bundle().version_hash
    assert "nikto" in bundle.malicious_ua_keywords
    health = await engine.health_check()
    assert health.source == "fallback"


@pytest.mark.anyio
async def test_e2e_redis_cache_miss_reloads_from_mongo(rules_client, patch_rules_db):
    """E2E 8: Cache miss → reload from MongoDB."""
    engine = get_rules_engine()
    await patch_rules_db.invalidate_rules_cache()
    bundle = await engine.get_active_rules()
    assert len(bundle.malicious_ua_keywords) == 29
    cached = await patch_rules_db.get_cached_rules()
    assert cached is not None


@pytest.mark.anyio
async def test_e2e_get_rule_by_id(rules_client):
    resp = await rules_client.get("/api/v1/rules/malicious_ua_keywords_v1")
    assert resp.status_code == 200
    assert resp.json()["rule_id"] == "malicious_ua_keywords_v1"


@pytest.mark.anyio
async def test_e2e_delete_rule_soft(rules_client, patch_rules_db):
    resp = await rules_client.delete("/api/v1/rules/malicious_ua_keywords_v1")
    assert resp.status_code == 200
    rule = await patch_rules_db.get_rule("malicious_ua_keywords_v1")
    assert rule is not None
    assert rule.is_active is False


@pytest.mark.anyio
async def test_e2e_rules_health(rules_client):
    resp = await rules_client.get("/api/v1/rules/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] in ("healthy", "initializing")
    assert body["total_active_rules"] >= 4


@pytest.mark.anyio
async def test_e2e_create_duplicate_rule_returns_409(rules_client):
    payload = load_seed_rules()[0].model_dump(mode="json")
    resp = await rules_client.post("/api/v1/rules", json=payload)
    assert resp.status_code == 409

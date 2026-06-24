"""
Shared fixtures for rules engine and API tests.
"""

from __future__ import annotations

import json
import os
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

os.environ.setdefault("LLM_PROVIDER", "ollama")

from core_orchestrator.models.rule_schema import (  # noqa: E402
    HeuristicRule,
    RuleVersion,
    RulesBundle,
    rules_to_bundle,
)

ROOT = Path(__file__).resolve().parents[2]
SEED_PATH = ROOT / "data" / "mongodb" / "heuristic_rules.json"


def load_seed_rules() -> List[HeuristicRule]:
    seed = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    return [HeuristicRule(**doc) for doc in seed["heuristic_rules"]]


def load_seed_versions() -> List[RuleVersion]:
    seed = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    return [RuleVersion(**doc) for doc in seed.get("rule_versions", [])]


class InMemoryRulesStore:
    """In-memory stand-in for Database rules/cache operations."""

    def __init__(self) -> None:
        self.rules: Dict[str, HeuristicRule] = {}
        self.versions: Dict[str, RuleVersion] = {}
        self.audit_logs: List[Dict[str, Any]] = []
        self._cache: Optional[RulesBundle] = None
        self.mongo_client = self
        self.redis_client = object()
        self.redis_rules_client = object()
        self._app_mongo_db_name = "test_sentinel"
        self._rules_mongo_db_name = "heuristy"
        self._fail_mongo = False

    async def connect_to_mongo(self) -> None:
        pass

    async def connect_to_redis(self) -> None:
        pass

    async def close_mongo_connection(self) -> None:
        pass

    async def close_redis_connection(self) -> None:
        pass

    def _get_db(self):
        if self._fail_mongo:
            raise RuntimeError("MongoDB unavailable")
        return self

    def get_app_db_name(self) -> str:
        return self._app_mongo_db_name

    def get_rules_db_name(self) -> str:
        return self._rules_mongo_db_name

    def get_app_db(self):
        return self._get_db()

    def get_rules_db(self):
        return self._get_db()

    def __getitem__(self, name: str):
        return self

    async def insert_one(self, doc: Dict[str, Any]) -> Any:
        return type("Result", (), {"inserted_id": "mock-id"})()

    async def count_documents(self, _query: Dict[str, Any]) -> int:
        return len(self.rules)

    async def delete_many(self, _query: Dict[str, Any]) -> Any:
        self.rules.clear()
        self.versions.clear()
        self.audit_logs.clear()
        return type("Result", (), {"deleted_count": 0})()

    def _ensure_mongo(self) -> None:
        if self._fail_mongo:
            raise RuntimeError("MongoDB unavailable")

    async def create_rule(self, rule: HeuristicRule) -> str:
        self._ensure_mongo()
        self.rules[rule.rule_id] = rule
        return rule.rule_id

    async def get_rule(self, rule_id: str) -> Optional[HeuristicRule]:
        self._ensure_mongo()
        return self.rules.get(rule_id)

    async def list_active_rules(self) -> List[HeuristicRule]:
        self._ensure_mongo()
        return [r for r in self.rules.values() if r.is_active]

    async def list_all_rules(self, include_inactive: bool = False) -> List[HeuristicRule]:
        self._ensure_mongo()
        if include_inactive:
            return list(self.rules.values())
        return await self.list_active_rules()

    async def get_rules_by_ids(self, rule_ids: List[str]) -> List[HeuristicRule]:
        self._ensure_mongo()
        return [self.rules[rid] for rid in rule_ids if rid in self.rules]

    async def rule_exists(self, rule_id: str) -> bool:
        self._ensure_mongo()
        return rule_id in self.rules

    async def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        self._ensure_mongo()
        if rule_id not in self.rules:
            return False
        merged = self.rules[rule_id].model_dump()
        merged.update(updates)
        merged["updated_at"] = datetime.now(timezone.utc)
        self.rules[rule_id] = HeuristicRule.model_validate(merged)
        return True

    async def delete_rule(self, rule_id: str) -> bool:
        self._ensure_mongo()
        if rule_id not in self.rules:
            return False
        rule = self.rules[rule_id]
        self.rules[rule_id] = rule.model_copy(update={"is_active": False})
        return True

    async def create_version(self, version: RuleVersion) -> str:
        self.versions[version.version_hash] = version
        return version.version_hash

    async def get_version(self, version_hash: str) -> Optional[RuleVersion]:
        return self.versions.get(version_hash)

    async def activate_version(self, version_hash: str) -> bool:
        if version_hash not in self.versions:
            return False
        updated: Dict[str, RuleVersion] = {}
        for key, version in self.versions.items():
            if key == version_hash:
                updated[key] = version.model_copy(
                    update={
                        "is_active": True,
                        "deployment_timestamp": datetime.now(timezone.utc),
                    }
                )
            else:
                updated[key] = version.model_copy(update={"is_active": False})
        self.versions = updated
        return True

    async def get_active_version(self) -> Optional[RuleVersion]:
        for v in self.versions.values():
            if v.is_active:
                return v
        return None

    async def list_versions(self, limit: int = 50) -> List[RuleVersion]:
        return list(self.versions.values())[:limit]

    async def log_rule_action(
        self,
        action: str,
        rule_id: str,
        user: str,
        changes: Dict[str, Any],
        reason: str = "",
        status: str = "success",
        ip_address: str = "127.0.0.1",
    ) -> str:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "rule_id": rule_id,
            "user": user,
            "changes": changes,
            "reason": reason,
            "status": status,
            "ip_address": ip_address,
        }
        self.audit_logs.append(entry)
        return str(len(self.audit_logs))

    async def get_audit_logs(self, rule_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        logs = self.audit_logs
        if rule_id:
            logs = [l for l in logs if l["rule_id"] == rule_id]
        return list(reversed(logs[-limit:]))

    async def cache_rules(self, bundle: RulesBundle, ttl_seconds: int = 86400) -> bool:
        self._cache = deepcopy(bundle)
        return True

    async def get_cached_rules(self) -> Optional[RulesBundle]:
        return self._cache

    async def invalidate_rules_cache(self) -> bool:
        self._cache = None
        return True

    def seed_from_file(self) -> None:
        for rule in load_seed_rules():
            self.rules[rule.rule_id] = rule
        for version in load_seed_versions():
            self.versions[version.version_hash] = version
        active_rules = [r for r in self.rules.values() if r.is_active]
        version = load_seed_versions()[0]
        self._cache = rules_to_bundle(active_rules, version_hash=version.version_hash)


@pytest.fixture
def seed_rules() -> List[HeuristicRule]:
    return load_seed_rules()


@pytest.fixture
def in_memory_db() -> InMemoryRulesStore:
    store = InMemoryRulesStore()
    store.seed_from_file()
    return store


@pytest.fixture
def patch_rules_db(monkeypatch, in_memory_db):
    """Patch db singleton across rules modules and disable rate limits."""

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr("core_orchestrator.services.database.db", in_memory_db)
    monkeypatch.setattr("core_orchestrator.services.rules_engine.db", in_memory_db)
    monkeypatch.setattr("core_orchestrator.api.v1.endpoints.rules_management.db", in_memory_db)

    import core_orchestrator.services.rules_engine as rules_engine_mod

    rules_engine_mod._rules_engine = None

    from core_orchestrator.agent import runner as agent_runner
    from core_orchestrator.services.limiter import limiter

    monkeypatch.setattr(agent_runner.agent_runner, "initialize_subsytem", _noop)
    monkeypatch.setattr(agent_runner.agent_runner, "shutdown_subsytem", _noop)
    limiter.enabled = False

    return in_memory_db

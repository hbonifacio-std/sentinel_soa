"""
Central rules engine: loads heuristic rules from MongoDB, caches in Redis DB3,
and exposes an in-memory RulesBundle for ThreatHeuristics analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from core_orchestrator.models.rule_schema import (
    HeuristicRule,
    RuleAuditLog,
    RuleVersion,
    RulesBundle,
    build_default_rules_bundle,
    hash_version,
    rules_to_bundle,
)
from core_orchestrator.services.database import Database, db
from shared.rules_seed import load_rules_seed_payload

logger = logging.getLogger(__name__)


@dataclass
class RulesStatistics:
    total_active_rules: int
    version_hash: str
    cached: bool
    last_updated: Optional[datetime]


@dataclass
class HealthStatus:
    status: str
    cached: bool
    version_hash: str
    last_updated: Optional[datetime]
    source: str


class RulesEngine:
    def __init__(self, database: Database, logger_instance: Optional[logging.Logger] = None):
        self._db = database
        self._logger = logger_instance or logger
        self._initialized = False
        self._memory_bundle: Optional[RulesBundle] = None
        self._last_source: str = "fallback"

    async def initialize(self) -> bool:
        """Load active rules at startup; fall back to defaults if DB is empty."""
        try:
            bundle = await self.get_active_rules()
            self._memory_bundle = bundle
            self._initialized = True
            self._logger.info(
                "RulesEngine initialized (version=%s, ua_keywords=%d, uris=%d)",
                bundle.version_hash,
                len(bundle.malicious_ua_keywords),
                len(bundle.sensitive_uris),
            )
            return True
        except Exception as exc:
            self._logger.error("RulesEngine initialization failed: %s", exc)
            self._memory_bundle = self._get_default_rules()
            self._last_source = "fallback"
            self._initialized = True
            return False

    async def get_active_rules(self) -> RulesBundle:
        """Return active rules from cache, MongoDB, or hardcoded fallback."""
        cached = await self._db.get_cached_rules()
        if cached and cached.malicious_ua_keywords:
            self._memory_bundle = cached
            self._last_source = "cache"
            return cached

        try:
            rules = await self._db.list_active_rules()
            if not rules:
                seeded_bundle = await self._seed_rules_store_if_empty()
                if seeded_bundle is not None:
                    self._memory_bundle = seeded_bundle
                    self._last_source = "mongodb"
                    return seeded_bundle
            if rules:
                active_version = await self._db.get_active_version()
                version_hash = active_version.version_hash if active_version else hash_version(rules)
                bundle = rules_to_bundle(rules, version_hash=version_hash)
                await self._db.cache_rules(bundle)
                self._memory_bundle = bundle
                self._last_source = "mongodb"
                return bundle
        except Exception as exc:
            self._logger.warning("Failed to load rules from MongoDB: %s", exc)

        fallback = self._get_default_rules()
        self._memory_bundle = fallback
        self._last_source = "fallback"
        return fallback

    async def reload_rules(self) -> bool:
        """Force reload from MongoDB and refresh cache."""
        await self._db.invalidate_rules_cache()
        bundle = await self.get_active_rules()
        self._memory_bundle = bundle
        return bundle.version_hash != "default"

    async def deploy_version(self, version_hash: str) -> RulesBundle:
        """Activate a version, rebuild cache, and return the deployed bundle."""
        version = await self._db.get_version(version_hash)
        if not version:
            raise ValueError(f"Version not found: {version_hash}")

        rules = await self._db.get_rules_by_ids(version.rules_included)
        found_ids = {r.rule_id for r in rules}
        missing = [rid for rid in version.rules_included if rid not in found_ids]
        if missing:
            raise ValueError(f"Rules not found for version: {', '.join(missing)}")

        from core_orchestrator.services.rule_validator import RuleValidator

        validation = RuleValidator.validate_rules(rules)
        if not validation.valid:
            raise ValueError("; ".join(validation.errors))

        await self._db.activate_version(version_hash)
        await self._db.invalidate_rules_cache()
        bundle = rules_to_bundle(rules, version_hash=version_hash)
        await self._db.cache_rules(bundle)
        self._memory_bundle = bundle
        self._last_source = "mongodb"
        return bundle

    async def get_rule_by_id(self, rule_id: str) -> Optional[HeuristicRule]:
        return await self._db.get_rule(rule_id)

    async def get_rules_stats(self) -> RulesStatistics:
        bundle = self._memory_bundle or await self.get_active_rules()
        cached = await self._db.get_cached_rules() is not None
        rules = await self._db.list_active_rules()
        return RulesStatistics(
            total_active_rules=len(rules),
            version_hash=bundle.version_hash,
            cached=cached,
            last_updated=bundle.last_updated,
        )

    async def health_check(self) -> HealthStatus:
        bundle = self._memory_bundle or await self.get_active_rules()
        cached = await self._db.get_cached_rules() is not None
        return HealthStatus(
            status="healthy" if self._initialized else "initializing",
            cached=cached,
            version_hash=bundle.version_hash,
            last_updated=bundle.last_updated,
            source=self._last_source if not cached else "cache",
        )

    @staticmethod
    def _get_default_rules() -> RulesBundle:
        return build_default_rules_bundle()

    async def _seed_rules_store_if_empty(self) -> Optional[RulesBundle]:
        """Bootstrap the dedicated rules DB (`heuristy`) from the canonical seed file."""
        payload = load_rules_seed_payload()
        rules = [HeuristicRule(**doc) for doc in payload.get("heuristic_rules", [])]
        if not rules:
            return None

        versions = [RuleVersion(**doc) for doc in payload.get("rule_versions", [])]
        audits = [RuleAuditLog(**doc) for doc in payload.get("rule_audit_log", [])]

        for rule in rules:
            await self._db.create_rule(rule)

        for version in versions:
            await self._db.create_version(version)

        for audit in audits:
            await self._db.log_rule_action(
                action=audit.action,
                rule_id=audit.rule_id,
                user=audit.user,
                changes=audit.changes,
                reason=audit.reason,
                status=audit.status,
                ip_address=audit.ip_address,
            )

        active_version = next((version for version in versions if version.is_active), None)
        version_hash = active_version.version_hash if active_version else hash_version(rules)
        bundle = rules_to_bundle(rules, version_hash=version_hash)
        await self._db.cache_rules(bundle)
        self._last_source = "mongodb"
        self._logger.info(
            "Seeded rules store '%s' with %d active rules from %s",
            self._db.get_rules_db_name(),
            len([rule for rule in rules if rule.is_active]),
            "data/mongodb/heuristic_rules.json",
        )
        return bundle


_rules_engine: Optional[RulesEngine] = None


def get_rules_engine() -> RulesEngine:
    global _rules_engine
    if _rules_engine is None:
        _rules_engine = RulesEngine(db)
    return _rules_engine

"""
Central rules engine: loads heuristic rules from MongoDB, caches in Redis DB3,
and exposes an in-memory RulesBundle for ThreatHeuristics analysis.
"""

from dataclasses import dataclass
from datetime import datetime
import logging
from typing import Optional

from core_orchestrator.domain.models.rule_engine.rules import RulesBundle, rules_to_bundle, hash_version, HeuristicRule, build_default_rules_bundle, RuleVersion, RuleAuditLog
from core_orchestrator.application.modules.analysis_reports.services.rule_service import RuleService
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


class RulesEngineService:
    def __init__(self, rules_service: RuleService):
        self._service = rules_service
        self._logger = logger
        self._initialized = False
        self._memory_bundle: Optional[RulesBundle] = None
        self._last_source: str = "fallback"

    async def initialize(self) -> bool:
        """Load active rules at startup; fall back to defaults if DB is empty."""
        try:
            # Initialize global bundle by default (client_id=None).
            bundle = await self.get_active_rules(client_id=None)
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

    async def get_active_rules(self, client_id: Optional[str] = None) -> RulesBundle:
        """Return active rules from cache, MongoDB, or hardcoded fallback.
        
        If client_id is None, loads only global rules.
        For multi-tenancy, pass client_id to get client overrides with global fallback.
        """
        # Try cache first (key includes client_id for isolation)
        cache_key_suffix = client_id or "global"
        cached = await self._service.get_cached_rules_for_tenant(cache_key_suffix)
        if cached and cached.malicious_ua_keywords:
            self._memory_bundle = cached
            self._last_source = "cache"
            return cached

        try:
            # Load client + global rules merged with client precedence.
            rules = await self._service.get_active_rules_by_client(client_id)
            if not rules:
                seeded_bundle = await self._seed_rules_store_if_empty()
                if seeded_bundle is not None:
                    self._memory_bundle = seeded_bundle
                    self._last_source = "mongodb"
                    return seeded_bundle
            if rules:
                active_version = await self._service.get_active_version(client_id)
                version_hash = active_version.version_hash if active_version else hash_version(rules)
                bundle = rules_to_bundle(rules, version_hash=version_hash)

                await self._service.cache_rules_for_tenant(bundle, cache_key_suffix=cache_key_suffix)
                self._memory_bundle = bundle
                self._last_source = "mongodb"
                return bundle
        except Exception as exc:
            self._logger.warning("Failed to load rules from MongoDB: %s", exc)

        fallback = self._get_default_rules()
        self._memory_bundle = fallback
        self._last_source = "fallback"
        return fallback

    async def reload_rules(self, client_id: Optional[str] = None) -> bool:
        """Force reload from MongoDB and refresh cache."""
        await self._service.invalidate_rules_cache()
        bundle = await self.get_active_rules(client_id=client_id)
        self._memory_bundle = bundle
        return bundle.version_hash != "default"

    async def deploy_version(self, version_hash: str, client_id: Optional[str]) -> RulesBundle:
        """Activate a version, rebuild cache, and return the deployed bundle."""
        bundle = await self._service.deploy_version(version_hash, client_id)
        self._memory_bundle = bundle
        self._last_source = "mongodb"
        return bundle

    async def get_rule_by_id(self, rule_id: str, client_id: Optional[str] = None) -> Optional[HeuristicRule]:
        return await self._service.fetch_rule_by_id(rule_id, client_id)

    async def get_rules_stats(self) -> RulesStatistics:
        bundle = self._memory_bundle or await self.get_active_rules()
        cached = await self._service.get_cached_rules() is not None
        rules = await self._service.list_all_active_rules_internal()
        return RulesStatistics(
            total_active_rules=len(rules),
            version_hash=bundle.version_hash,
            cached=cached,
            last_updated=bundle.last_updated,
        )

    async def health_check(self) -> HealthStatus:
        bundle = self._memory_bundle or await self.get_active_rules()
        cached = await self._service.get_cached_rules() is not None
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
            await self._service.create_rule(rule)

        for version in versions:
            await self._service.create_version(version)

        for audit in audits:
            await self._service.log_rule_action(
                action=audit.action,
                rule_id=audit.rule_id,
                user=audit.user,
                changes=audit.changes,
                reason=audit.reason,
                ip_address=audit.ip_address,
                client_id=audit.client_id,
            )

        active_version = next((version for version in versions if version.is_active), None)
        version_hash = active_version.version_hash if active_version else hash_version(rules)
        bundle = rules_to_bundle(rules, version_hash=version_hash)
        await self._service.cache_rules(bundle)
        self._last_source = "mongodb"

        self._logger.info(
            "Seeded rules store with active rules from seed payload"
        )
        return bundle

import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from core_orchestrator.domain.models.rule_engine.rules import (
    HeuristicRule,
    RulesBundle,
    RuleVersion,
    hash_version,
    rules_to_bundle,
)
from core_orchestrator.domain.ports.rules.audit_repository import AuditRepository
from core_orchestrator.domain.ports.rules.rule_repository import RuleRepository
from core_orchestrator.domain.ports.rules.rules_bundle_cache import RulesBundleCachePort
from core_orchestrator.domain.ports.rules.rule_validator_port import RuleValidatorPort

logger = logging.getLogger(__name__)


class RuleService:
    def __init__(
        self,
        rule_repository: RuleRepository,
        audit_repository: AuditRepository,
        rules_bundle_cache: RulesBundleCachePort,
        rule_validator: RuleValidatorPort,
    ):
        # All collaborators arrive by dependency inversion (ports), never instantiated here.
        self.repo = rule_repository
        self.audit_repo = audit_repository
        self.cache = rules_bundle_cache
        self.validator = rule_validator

    # ------------------------------------------------------------------ #
    # Rule CRUD
    # ------------------------------------------------------------------ #
    async def create_rule(self, rule: HeuristicRule) -> HeuristicRule:
        new_rule = await self.repo.create_rule(rule)
        await self.cache.invalidate_bundle()
        return new_rule

    async def fetch_rule_by_id(self, rule_id: str) -> Optional[HeuristicRule]:
        return await self.repo.get_by_id(rule_id)

    async def fetch_all_rules(self, include_inactive: bool = False) -> List[HeuristicRule]:
        return await self.repo.get_all(include_inactive=include_inactive)

    async def rule_exists(self, rule_id: str) -> bool:
        return await self.repo.rule_exists(rule_id)

    async def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        success = await self.repo.update_rule(rule_id, updates)
        if success:
            await self.cache.invalidate_bundle()
        return success

    async def delete_rule(self, rule_id: str) -> bool:
        success = await self.repo.delete_rule(rule_id)
        if success:
            await self.cache.invalidate_bundle()
        return success

    # ------------------------------------------------------------------ #
    # Audit log
    # ------------------------------------------------------------------ #
    async def get_audit_logs(
        self, rule_id: Optional[str] = None, limit: int = 50, offset: int = 0
    ) -> List[Dict[str, Any]]:
        return await self.audit_repo.get_logs(rule_id=rule_id, limit=limit, offset=offset)

    async def log_rule_action(
        self,
        action: str,
        rule_id: str,
        user: str,
        changes: Dict[str, Any],
        reason: str,
        ip_address: str,
    ):
        await self.audit_repo.log_action(
            action=action,
            rule_id=rule_id,
            user=user,
            changes=changes,
            reason=reason,
            ip_address=ip_address,
        )

    # ------------------------------------------------------------------ #
    # Versioning
    # ------------------------------------------------------------------ #
    async def create_new_version(self, rule_ids: List[str], changelog: str, deployed_by: str) -> RuleVersion:
        rules = await self.repo.get_by_ids(rule_ids)
        found_ids = {r.rule_id for r in rules}
        missing_ids = [rid for rid in rule_ids if rid not in found_ids]
        if missing_ids:
            raise ValueError(f"Rules not found: {', '.join(missing_ids)}")

        validation = self.validator.validate_rules(rules)
        if not validation.valid:
            raise ValueError(f"Validation failed: {validation.errors}")

        version_hash = hash_version(rules)
        version = RuleVersion(
            version_hash=version_hash,
            created_at=datetime.now(timezone.utc),
            is_active=False,
            rules_included=rule_ids,
            changelog=changelog,
            deployed_by=deployed_by,
        )
        return await self.create_version(version)

    async def create_version(self, version: RuleVersion) -> RuleVersion:
        new_version = await self.repo.create_version(version)
        await self.cache.invalidate_bundle()
        return new_version

    async def get_version(self, version_hash: str) -> Optional[RuleVersion]:
        return await self.repo.get_version(version_hash)

    async def get_active_version(self) -> Optional[RuleVersion]:
        return await self.repo.get_active_version()

    async def list_versions(self, limit: int = 50) -> List[RuleVersion]:
        return await self.repo.list_versions(limit=limit)

    async def activate_version(self, version_hash: str) -> bool:
        success = await self.repo.activate_version(version_hash)
        if success:
            await self.cache.invalidate_bundle()
        return success

    async def deploy_version(self, version_hash: str) -> RulesBundle:
        version = await self.repo.get_version(version_hash)
        if not version:
            raise ValueError(f"Version not found: {version_hash}")

        rules = await self.repo.get_by_ids(version.rules_included)
        found_ids = {r.rule_id for r in rules}
        missing = [rid for rid in version.rules_included if rid not in found_ids]
        if missing:
            raise ValueError(f"Rules not found for version: {', '.join(missing)}")

        validation = self.validator.validate_rules(rules)
        if not validation.valid:
            raise ValueError("; ".join(validation.errors))

        await self.repo.activate_version(version_hash)

        bundle = rules_to_bundle(rules, version_hash=version_hash)

        await self.cache.store_bundle(bundle)

        return bundle

    # ------------------------------------------------------------------ #
    # Cache facade (delegates to the RulesBundleCachePort adapter)
    #
    # These thin wrappers preserve the public RuleService API consumed by
    # RulesEngineService, so the cache implementation can change behind the
    # port without touching the engine.
    # ------------------------------------------------------------------ #
    async def cache_rules(self, bundle: RulesBundle, ttl_seconds: Optional[int] = None) -> None:
        await self.cache.store_bundle(bundle, ttl_seconds=ttl_seconds)

    async def get_cached_rules(self) -> Optional[RulesBundle]:
        return await self.cache.get_bundle()

    async def invalidate_rules_cache(self) -> None:
        await self.cache.invalidate_bundle()

    # ------------------------------------------------------------------ #
    # Internal, non-paginated reads (used by the in-memory rules engine)
    # ------------------------------------------------------------------ #
    async def list_all_active_rules_internal(self) -> List[HeuristicRule]:
        """Trae absolutamente todas las reglas activas usando cursores (Sin paginación)."""
        return await self.repo.get_all(include_inactive=False)

    async def get_rules_by_ids_internal(self, rule_ids: List[str]) -> List[HeuristicRule]:
        """
        Busca un lote completo de reglas por ID en la base de datos sin límite de paginación.
        Útil para procesos internos del sistema como el RulesEngine.
        """
        return await self.repo.get_by_ids(rule_ids)


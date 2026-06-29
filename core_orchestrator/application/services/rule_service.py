import json
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from redis.asyncio import Redis

from core_orchestrator.domain.models.rules import HeuristicRule, RulesBundle, RuleVersion, AuditAction
from core_orchestrator.domain.ports.audit_repository import AuditRepository
from core_orchestrator.domain.ports.rule_repository import RuleRepository

RULES_CACHE_KEY = "rules:active:all"
RULES_VERSION_KEY = "rules:metadata:version_hash"
RULES_UPDATED_KEY = "rules:metadata:last_updated"
DEFAULT_RULES_TTL = 86400

logger = logging.getLogger(__name__)

class RuleService:
    def __init__(
        self,
        rule_repository: RuleRepository,
        audit_repository: AuditRepository,
        redis_rules_client: Optional[Redis] = None
    ):
        self.repo = rule_repository
        self.audit_repo = audit_repository
        self.redis = redis_rules_client

    async def create_rule(self, rule: HeuristicRule) -> HeuristicRule:
        new_rule = await self.repo.create_rule(rule)
        await self.invalidate_rules_cache()
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
            await self.invalidate_rules_cache()
        return success

    async def delete_rule(self, rule_id: str) -> bool:
        success = await self.repo.delete_rule(rule_id)
        if success:
            await self.invalidate_rules_cache()
        return success

    async def get_audit_logs(self, rule_id: Optional[str] = None, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        return await self.audit_repo.get_logs(rule_id=rule_id, limit=limit, offset=offset)

    async def log_rule_action(self, action: str, rule_id: str, user: str, changes: Dict[str, Any], reason: str, ip_address: str):
        await self.audit_repo.log_action(
            action=action,
            rule_id=rule_id,
            user=user,
            changes=changes,
            reason=reason,
            ip_address=ip_address
        )
    
    async def create_new_version(self, rule_ids: List[str], changelog: str, deployed_by: str) -> RuleVersion:
        from core_orchestrator.application.services.rule_validator import RuleValidator
        from core_orchestrator.domain.models.rules import hash_version

        rules = await self.repo.get_by_ids(rule_ids)
        found_ids = {r.rule_id for r in rules}
        missing_ids = [rid for rid in rule_ids if rid not in found_ids]
        if missing_ids:
            raise ValueError(f"Rules not found: {', '.join(missing_ids)}")

        validation = RuleValidator.validate_rules(rules)
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
        await self.invalidate_rules_cache()
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
            await self.invalidate_rules_cache()
        return success

    async def deploy_version(self, version_hash: str) -> RulesBundle:
        from core_orchestrator.application.services.rule_validator import RuleValidator
        from core_orchestrator.domain.models.rules import rules_to_bundle

        version = await self.repo.get_version(version_hash)
        if not version:
            raise ValueError(f"Version not found: {version_hash}")

        rules = await self.repo.get_by_ids(version.rules_included)
        found_ids = {r.rule_id for r in rules}
        missing = [rid for rid in version.rules_included if rid not in found_ids]
        if missing:
            raise ValueError(f"Rules not found for version: {', '.join(missing)}")

        validation = RuleValidator.validate_rules(rules)
        if not validation.valid:
            raise ValueError("; ".join(validation.errors))

        await self.repo.activate_version(version_hash)
        
        bundle = rules_to_bundle(rules, version_hash=version_hash)
        
        await self.cache_rules(bundle)
        
        return bundle

    async def cache_rules(self, bundle: RulesBundle, ttl_seconds: int = DEFAULT_RULES_TTL) -> bool:
        """Guarda el bundle de reglas en Redis de forma atómica usando pipeline asíncrono."""
        if not self.redis:
            logger.warning("Redis rules client no conectado; saltando la actualización de caché")
            return False

        payload = json.dumps(bundle.to_cache_dict())

        async with self.redis.pipeline(transaction=True) as pipe:
            await pipe.set(RULES_CACHE_KEY, payload, ex=ttl_seconds)
            await pipe.set(RULES_VERSION_KEY, bundle.version_hash, ex=ttl_seconds)

            updated = bundle.last_updated.isoformat() if bundle.last_updated else datetime.now(timezone.utc).isoformat()
            await pipe.set(RULES_UPDATED_KEY, updated, ex=ttl_seconds)

            await pipe.execute()

        return True

    async def get_cached_rules(self) -> Optional[RulesBundle]:
        """Recupera el bundle de reglas serializado desde la caché de Redis."""
        if not self.redis:
            return None
        raw = await self.redis.get(RULES_CACHE_KEY)
        if not raw:
            return None
        data = json.loads(raw)
        return RulesBundle.from_cache_dict(data)

    async def invalidate_rules_cache(self) -> bool:
        """Deletes linked cache keys to force a clean reload."""
        if not self.redis:
            return False
        await self.redis.delete(RULES_CACHE_KEY, RULES_VERSION_KEY, RULES_UPDATED_KEY)
        logger.info("Rules cache invalidated.")
        return True

    async def list_all_active_rules_internal(self) -> List[HeuristicRule]:
        """Trae absolutamente todas las reglas activas usando cursores (Sin paginación)."""
        return await self.repo.get_all(include_inactive=False)

    async def get_rules_by_ids_internal(self, rule_ids: List[str]) -> List[HeuristicRule]:
        """
        Busca un lote completo de reglas por ID en la base de datos sin límite de paginación.
        Útil para procesos internos del sistema como el RulesEngine.
        """
        return await self.repo.get_by_ids(rule_ids)

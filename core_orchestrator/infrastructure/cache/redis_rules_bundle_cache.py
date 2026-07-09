# core_orchestrator/infrastructure/cache/redis_rules_bundle_cache.py
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from redis.asyncio import Redis

from core_orchestrator.domain.models.rule_engine.rules import RulesBundle
from core_orchestrator.domain.ports.rules.rules_bundle_cache import RulesBundleCachePort

logger = logging.getLogger(__name__)

RULES_CACHE_KEY = "rules:active:all"
RULES_VERSION_KEY = "rules:metadata:version_hash"
RULES_UPDATED_KEY = "rules:metadata:last_updated"
DEFAULT_RULES_TTL = 86400


class RedisRulesBundleCache(RulesBundleCachePort):
    """
    A Redis implementation of the RulesBundleCachePort with optional tenant isolation.
    """

    def __init__(self, redis_client: Redis):
        self._redis = redis_client

    @staticmethod
    def _build_cache_key(suffix: Optional[str] = None) -> str:
        """Build cache key with optional tenant suffix."""
        if suffix and suffix != "all":
            return f"rules:active:{suffix}"
        return RULES_CACHE_KEY

    @staticmethod
    def _build_version_key(suffix: Optional[str] = None) -> str:
        """Build version metadata key with optional tenant suffix."""
        if suffix and suffix != "all":
            return f"rules:metadata:version_hash:{suffix}"
        return RULES_VERSION_KEY

    @staticmethod
    def _build_updated_key(suffix: Optional[str] = None) -> str:
        """Build last_updated metadata key with optional tenant suffix."""
        if suffix and suffix != "all":
            return f"rules:metadata:last_updated:{suffix}"
        return RULES_UPDATED_KEY

    async def get_bundle(self, cache_key_suffix: Optional[str] = None) -> Optional[RulesBundle]:
        if not self._redis:
            logger.warning("Redis client not connected.")
            return None
        # Default to "global" if no suffix provided
        key = self._build_cache_key(cache_key_suffix or "global")
        raw = await self._redis.get(key)
        if not raw:
            return None
        data = json.loads(raw)
        return RulesBundle.from_cache_dict(data)

    async def store_bundle(self, bundle: RulesBundle, cache_key_suffix: Optional[str] = None, ttl_seconds: Optional[int] = None):
        if not self._redis:
            logger.warning("Redis client not connected; skipping cache update.")
            return

        ttl = ttl_seconds if ttl_seconds is not None else DEFAULT_RULES_TTL
        # Default to "global" if no suffix provided
        safe_suffix = cache_key_suffix or "global"
        cache_key = self._build_cache_key(safe_suffix)
        version_key = self._build_version_key(safe_suffix)
        updated_key = self._build_updated_key(safe_suffix)
        
        payload = json.dumps(bundle.to_cache_dict())
        updated = bundle.last_updated.isoformat() if bundle.last_updated else datetime.now(timezone.utc).isoformat()

        async with self._redis.pipeline(transaction=True) as pipe:
            await pipe.set(cache_key, payload, ex=ttl)
            await pipe.set(version_key, bundle.version_hash, ex=ttl)
            await pipe.set(updated_key, updated, ex=ttl)
            await pipe.execute()
        logger.info(f"Successfully cached rules bundle version: {bundle.version_hash} (key suffix: {safe_suffix})")

    async def invalidate_bundle(self, cache_key_suffix: Optional[str] = None):
        if not self._redis:
            logger.warning("Redis client not connected.")
            return
        # Default to "global" if no suffix provided
        safe_suffix = cache_key_suffix or "global"
        cache_key = self._build_cache_key(safe_suffix)
        version_key = self._build_version_key(safe_suffix)
        updated_key = self._build_updated_key(safe_suffix)
        await self._redis.delete(cache_key, version_key, updated_key)
        logger.info(f"Rules cache bundle invalidated (key suffix: {safe_suffix}).")

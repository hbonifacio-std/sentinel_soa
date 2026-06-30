# core_orchestrator/infrastructure/cache/redis_rules_bundle_cache.py
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from redis.asyncio import Redis

from core_orchestrator.domain.models.rules import RulesBundle
from core_orchestrator.domain.ports.rules_bundle_cache import RulesBundleCachePort

logger = logging.getLogger(__name__)

RULES_CACHE_KEY = "rules:active:all"
RULES_VERSION_KEY = "rules:metadata:version_hash"
RULES_UPDATED_KEY = "rules:metadata:last_updated"
DEFAULT_RULES_TTL = 86400


class RedisRulesBundleCache(RulesBundleCachePort):
    """
    A Redis implementation of the RulesBundleCachePort.
    """

    def __init__(self, redis_client: Redis):
        self._redis = redis_client

    async def get_bundle(self) -> Optional[RulesBundle]:
        if not self._redis:
            logger.warning("Redis client not connected.")
            return None
        raw = await self._redis.get(RULES_CACHE_KEY)
        if not raw:
            return None
        data = json.loads(raw)
        return RulesBundle.from_cache_dict(data)

    async def store_bundle(self, bundle: RulesBundle, ttl_seconds: Optional[int] = None):
        if not self._redis:
            logger.warning("Redis client not connected; skipping cache update.")
            return

        ttl = ttl_seconds if ttl_seconds is not None else DEFAULT_RULES_TTL
        payload = json.dumps(bundle.to_cache_dict())
        updated = bundle.last_updated.isoformat() if bundle.last_updated else datetime.now(timezone.utc).isoformat()

        async with self._redis.pipeline(transaction=True) as pipe:
            await pipe.set(RULES_CACHE_KEY, payload, ex=ttl)
            await pipe.set(RULES_VERSION_KEY, bundle.version_hash, ex=ttl)
            await pipe.set(RULES_UPDATED_KEY, updated, ex=ttl)
            await pipe.execute()
        logger.info(f"Successfully cached rules bundle version: {bundle.version_hash}")

    async def invalidate_bundle(self):
        if not self._redis:
            logger.warning("Redis client not connected.")
            return
        await self._redis.delete(RULES_CACHE_KEY, RULES_VERSION_KEY, RULES_UPDATED_KEY)
        logger.info("Rules cache bundle invalidated.")

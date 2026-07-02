# core_orchestrator/infrastructure/cache/redis_cache.py
import logging
from typing import Any, Optional

from redis.asyncio import Redis

from core_orchestrator.domain.ports.shared.cache_port import CachePort

logger = logging.getLogger(__name__)


class RedisCache(CachePort):
    """
    A Redis implementation of the CachePort.
    """

    def __init__(self, redis_client: Redis):
        self._redis = redis_client

    async def get(self, key: str) -> Optional[Any]:
        """Gets a value from the cache by key."""
        if not self._redis:
            logger.warning("Redis client not connected; cannot get key %s", key)
            return None
        value = await self._redis.get(key)
        if value:
            return value
        return None

    async def set(self, key: str, value: Any, expire_seconds: Optional[int] = None):
        """Sets a value in the cache with an optional expiration."""
        if not self._redis:
            logger.warning("Redis client not connected; cannot set key %s", key)
            return
        await self._redis.set(key, value, ex=expire_seconds)

    async def delete(self, key: str):
        """Deletes a value from the cache by key."""
        if not self._redis:
            logger.warning("Redis client not connected; cannot delete key %s", key)
            return
        await self._redis.delete(key)

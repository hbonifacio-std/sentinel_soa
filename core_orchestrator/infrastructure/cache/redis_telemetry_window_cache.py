# core_orchestrator/infrastructure/cache/redis_telemetry_window_cache.py
import logging
from typing import List, Any, Optional

from redis.asyncio import Redis

from core_orchestrator.domain.ports.telemetry_window_cache import TelemetryWindowCachePort

logger = logging.getLogger(__name__)


class RedisTelemetryWindowCache(TelemetryWindowCachePort):
    """
    A Redis implementation of the TelemetryWindowCachePort, using Redis lists.
    """

    def __init__(self, redis_client: Redis):
        self._redis = redis_client

    async def add_to_window(self, key: str, value: Any, expire_seconds: int):
        if not self._redis:
            logger.warning("Redis client not connected.")
            return
        pipe = self._redis.pipeline()
        pipe.rpush(key, value)
        pipe.expire(key, expire_seconds)
        await pipe.execute()

    async def add_multiple_to_window(self, key: str, values: List[Any], expire_seconds: int):
        if not self._redis:
            logger.warning("Redis client not connected.")
            return
        pipe = self._redis.pipeline()
        pipe.rpush(key, *values)
        pipe.expire(key, expire_seconds)
        await pipe.execute()

    async def get_active_window_keys(self, pattern: str) -> List[str]:
        if not self._redis:
            logger.warning("Redis client not connected.")
            return []
        keys = []
        async for key in self._redis.scan_iter(pattern):
            keys.append(key)
        return keys

    async def get_window_size(self, key: str) -> int:
        if not self._redis or not key:
            return 0
        return await self._redis.llen(key)

    async def get_and_clear_window(self, key: str) -> Optional[List[Any]]:
        if not self._redis:
            logger.warning("Redis client not connected.")
            return None
        
        pipe = self._redis.pipeline()
        pipe.lrange(key, 0, -1)
        pipe.delete(key)
        results = await pipe.execute()
        
        events_json = results[0]
        return events_json if events_json else None

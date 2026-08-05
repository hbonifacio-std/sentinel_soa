import logging
from typing import List, Any, Optional, Awaitable, cast
from core_orchestrator.domain.exceptions.database_exceptions import DatabaseNotConnectedError
from core_orchestrator.domain.ports.telemetry.telemetry_window_cache_port import TelemetryWindowCachePort
from core_orchestrator.infrastructure.adapters.redis.base_redis_adapter import BaseRedisCacheAdapter

logger = logging.getLogger(__name__)


class RedisTelemetryWindowAdapter(BaseRedisCacheAdapter,TelemetryWindowCachePort):
    """
    A Redis implementation of the TelemetryWindowCachePort, using Redis lists.
    """

    async def add_to_window(self, key: str, value: Any, expire_seconds: int):
        if not self._redis:
            raise DatabaseNotConnectedError(client_name="Redis")

        pipe = self._redis.pipeline()
        pipe.rpush(key, value)
        pipe.expire(key, expire_seconds)
        await pipe.execute()

    async def add_multiple_to_window(self, key: str, values: List[Any], expire_seconds: int):
        if not self._redis:
            raise DatabaseNotConnectedError(client_name="Redis")

        pipe = self._redis.pipeline()
        pipe.rpush(key, *values)
        pipe.expire(key, expire_seconds)
        await pipe.execute()

    async def get_active_window_keys(self, pattern: str) -> List[str]:
        if not self._redis:
            raise DatabaseNotConnectedError(client_name="Redis")

        keys: List[str] = []
        async for key in self._redis.scan_iter(match=pattern, count=200):
            keys.append(key.decode("utf-8") if isinstance(key, bytes) else key)
        return keys

    async def get_window_size(self, key: str) -> int:
        if not self._redis or not key:
            return 0
        return await cast(Awaitable[int], self._redis.llen(key))

    async def get_and_clear_window(self, key: str) -> Optional[List[Any]]:
        if not self._redis:
            raise DatabaseNotConnectedError(client_name="Redis")
        
        pipe = self._redis.pipeline()
        pipe.lrange(key, 0, -1)
        await pipe.delete(key)
        results = await pipe.execute()
        
        events_json = results[0]
        return events_json if events_json else None

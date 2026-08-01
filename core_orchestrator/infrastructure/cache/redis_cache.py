# core_orchestrator/infrastructure/cache/redis_cache.py
import logging
from typing import Any, Optional

from redis.asyncio import Redis

from core_orchestrator.domain.ports.shared.cache_port import CacheRepositoryPort

logger = logging.getLogger(__name__)


class RedisCacheRepository(CacheRepositoryPort):
    """
    Handles caching operations using a Redis backend.

    This class provides methods to perform basic cache operations such as retrieving, storing, and deleting
    data in a Redis database. It relies on an established Redis client to handle all interactions with the
    Redis server. The class serves as an implementation of the `CacheRepositoryPort` interface and adheres
    to its defined contract.
    """

    def __init__(self, redis_client: Redis):
        self._redis = redis_client

    async def get(self, key: str) -> Optional[Any]:
        """
        Retrieve a value associated with a given key from Redis.

        This method attempts to fetch the value corresponding to the provided key
        from the Redis database if the Redis client is properly connected. If the
        key does not exist or the client is not connected, the method will return
        None.

        Parameters:
        key (str): The key to retrieve the associated value for.

        Returns:
        Optional[Any]: The value associated with the provided key if it exists, or
        None if the key does not exist or the Redis client is not connected.
        """
        if not self._redis:
            logger.warning("Redis client not connected; cannot get key %s", key)
            return None
        value = await self._redis.get(key)
        if value:
            return value
        return None

    async def set(self, key: str, value: Any, expire_seconds: Optional[int] = None):
        """
        Sets a key-value pair in the Redis store, with an optional expiration time.

        This method allows storing data in Redis and optionally specifying an expiration
        time for the key. If the Redis client is not connected, the method logs a warning
        and does not perform the operation.

        Parameters:
            key: str
                The key to be set in Redis.
            value: Any
                The value to be associated with the specified key.
            expire_seconds: Optional[int]
                The expiration time for the key, in seconds. If None, the key will not
                have an expiration.

        Returns:
            None
        """
        if not self._redis:
            logger.warning("Redis client not connected; cannot set key %s", key)
            return
        await self._redis.set(key, value, ex=expire_seconds)

    async def delete(self, key: str):
        """
        Deletes a key from the Redis database.

        This asynchronous method attempts to delete the specified key from the Redis
        database if a connection to the Redis client exists. If the Redis client is
        not connected, a warning is logged and no action is taken.

        Parameters:
        key : str
            The key to delete from the Redis database.
        """
        if not self._redis:
            logger.warning("Redis client not connected; cannot delete key %s", key)
            return
        await self._redis.delete(key)

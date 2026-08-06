import logging
from typing import  Optional

from redis.asyncio import Redis
from core_orchestrator.domain.ports.auth.telemetry_tenant_cache_port import TelemetryTenantCachePort
from core_orchestrator.infrastructure.adapters.redis.base_redis_adapter import RedisBaseCacheAdapter

logger = logging.getLogger(__name__)

CACHE_KEY_PREFIX_ID = "telemetry_client:id:"
CACHE_TTL_SECONDS = 86400


class RedisTelemetryTenantRepositoryAdapter(RedisBaseCacheAdapter, TelemetryTenantCachePort):
    """
    Adapter for managing telemetry tenant data in Redis cache.

    This class provides functionality to interact with the Redis cache for telemetry
    tenant information. It supports storing and retrieving tenant data associated with
    specific client identifiers. This class extends the base Redis cache adapter and
    implements the telemetry tenant cache port interface.

    Attributes:
        redis_client (Redis): The Redis client instance used to interact with the
                              Redis database.

    Methods:
        fetch_cached_tenant(client_id: str) -> Optional[str]:
            Fetches the cached telemetry tenant data for the specified client ID
        cache_tenant(client_id: str, tenant: str) -> None:
            Caches the telemetry tenant data for the specified client ID.
    """
    def __init__(self, redis_client: Redis|None = None):
        super().__init__(redis_client)
        self.redis_client = redis_client

    def _build_key(self, client_id: str) -> str:
        """
        Builds a cache key by appending the given client ID to a predefined prefix.

        Arguments:
        client_id: str
            The ID of the client for which the cache key is being generated.

        Returns:
        str
            The generated cache key.
        """
        return f"{CACHE_KEY_PREFIX_ID}{client_id}"

    async def fetch_cached_tenant(self, client_id: str) -> Optional[str]:
        """
        Fetches and returns the cached tenant identifier associated with the given client ID.

        The method attempts to retrieve a previously cached tenant identifier by constructing a
        key based on the provided client ID. The data is retrieved asynchronously and decoded
        if it is stored as a byte string.

        Parameters:
            client_id (str): The unique identifier of the client for which the tenant
            is being fetched.

        Returns:
            Optional[str]: The cached tenant identifier as a string if found, otherwise None.
        """
        key = self._build_key(client_id)
        raw = await self.get(key)

        if isinstance(raw, bytes):
            return raw.decode("utf-8")
        if isinstance(raw, str):
            return raw
        return None

    async def cache_tenant(self,client_id: str, tenant: str) -> None:
        """
        Caches the tenant data for a specific client ID.

        This method stores tenant information in the cache with a key built from
        the tenant identifier and a predefined expiration time. This is useful
        for reducing redundant operations or requests related to tenant
        information.

        Parameters:
        client_id : str
            The unique identifier of the client.
        tenant : str
            The tenant information to be cached.

        Returns:
        None
        """
        key = self._build_key(tenant)
        await self.set(key, tenant, expire_seconds=CACHE_TTL_SECONDS)




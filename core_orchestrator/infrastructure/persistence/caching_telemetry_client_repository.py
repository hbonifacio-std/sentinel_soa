# core_orchestrator/infrastructure/persistence/caching_telemetry_client_repository.py
import logging
from typing import List, Optional

from core_orchestrator.domain.entities.auth.telemetry_client import TelemetryClientInDB, TelemetryClientCreate
from core_orchestrator.domain.ports.shared.cache_port import CachePort
from core_orchestrator.domain.ports.telemetry.telemetry_client_repository import TelemetryClientRepository

logger = logging.getLogger(__name__)

CACHE_KEY_PREFIX_ID = "telemetry_client:id:"
CACHE_KEY_PREFIX_PK = "telemetry_client:pk:"
CACHE_TTL_SECONDS = 3600  # 1 hour


class CachingTelemetryClientRepository(TelemetryClientRepository):
    """
    A decorator for TelemetryClientRepository that adds a caching layer.
    """

    def __init__(self, primary_repository: TelemetryClientRepository, cache: CachePort):
        self._primary_repository = primary_repository
        self._cache = cache

    def _client_id_key(self, client_id: str) -> str:
        return f"{CACHE_KEY_PREFIX_ID}{client_id}"

    def _public_key_key(self, public_key: str) -> str:
        return f"{CACHE_KEY_PREFIX_PK}{public_key}"

    async def get(self, client_id: str) -> Optional[TelemetryClientInDB]:
        # This method seems to be missing from TelemetryClientService logic, but it's good to have
        return await self.get_by_client_id(client_id, include_inactive=True)

    async def get_by_client_id(self, client_id: str, include_inactive: bool = False) -> Optional[TelemetryClientInDB]:
        cache_key = self._client_id_key(client_id)
        cached = await self._cache.get(cache_key)
        if cached:
            client = TelemetryClientInDB.model_validate_json(cached)
            if include_inactive or client.is_active:
                logger.debug(f"Cache hit for client ID: {client_id}")
                return client

        logger.debug(f"Cache miss for client ID: {client_id}")
        client = await self._primary_repository.get_by_client_id(client_id, include_inactive)
        if client:
            await self._cache.set(
                cache_key,
                client.model_dump_json(),
                expire_seconds=CACHE_TTL_SECONDS
            )
            await self._cache.set(
                self._public_key_key(client.api_key_hash),
                client.model_dump_json(),
                expire_seconds=CACHE_TTL_SECONDS
            )
        return client

    async def get_by_public_key(self, public_key: str) -> Optional[TelemetryClientInDB]:
        cache_key = self._public_key_key(public_key)
        cached = await self._cache.get(cache_key)
        if cached:
            logger.debug(f"Cache hit for public key: {public_key}")
            return TelemetryClientInDB.model_validate_json(cached)

        logger.debug(f"Cache miss for public key: {public_key}")
        client = await self._primary_repository.get_by_public_key(public_key)
        if client:
            await self._cache.set(
                cache_key,
                client.model_dump_json(),
                expire_seconds=CACHE_TTL_SECONDS
            )
            await self._cache.set(
                self._client_id_key(client.client_id),
                client.model_dump_json(),
                expire_seconds=CACHE_TTL_SECONDS
            )
        return client

    async def create(self, client_create: TelemetryClientCreate) -> TelemetryClientInDB:
        # No caching on create, just pass through
        return await self._primary_repository.create(client_create)

    async def list_all(self, include_inactive: bool = False) -> List[TelemetryClientInDB]:
        # We don't cache lists as they can get stale. Pass through.
        return await self._primary_repository.list_all(include_inactive)

    async def upsert(self, client_create: TelemetryClientCreate, overwrite_existing: bool) -> tuple[TelemetryClientInDB, bool, bool]:
        # After upserting, invalidate cache for this client.
        client, created, updated = await self._primary_repository.upsert(client_create, overwrite_existing)
        
        logger.debug(f"Invalidating cache for client ID: {client.client_id}")
        await self._cache.delete(self._client_id_key(client.client_id))
        
        return client, created, updated

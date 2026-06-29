import logging
import secrets
from typing import Optional, List

from core_orchestrator.domain.ports.telemetry_client_repository import TelemetryClientRepository
from core_orchestrator.domain.models.telemetry_client import TelemetryClientAuthContext, TelemetryClientCreate, TelemetryClientInDB, TelemetryClientInDB
from core_orchestrator.infrastructure.cache.cache_service import CacheService
from core_orchestrator.infrastructure.security.jwt_utils import verify_hmac_signature

logger = logging.getLogger(__name__)


class TelemetryClientService:
    def __init__(self, telemetry_client_repository: TelemetryClientRepository, cache_service: CacheService):
        self._repository = telemetry_client_repository
        self._cache_service = cache_service

    async def list_clients(self, include_inactive: bool = False) -> List[TelemetryClientInDB]:
        return await self._repository.list_all(include_inactive)

    async def get_client_by_client_id(self, client_id: str, include_inactive: bool = False) -> Optional[TelemetryClientInDB]:
        cached_client = await self._cache_service.get_client_by_id(client_id)
        if cached_client and (include_inactive or cached_client.is_active):
            return cached_client

        client = await self._repository.get_by_client_id(client_id, include_inactive)
        if client and client.is_active:
            await self._cache_service.cache_client(client)
        return client

    async def get_client_by_public_key(self, public_key: str, include_inactive: bool = False) -> Optional[TelemetryClientInDB]:
        cached_client = await self._cache_service.get_client_by_public_key(public_key)
        if cached_client and (include_inactive or cached_client.is_active):
            return cached_client
        
        client = await self._repository.get_by_public_key(public_key)
        if client and client.is_active:
            await self._cache_service.cache_client(client)
        return client

    async def upsert_client(self, payload: TelemetryClientCreate, overwrite_existing: bool = False) -> tuple[
        TelemetryClientInDB, bool, bool]:
        client, created, updated = await self._repository.upsert(payload, overwrite_existing)
        if client.is_active:
            await self._cache_service.cache_client(client)
        else:
            await self._cache_service.evict_cached_client(client)
        return client, created, updated

    async def authorize_api_key(self, client_id: str, api_key: str) -> Optional[TelemetryClientAuthContext]:
        client = await self.get_client_by_client_id(client_id)
        if not client or not client.is_active:
            return None
        if not secrets.compare_digest(client.api_key, api_key):
            return None
        return TelemetryClientAuthContext(
            client_id=client.client_id,
            source_id=client.source_id,
            display_name=client.display_name,
            hmac_public_key=client.hmac_public_key,
        )

    async def authorize_hmac(self, public_key: str, signature: str, timestamp: int,
                             body: bytes) -> Optional[TelemetryClientAuthContext]:
        client = await self.get_client_by_public_key(public_key)
        if not client or not client.is_active:
            return None

        is_valid = verify_hmac_signature(
            body=body,
            signature=signature,
            public_key=public_key,
            timestamp=timestamp,
            redis_secrets={public_key: client.hmac_secret},
        )
        if not is_valid:
            return None

        return TelemetryClientAuthContext(
            client_id=client.client_id,
            source_id=client.source_id,
            display_name=client.display_name,
            hmac_public_key=client.hmac_public_key,
        )
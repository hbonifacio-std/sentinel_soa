import logging
import secrets
from typing import Optional, List

from core_orchestrator.domain.ports.telemetry.telemetry_client_repository import TelemetryClientRepository
from core_orchestrator.domain.ports.auth.signature_verifier import SignatureVerifierPort
from core_orchestrator.domain.models.auth.telemetry_client import TelemetryClientAuthContext, TelemetryClientCreate, TelemetryClientInDB

logger = logging.getLogger(__name__)


class TelemetryClientService:
    def __init__(self, telemetry_client_repository: TelemetryClientRepository, signature_verifier: SignatureVerifierPort):
        self._repository = telemetry_client_repository
        self._signature_verifier = signature_verifier

    async def list_clients(self, include_inactive: bool = False) -> List[TelemetryClientInDB]:
        return await self._repository.list_all(include_inactive)

    async def get_client_by_client_id(self, client_id: str, include_inactive: bool = False) -> Optional[TelemetryClientInDB]:
        return await self._repository.get_by_client_id(client_id, include_inactive)

    async def get_client_by_public_key(self, public_key: str, include_inactive: bool = False) -> Optional[TelemetryClientInDB]:
        # Note: The original implementation had `include_inactive` but the port didn't.
        # The caching repository now handles this correctly.
        return await self._repository.get_by_public_key(public_key)

    async def upsert_client(self, payload: TelemetryClientCreate, overwrite_existing: bool = False) -> tuple[
        TelemetryClientInDB, bool, bool]:
        return await self._repository.upsert(payload, overwrite_existing)

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

        is_valid = self._signature_verifier.verify_hmac_signature(
            body=body,
            signature=signature,
            public_key=public_key,
            timestamp=timestamp,
            secret=client.hmac_secret,
        )
        if not is_valid:
            return None

        return TelemetryClientAuthContext(
            client_id=client.client_id,
            source_id=client.source_id,
            display_name=client.display_name,
            hmac_public_key=client.hmac_public_key,
        )

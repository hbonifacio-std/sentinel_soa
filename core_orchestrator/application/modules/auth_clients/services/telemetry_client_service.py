import logging
import secrets
import hashlib
from typing import Optional, List
import bcrypt

from core_orchestrator.domain.ports.telemetry.telemetry_client_repository import TelemetryClientRepository
from core_orchestrator.domain.ports.auth.signature_verifier import SignatureVerifierPort
from core_orchestrator.domain.models.auth.telemetry_client import (
    TelemetryClientAuthContext,
    TelemetryClientCreate,
    TelemetryClientInDB,
)

logger = logging.getLogger(__name__)

def _is_bcrypt_hash(hash_string: str) -> bool:
    return hash_string.startswith(("$2a$", "$2b$", "$2y$"))


def _is_sha256_hash(hash_string: str) -> bool:
    return len(hash_string) == 64 and all(c in "0123456789abcdef" for c in hash_string.lower())


def _verify_api_key(stored_api_key: str, provided_api_key: str) -> tuple[bool, bool]:
    """
    Return a tuple: (is_valid, should_migrate_to_bcrypt).
    """
    if _is_bcrypt_hash(stored_api_key):
        try:
            return bcrypt.checkpw(provided_api_key.encode(), stored_api_key.encode()), False
        except Exception:
            return False, False
    if _is_sha256_hash(stored_api_key):
        is_valid = secrets.compare_digest(
            hashlib.sha256(provided_api_key.encode()).hexdigest(),
            stored_api_key,
        )
        return is_valid, is_valid
    is_valid = secrets.compare_digest(stored_api_key, provided_api_key)
    return is_valid, is_valid


class TelemetryClientService:
    def __init__(self, telemetry_client_repository: TelemetryClientRepository, signature_verifier: SignatureVerifierPort):
        self._repository = telemetry_client_repository
        self._signature_verifier = signature_verifier

    async def list_clients(self, include_inactive: bool = False) -> List[TelemetryClientInDB]:
        return await self._repository.list_all(include_inactive)

    async def get_client_by_client_id(self, client_id: str, include_inactive: bool = False) -> Optional[TelemetryClientInDB]:
        return await self._repository.get_by_client_id(client_id, include_inactive)

    async def get_client_by_public_key(self, public_key: str) -> Optional[TelemetryClientInDB]:
        # Note: The original implementation had `include_inactive` but the port didn't.
        # The caching repository now handles this correctly.
        return await self._repository.get_by_public_key(public_key)

    async def upsert_client(self, payload: TelemetryClientCreate, overwrite_existing: bool = False) -> tuple[
        TelemetryClientInDB, bool, bool]:
        return await self._repository.upsert(payload, overwrite_existing)

    async def authorize_api_key(self, client_id: str) -> Optional[TelemetryClientInDB]:
        client = await self.get_client_by_client_id(client_id)
        if not client or not client.is_active:
            return None
        return client

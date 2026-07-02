"""
MongoDB implementation of the telemetry client repository.
"""
import logging
from datetime import datetime, timezone
from typing import List, Optional

from core_orchestrator.infrastructure.config.database import DatabaseManager
from core_orchestrator.domain.ports.telemetry.telemetry_client_repository import TelemetryClientRepository
from core_orchestrator.domain.models.auth.telemetry_client import TelemetryClientCreate, TelemetryClientInDB

logger = logging.getLogger(__name__)


class MongoTelemetryClientRepository(TelemetryClientRepository):
    """
    MongoDB implementation for telemetry client persistence.
    """

    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager
        self.collection = db_manager.get_auth_db()["authorized_telemetry_clients"]

    async def get(self, client_id: str) -> Optional[TelemetryClientInDB]:
        doc = await self.collection.find_one({"client_id": client_id})
        return TelemetryClientInDB(**doc) if doc else None

    async def get_by_public_key(self, public_key: str) -> Optional[TelemetryClientInDB]:
        doc = await self.collection.find_one({"hmac_public_key": public_key})
        return TelemetryClientInDB(**doc) if doc else None
    
    async def get_by_client_id(self, client_id: str, include_inactive: bool = False) -> Optional[TelemetryClientInDB]:
        query = {"client_id": client_id}
        if not include_inactive:
            query["is_active"] = True
        doc = await self.collection.find_one(query)
        return TelemetryClientInDB(**doc) if doc else None

    async def create(self, client_create: TelemetryClientCreate) -> TelemetryClientInDB:
        now = datetime.now(timezone.utc)
        client = TelemetryClientInDB(
            **client_create.model_dump(),
            created_at=now,
            updated_at=now,
        )
        await self.collection.insert_one(client.model_dump(mode="python"))
        logger.info("Telemetry client created: %s -> source=%s", client.client_id, client.source_id)
        return client

    async def list_all(self, include_inactive: bool = False) -> List[TelemetryClientInDB]:
        query = {} if include_inactive else {"is_active": True}
        cursor = self.collection.find(query).sort("client_id", 1)
        docs = await cursor.to_list(length=None)
        return [TelemetryClientInDB(**doc) for doc in docs]

    async def upsert(self, payload: TelemetryClientCreate, overwrite_existing: bool = False) -> tuple[TelemetryClientInDB, bool, bool]:
        existing = await self.collection.find_one({"client_id": payload.client_id})
        now = datetime.now(timezone.utc)

        if existing and not overwrite_existing:
            client = TelemetryClientInDB(**existing)
            return client, False, False

        if existing:
            current = TelemetryClientInDB(**existing)
            updated = current.model_copy(
                update={
                    "source_id": payload.source_id,
                    "display_name": payload.display_name,
                    "description": payload.description,
                    "is_active": payload.is_active,
                    "api_key": payload.api_key,
                    "hmac_public_key": payload.hmac_public_key,
                    "hmac_secret": payload.hmac_secret,
                    "updated_at": now,
                }
            )
            await self.collection.update_one({"client_id": payload.client_id}, {"$set": updated.model_dump(mode="python")})
            logger.info("Telemetry client updated: %s -> source=%s", updated.client_id, updated.source_id)
            return updated, False, True

        client = TelemetryClientInDB(
            **payload.model_dump(),
            created_at=now,
            updated_at=now,
        )
        await self.collection.insert_one(client.model_dump(mode="python"))
        logger.info("Telemetry client created: %s -> source=%s", client.client_id, client.source_id)
        return client, True, False

    async def ensure_indexes(self) -> None:
        """Ensure unique indexes required by the clients collection."""
        await self.collection.create_index("client_id", unique=True)
        await self.collection.create_index("source_id", unique=True)
        await self.collection.create_index("hmac_public_key", unique=True)
        await self.collection.create_index("is_active")

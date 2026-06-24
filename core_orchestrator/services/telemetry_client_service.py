from __future__ import annotations

import json
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import List, Optional

from core_orchestrator.models.telemetry_client import (
    TelemetryClientAuthContext,
    TelemetryClientCreate,
    TelemetryClientInDB,
)
from core_orchestrator.security.jwt_utils import verify_hmac_signature
from core_orchestrator.services.database import db

logger = logging.getLogger("core_orchestrator.services.telemetry_client_service")

CACHE_TTL_SECONDS = int(os.getenv("AUTHORIZED_CLIENT_CACHE_TTL_SECONDS", "3600"))
CLIENT_ID_CACHE_PREFIX = "telemetry:clients:client_id:"
PUBLIC_KEY_CACHE_PREFIX = "telemetry:clients:public_key:"
SOURCE_ID_CACHE_PREFIX = "telemetry:clients:source_id:"


class TelemetryClientService:
    @staticmethod
    async def get_collection():
        return db.get_app_db().authorized_telemetry_clients

    @staticmethod
    async def ensure_indexes() -> None:
        collection = await TelemetryClientService.get_collection()
        await collection.create_index("client_id", unique=True)
        await collection.create_index("source_id", unique=True)
        await collection.create_index("hmac_public_key", unique=True)
        await collection.create_index("is_active")

    @staticmethod
    def _redis():
        return db.redis_client

    @staticmethod
    def _serialize_client(client: TelemetryClientInDB) -> str:
        return json.dumps(client.model_dump(mode="json"))

    @staticmethod
    def _deserialize_client(raw: str | bytes) -> TelemetryClientInDB:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return TelemetryClientInDB(**json.loads(raw))

    @staticmethod
    def _client_id_key(client_id: str) -> str:
        return f"{CLIENT_ID_CACHE_PREFIX}{client_id}"

    @staticmethod
    def _public_key_key(public_key: str) -> str:
        return f"{PUBLIC_KEY_CACHE_PREFIX}{public_key}"

    @staticmethod
    def _source_id_key(source_id: str) -> str:
        return f"{SOURCE_ID_CACHE_PREFIX}{source_id}"

    @staticmethod
    async def cache_client(client: TelemetryClientInDB) -> bool:
        redis_client = TelemetryClientService._redis()
        if not redis_client:
            return False

        payload = TelemetryClientService._serialize_client(client)
        pipe = redis_client.pipeline()
        pipe.set(TelemetryClientService._client_id_key(client.client_id), payload, ex=CACHE_TTL_SECONDS)
        pipe.set(TelemetryClientService._public_key_key(client.hmac_public_key), payload, ex=CACHE_TTL_SECONDS)
        pipe.set(TelemetryClientService._source_id_key(client.source_id), payload, ex=CACHE_TTL_SECONDS)
        await pipe.execute()
        return True

    @staticmethod
    async def evict_cached_client(client: TelemetryClientInDB) -> bool:
        redis_client = TelemetryClientService._redis()
        if not redis_client:
            return False
        await redis_client.delete(
            TelemetryClientService._client_id_key(client.client_id),
            TelemetryClientService._public_key_key(client.hmac_public_key),
            TelemetryClientService._source_id_key(client.source_id),
        )
        return True

    @staticmethod
    async def list_clients(include_inactive: bool = False) -> List[TelemetryClientInDB]:
        collection = await TelemetryClientService.get_collection()
        query = {} if include_inactive else {"is_active": True}
        cursor = collection.find(query).sort("client_id", 1)
        docs = await cursor.to_list(length=None)
        return [TelemetryClientInDB(**doc) for doc in docs]

    @staticmethod
    async def _get_cached_by_key(cache_key: str) -> Optional[TelemetryClientInDB]:
        redis_client = TelemetryClientService._redis()
        if not redis_client:
            return None
        raw = await redis_client.get(cache_key)
        if not raw:
            return None
        return TelemetryClientService._deserialize_client(raw)

    @staticmethod
    async def get_client_by_client_id(client_id: str, include_inactive: bool = False) -> Optional[TelemetryClientInDB]:
        cached = await TelemetryClientService._get_cached_by_key(TelemetryClientService._client_id_key(client_id))
        if cached and (include_inactive or cached.is_active):
            return cached

        collection = await TelemetryClientService.get_collection()
        query = {"client_id": client_id}
        if not include_inactive:
            query["is_active"] = True
        doc = await collection.find_one(query)
        if not doc:
            return None
        client = TelemetryClientInDB(**doc)
        if client.is_active:
            await TelemetryClientService.cache_client(client)
        return client

    @staticmethod
    async def get_client_by_public_key(public_key: str, include_inactive: bool = False) -> Optional[TelemetryClientInDB]:
        cached = await TelemetryClientService._get_cached_by_key(TelemetryClientService._public_key_key(public_key))
        if cached and (include_inactive or cached.is_active):
            return cached

        collection = await TelemetryClientService.get_collection()
        query = {"hmac_public_key": public_key}
        if not include_inactive:
            query["is_active"] = True
        doc = await collection.find_one(query)
        if not doc:
            return None
        client = TelemetryClientInDB(**doc)
        if client.is_active:
            await TelemetryClientService.cache_client(client)
        return client

    @staticmethod
    async def upsert_client(payload: TelemetryClientCreate, overwrite_existing: bool = False) -> tuple[TelemetryClientInDB, bool, bool]:
        """
        Returns:
            tuple[client, created, updated]
        """
        collection = await TelemetryClientService.get_collection()
        existing = await collection.find_one({"client_id": payload.client_id})
        now = datetime.now(timezone.utc)

        if existing and not overwrite_existing:
            client = TelemetryClientInDB(**existing)
            if client.is_active:
                await TelemetryClientService.cache_client(client)
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
            await collection.update_one({"client_id": payload.client_id}, {"$set": updated.model_dump(mode="python")})
            if updated.is_active:
                await TelemetryClientService.cache_client(updated)
            else:
                await TelemetryClientService.evict_cached_client(updated)
            logger.info("Telemetry client updated: %s -> source=%s", updated.client_id, updated.source_id)
            return updated, False, True

        client = TelemetryClientInDB(
            client_id=payload.client_id,
            source_id=payload.source_id,
            display_name=payload.display_name,
            description=payload.description,
            is_active=payload.is_active,
            api_key=payload.api_key,
            hmac_public_key=payload.hmac_public_key,
            hmac_secret=payload.hmac_secret,
            created_at=now,
            updated_at=now,
        )
        await collection.insert_one(client.model_dump(mode="python"))
        if client.is_active:
            await TelemetryClientService.cache_client(client)
        logger.info("Telemetry client created: %s -> source=%s", client.client_id, client.source_id)
        return client, True, False

    @staticmethod
    async def warm_cache() -> int:
        clients = await TelemetryClientService.list_clients(include_inactive=False)
        warmed = 0
        for client in clients:
            if await TelemetryClientService.cache_client(client):
                warmed += 1
        logger.info("Telemetry clients cache warmed: %d active clients", warmed)
        return warmed

    @staticmethod
    async def authorize_api_key(client_id: str, api_key: str) -> Optional[TelemetryClientAuthContext]:
        client = await TelemetryClientService.get_client_by_client_id(client_id)
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

    @staticmethod
    async def authorize_hmac(public_key: str, signature: str, timestamp: int, body: bytes) -> Optional[TelemetryClientAuthContext]:
        client = await TelemetryClientService.get_client_by_public_key(public_key)
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


telemetry_client_service = TelemetryClientService()

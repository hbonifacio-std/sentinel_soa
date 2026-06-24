from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from core_orchestrator.models.telemetry_client import TelemetryClientCreate
from core_orchestrator.services.telemetry_client_service import (
    CLIENT_ID_CACHE_PREFIX,
    PUBLIC_KEY_CACHE_PREFIX,
    TelemetryClientService,
)


class FakeCursor:
    def __init__(self, docs):
        self._docs = list(docs)

    def sort(self, field, direction):
        reverse = direction == -1
        self._docs = sorted(self._docs, key=lambda doc: doc.get(field), reverse=reverse)
        return self

    async def to_list(self, length=None):
        if length is None:
            return list(self._docs)
        return list(self._docs)[:length]


class FakeCollection:
    def __init__(self):
        self.docs = {}
        self.indexes = []

    async def create_index(self, field, unique=False):
        self.indexes.append((field, unique))

    async def find_one(self, query):
        for doc in self.docs.values():
            if all(doc.get(key) == value for key, value in query.items()):
                return dict(doc)
        return None

    async def insert_one(self, doc):
        self.docs[doc["client_id"]] = dict(doc)
        return SimpleNamespace(inserted_id=doc["client_id"])

    async def update_one(self, query, update):
        client_id = query["client_id"]
        current = self.docs[client_id]
        current.update(update["$set"])
        self.docs[client_id] = current
        return SimpleNamespace(modified_count=1)

    def find(self, query):
        matched = []
        for doc in self.docs.values():
            if all(doc.get(key) == value for key, value in query.items()):
                matched.append(dict(doc))
        return FakeCursor(matched)


class FakePipeline:
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.operations = []

    def set(self, key, value, ex=None):
        self.operations.append(("set", key, value))
        return self

    async def execute(self):
        for operation, key, value in self.operations:
            if operation == "set":
                self.redis_client.store[key] = value
        return True


class FakeRedis:
    def __init__(self):
        self.store = {}

    def pipeline(self):
        return FakePipeline(self)

    async def get(self, key):
        return self.store.get(key)

    async def delete(self, *keys):
        for key in keys:
            self.store.pop(key, None)


class FakeDB:
    def __init__(self):
        self.collection = FakeCollection()
        self.redis_client = FakeRedis()
        self.app_db = SimpleNamespace(authorized_telemetry_clients=self.collection)

    def get_app_db(self):
        return self.app_db


@pytest.fixture
def fake_db(monkeypatch):
    database = FakeDB()
    monkeypatch.setattr("core_orchestrator.services.telemetry_client_service.db", database)
    return database


@pytest.mark.asyncio
async def test_upsert_and_authorize_api_key_caches_client(fake_db):
    payload = TelemetryClientCreate(
        client_id="victim-app-01",
        source_id="victim-app-01",
        display_name="Vector victim",
        description="seed client",
        is_active=True,
        api_key="sentinel_local_dev_api_key_12345",
        hmac_public_key="victim-app-01",
        hmac_secret="sentinel_local_dev_hmac_secret_12345",
    )

    client, created, updated = await TelemetryClientService.upsert_client(payload, overwrite_existing=False)

    assert created is True
    assert updated is False
    assert client.client_id == "victim-app-01"

    auth_context = await TelemetryClientService.authorize_api_key(
        client_id="victim-app-01",
        api_key="sentinel_local_dev_api_key_12345",
    )

    assert auth_context is not None
    assert auth_context.source_id == "victim-app-01"
    assert f"{CLIENT_ID_CACHE_PREFIX}victim-app-01" in fake_db.redis_client.store


@pytest.mark.asyncio
async def test_authorize_hmac_uses_persisted_secret(fake_db):
    payload = TelemetryClientCreate(
        client_id="victim-app-01",
        source_id="victim-app-01",
        display_name="Vector victim",
        description="seed client",
        is_active=True,
        api_key="sentinel_local_dev_api_key_12345",
        hmac_public_key="victim-app-01",
        hmac_secret="sentinel_local_dev_hmac_secret_12345",
    )
    await TelemetryClientService.upsert_client(payload, overwrite_existing=False)

    body = b'{"source_id":"victim-app-01"}'
    timestamp = int(datetime.now(timezone.utc).timestamp())
    message = f"{timestamp}:{body.decode('utf-8')}".encode("utf-8")
    signature = hmac.new(
        payload.hmac_secret.encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()

    auth_context = await TelemetryClientService.authorize_hmac(
        public_key=payload.hmac_public_key,
        signature=signature,
        timestamp=timestamp,
        body=body,
    )

    assert auth_context is not None
    assert auth_context.client_id == payload.client_id
    assert f"{PUBLIC_KEY_CACHE_PREFIX}{payload.hmac_public_key}" in fake_db.redis_client.store


@pytest.mark.asyncio
async def test_warm_cache_only_includes_active_clients(fake_db):
    active_payload = TelemetryClientCreate(
        client_id="active-client",
        source_id="active-source",
        display_name="Active",
        description=None,
        is_active=True,
        api_key="active_seed_key_123456",
        hmac_public_key="active-public-key",
        hmac_secret="active_hmac_secret_123456",
    )
    inactive_payload = TelemetryClientCreate(
        client_id="inactive-client",
        source_id="inactive-source",
        display_name="Inactive",
        description=None,
        is_active=False,
        api_key="inactive_seed_key_123456",
        hmac_public_key="inactive-public-key",
        hmac_secret="inactive_hmac_secret_123456",
    )

    await TelemetryClientService.upsert_client(active_payload, overwrite_existing=False)
    await TelemetryClientService.upsert_client(inactive_payload, overwrite_existing=False)

    fake_db.redis_client.store.clear()
    warmed = await TelemetryClientService.warm_cache()

    assert warmed == 1
    assert f"{CLIENT_ID_CACHE_PREFIX}active-client" in fake_db.redis_client.store
    assert f"{CLIENT_ID_CACHE_PREFIX}inactive-client" not in fake_db.redis_client.store



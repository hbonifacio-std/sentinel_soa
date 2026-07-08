"""Tests for CachingTelemetryClientRepository."""
import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone

from core_orchestrator.infrastructure.persistence.caching_telemetry_client_repository import (
    CachingTelemetryClientRepository,
    CACHE_KEY_PREFIX_ID,
    CACHE_KEY_PREFIX_PK,
    CACHE_TTL_SECONDS,
)
from core_orchestrator.domain.models.auth.telemetry_client import (
    TelemetryClientInDB,
    TelemetryClientCreate,
)


def _make_client(**kwargs) -> TelemetryClientInDB:
    defaults = dict(
        client_id="client-1",
        source_id="src-1",
        display_name="Client One",
        api_key="api-key-key-key-key",
        hmac_public_key="pubkey-1",
        hmac_secret="secret-secret-secret",
        is_active=True,
    )
    defaults.update(kwargs)
    return TelemetryClientInDB(**defaults)


@pytest.fixture
def mock_primary():
    return AsyncMock()


@pytest.fixture
def mock_cache():
    return AsyncMock()


@pytest.fixture
def repo(mock_primary, mock_cache):
    return CachingTelemetryClientRepository(
        primary_repository=mock_primary,
        cache=mock_cache,
    )


# ──────────────────────────────────────────────────────────────────────────────
# get_by_client_id
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_by_client_id_cache_hit(repo, mock_cache, mock_primary):
    client = _make_client()
    mock_cache.get.return_value = client.model_dump_json()

    result = await repo.get_by_client_id("client-1")

    assert result.client_id == "client-1"
    mock_primary.get_by_client_id.assert_not_called()


@pytest.mark.asyncio
async def test_get_by_client_id_cache_hit_inactive_excluded(repo, mock_cache, mock_primary):
    client = _make_client(is_active=False)
    mock_cache.get.return_value = client.model_dump_json()
    mock_primary.get_by_client_id.return_value = None

    result = await repo.get_by_client_id("client-1", include_inactive=False)

    assert result is None
    mock_primary.get_by_client_id.assert_called_once_with("client-1", False)


@pytest.mark.asyncio
async def test_get_by_client_id_cache_hit_inactive_included(repo, mock_cache, mock_primary):
    client = _make_client(is_active=False)
    mock_cache.get.return_value = client.model_dump_json()

    result = await repo.get_by_client_id("client-1", include_inactive=True)

    assert result is not None
    assert result.client_id == "client-1"


@pytest.mark.asyncio
async def test_get_by_client_id_cache_miss_populates_cache(repo, mock_cache, mock_primary):
    client = _make_client()
    mock_cache.get.return_value = None
    mock_primary.get_by_client_id.return_value = client

    result = await repo.get_by_client_id("client-1")

    assert result.client_id == "client-1"
    assert mock_cache.set.call_count == 2


@pytest.mark.asyncio
async def test_get_by_client_id_cache_miss_not_found(repo, mock_cache, mock_primary):
    mock_cache.get.return_value = None
    mock_primary.get_by_client_id.return_value = None

    result = await repo.get_by_client_id("nonexistent")

    assert result is None
    mock_cache.set.assert_not_called()


# ──────────────────────────────────────────────────────────────────────────────
# get_by_public_key
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_by_public_key_cache_hit(repo, mock_cache, mock_primary):
    client = _make_client()
    mock_cache.get.return_value = client.model_dump_json()

    result = await repo.get_by_public_key("pubkey-1")

    assert result.hmac_public_key == "pubkey-1"
    mock_primary.get_by_public_key.assert_not_called()


@pytest.mark.asyncio
async def test_get_by_public_key_cache_miss_populates_cache(repo, mock_cache, mock_primary):
    client = _make_client()
    mock_cache.get.return_value = None
    mock_primary.get_by_public_key.return_value = client

    result = await repo.get_by_public_key("pubkey-1")

    assert result.client_id == "client-1"
    assert mock_cache.set.call_count == 2


@pytest.mark.asyncio
async def test_get_by_public_key_cache_miss_not_found(repo, mock_cache, mock_primary):
    mock_cache.get.return_value = None
    mock_primary.get_by_public_key.return_value = None

    result = await repo.get_by_public_key("nonexistent-pk")

    assert result is None
    mock_cache.set.assert_not_called()


# ──────────────────────────────────────────────────────────────────────────────
# get (delegates to get_by_client_id)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_delegates_to_get_by_client_id(repo, mock_cache, mock_primary):
    client = _make_client()
    mock_cache.get.return_value = client.model_dump_json()

    result = await repo.get("client-1")

    assert result.client_id == "client-1"


# ──────────────────────────────────────────────────────────────────────────────
# create / list_all (pass-through)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_passes_through(repo, mock_primary):
    client = _make_client()
    mock_primary.create.return_value = client
    create_payload = MagicMock(spec=TelemetryClientCreate)

    result = await repo.create(create_payload)

    mock_primary.create.assert_called_once_with(create_payload)
    assert result.client_id == "client-1"


@pytest.mark.asyncio
async def test_list_all_passes_through(repo, mock_primary):
    clients = [_make_client()]
    mock_primary.list_all.return_value = clients

    result = await repo.list_all(include_inactive=True)

    mock_primary.list_all.assert_called_once_with(True)
    assert len(result) == 1


# ──────────────────────────────────────────────────────────────────────────────
# upsert (invalidates cache)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_upsert_invalidates_cache(repo, mock_primary, mock_cache):
    client = _make_client()
    mock_primary.upsert.return_value = (client, True, False)
    create_payload = MagicMock(spec=TelemetryClientCreate)

    result_client, created, updated = await repo.upsert(create_payload, overwrite_existing=False)

    assert created is True
    assert mock_cache.delete.call_count == 2

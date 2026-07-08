"""
Tests for CacheService (infrastructure/cache/cache_service.py).
All Redis operations are mocked.
"""
import json
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_redis():
    r = AsyncMock()
    r.get = AsyncMock(return_value=None)
    r.set = AsyncMock(return_value=True)
    r.delete = AsyncMock(return_value=3)
    r.ttl = AsyncMock(return_value=300)
    r.exists = AsyncMock(return_value=0)
    r.lock = MagicMock()
    # pipeline as async context manager
    pipe = AsyncMock()
    pipe.__aenter__ = AsyncMock(return_value=pipe)
    pipe.__aexit__ = AsyncMock(return_value=False)
    pipe.set = AsyncMock()
    pipe.rpush = AsyncMock()
    pipe.expire = AsyncMock()
    pipe.execute = AsyncMock(return_value=[True, True, True])
    r.pipeline = MagicMock(return_value=pipe)
    return r, pipe


@pytest.fixture
def cache_service(mock_redis):
    r, pipe = mock_redis
    db_manager = MagicMock()
    db_manager.redis_client = r
    from core_orchestrator.infrastructure.cache.cache_service import CacheService
    return CacheService(db_manager), r, pipe


@pytest.fixture
def cache_service_no_redis():
    db_manager = MagicMock()
    db_manager.redis_client = None
    from core_orchestrator.infrastructure.cache.cache_service import CacheService
    return CacheService(db_manager)


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------
class TestCacheServiceGet:
    @pytest.mark.asyncio
    async def test_get_returns_decoded_value(self, cache_service):
        svc, r, _ = cache_service
        r.get.return_value = b"hello"
        result = await svc.get("mykey")
        assert result == "hello"

    @pytest.mark.asyncio
    async def test_get_returns_none_when_missing(self, cache_service):
        svc, r, _ = cache_service
        r.get.return_value = None
        result = await svc.get("missing")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_returns_none_when_no_redis(self, cache_service_no_redis):
        result = await cache_service_no_redis.get("key")
        assert result is None


# ---------------------------------------------------------------------------
# set
# ---------------------------------------------------------------------------
class TestCacheServiceSet:
    @pytest.mark.asyncio
    async def test_set_calls_redis_with_expiry(self, cache_service):
        svc, r, _ = cache_service
        await svc.set("k", "v", 60)
        r.set.assert_awaited_once_with("k", "v", ex=60)

    @pytest.mark.asyncio
    async def test_set_does_nothing_when_no_redis(self, cache_service_no_redis):
        # Should not raise
        await cache_service_no_redis.set("k", "v", 60)


# ---------------------------------------------------------------------------
# get_ttl
# ---------------------------------------------------------------------------
class TestCacheServiceGetTtl:
    @pytest.mark.asyncio
    async def test_get_ttl_returns_value(self, cache_service):
        svc, r, _ = cache_service
        r.ttl.return_value = 120
        result = await svc.get_ttl("k")
        assert result == 120

    @pytest.mark.asyncio
    async def test_get_ttl_returns_minus_2_when_no_redis(self, cache_service_no_redis):
        result = await cache_service_no_redis.get_ttl("k")
        assert result == -2


# ---------------------------------------------------------------------------
# invalidate_rules_cache
# ---------------------------------------------------------------------------
class TestInvalidateRulesCache:
    @pytest.mark.asyncio
    async def test_invalidate_deletes_keys(self, cache_service):
        svc, r, _ = cache_service
        result = await svc.invalidate_rules_cache()
        assert result is True
        r.delete.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_invalidate_returns_false_when_no_redis(self, cache_service_no_redis):
        result = await cache_service_no_redis.invalidate_rules_cache()
        assert result is False


# ---------------------------------------------------------------------------
# get_client_by_id
# ---------------------------------------------------------------------------
class TestGetClientById:
    @pytest.mark.asyncio
    async def test_get_client_by_id_returns_namespace(self, cache_service):
        svc, r, _ = cache_service
        r.get.return_value = json.dumps({"id": "c1", "name": "TestClient"}).encode()
        result = await svc.get_client_by_id("c1")
        assert result is not None
        assert result.id == "c1"
        assert result.name == "TestClient"

    @pytest.mark.asyncio
    async def test_get_client_by_id_returns_none_when_missing(self, cache_service):
        svc, r, _ = cache_service
        r.get.return_value = None
        result = await svc.get_client_by_id("unknown")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_client_by_id_returns_none_when_no_redis(self, cache_service_no_redis):
        result = await cache_service_no_redis.get_client_by_id("c1")
        assert result is None


# ---------------------------------------------------------------------------
# lock
# ---------------------------------------------------------------------------
class TestLock:
    def test_lock_returns_redis_lock(self, cache_service):
        svc, r, _ = cache_service
        lock_mock = MagicMock()
        r.lock.return_value = lock_mock
        result = svc.lock("my-lock", timeout=10)
        r.lock.assert_called_once_with("my-lock", timeout=10)
        assert result is lock_mock

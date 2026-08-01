import pytest
from unittest.mock import AsyncMock, MagicMock, Mock
from datetime import datetime, timezone, timedelta
import json
from types import SimpleNamespace
from core_orchestrator.infrastructure.cache.redis_cache import RedisCacheRepository
from core_orchestrator.infrastructure.cache.redis_token_blacklist_repository import RedisTokenBlacklistRepositoryPort
from core_orchestrator.infrastructure.cache.redis_rules_bundle_cache import RedisRulesBundleCache
from core_orchestrator.infrastructure.cache.redis_telemetry_window_cache import RedisTelemetryWindowCache
from core_orchestrator.infrastructure.cache.cache_service import CacheService
from core_orchestrator.domain.entities.rule_engine.rules import RulesBundle

@pytest.fixture
def mock_redis():
    r = AsyncMock()
    # Pipeline mock setup
    pipe = AsyncMock()
    pipe.execute = AsyncMock(return_value=[b"dummy_val", True])
    r.pipeline = Mock(return_value=pipe)
    return r

@pytest.fixture
def mock_db_manager(mock_redis):
    manager = MagicMock()
    manager.redis_client = mock_redis
    return manager

@pytest.mark.asyncio
async def test_redis_cache(mock_redis):
    cache = RedisCacheRepository(mock_redis)
    
    mock_redis.get.return_value = b"val"
    assert await cache.get("key") == b"val"
    
    await cache.set("key", "val", 10)
    mock_redis.set.assert_called_once_with("key", "val", ex=10)
    
    await cache.delete("key")
    mock_redis.delete.assert_called_once_with("key")

@pytest.mark.asyncio
async def test_redis_cache_disconnected():
    cache = RedisCacheRepository(None)
    assert await cache.get("key") is None
    await cache.set("key", "val")
    await cache.delete("key")

@pytest.mark.asyncio
async def test_redis_token_blacklist(mock_redis):
    repo = RedisTokenBlacklistRepositoryPort(mock_redis)
    
    # Add to blacklist
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=100)
    await repo.add_to_blacklist("jti-1", expires_at)
    mock_redis.set.assert_called_once()
    
    # Already expired
    mock_redis.set.reset_mock()
    await repo.add_to_blacklist("jti-1", datetime.now(timezone.utc) - timedelta(seconds=10))
    mock_redis.set.assert_not_called()
    
    # Is blacklisted
    mock_redis.exists.return_value = 1
    assert await repo.is_blacklisted("jti-1") is True
    assert await repo.is_blacklisted(None) is False

@pytest.mark.asyncio
async def test_redis_telemetry_window_cache(mock_redis):
    cache = RedisTelemetryWindowCache(mock_redis)
    
    # Add to window
    await cache.add_to_window("win-1", "val", 10)
    # Add multiple
    await cache.add_multiple_to_window("win-1", ["val1", "val2"], 10)
    
    # Scan keys
    async def mock_scan_iter(*args, **kwargs):
        yield "key-1"
        yield "key-2"
    mock_redis.scan_iter = mock_scan_iter
    keys = await cache.get_active_window_keys("pattern")
    assert keys == ["key-1", "key-2"]
    
    # Window size
    mock_redis.llen.return_value = 5
    assert await cache.get_window_size("win-1") == 5
    
    # Get and clear window
    mock_redis.pipeline.return_value.execute.return_value = [[b"evt1", b"evt2"], True]
    res = await cache.get_and_clear_window("win-1")
    assert res == [b"evt1", b"evt2"]

@pytest.mark.asyncio
async def test_cache_service(mock_db_manager, mock_redis):
    srv = CacheService(mock_db_manager)
    
    mock_redis.get.return_value = b"cached-val"
    assert await srv.get("key") == "cached-val"
    
    await srv.set("key", "val", 5)
    mock_redis.set.assert_called_once_with("key", "val", ex=5)
    
    mock_redis.ttl.return_value = 100
    assert await srv.get_ttl("key") == 100
    
    srv.lock("key", 5)
    mock_redis.lock.assert_called_once_with("key", timeout=5)
    
    # Rules Cache
    bundle = RulesBundle(version_hash="vhash", last_updated=datetime.now(timezone.utc))
    assert await srv.cache_rules(bundle) is True
    
    mock_redis.get.return_value = json.dumps(bundle.to_cache_dict()).encode("utf-8")
    cached = await srv.get_cached_rules()
    assert cached.version_hash == "vhash"
    
    assert await srv.invalidate_rules_cache() is True
    mock_redis.delete.assert_called_with("rules:active:all", "rules:metadata:version_hash", "rules:metadata:last_updated")
    
    # Add multiple
    mock_event = MagicMock()
    mock_event.model_dump_json.return_value = '{"evt": 1}'
    await srv.add_multiple("key", [mock_event], 10)
    
    # Get client by id
    mock_redis.get.return_value = b'{"name": "Client One"}'
    client = await srv.get_client_by_id("c-1")
    assert client.name == "Client One"

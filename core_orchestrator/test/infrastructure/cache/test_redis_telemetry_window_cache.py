"""Tests for RedisTelemetryWindowCache."""
import pytest
from unittest.mock import AsyncMock, MagicMock

from core_orchestrator.infrastructure.cache.redis_telemetry_window_cache import (
    RedisTelemetryWindowCache,
)


@pytest.fixture
def mock_redis():
    redis = AsyncMock()
    redis.pipeline = MagicMock()
    pipe = MagicMock()
    pipe.rpush = MagicMock()
    pipe.expire = MagicMock()
    pipe.execute = AsyncMock(return_value=[1, True])
    pipe.lrange = MagicMock()
    pipe.delete = MagicMock()
    redis.pipeline.return_value = pipe
    return redis, pipe


@pytest.mark.asyncio
async def test_add_to_window_skips_when_no_redis():
    cache = RedisTelemetryWindowCache(redis_client=None)
    await cache.add_to_window("key", "value", 60)  # should not raise


@pytest.mark.asyncio
async def test_add_to_window_calls_pipeline(mock_redis):
    redis, pipe = mock_redis
    cache = RedisTelemetryWindowCache(redis_client=redis)
    await cache.add_to_window("win:src-1:1234", '{"event": 1}', 60)
    pipe.rpush.assert_called_once_with("win:src-1:1234", '{"event": 1}')
    pipe.expire.assert_called_once_with("win:src-1:1234", 60)
    pipe.execute.assert_called_once()


@pytest.mark.asyncio
async def test_add_multiple_to_window_skips_when_no_redis():
    cache = RedisTelemetryWindowCache(redis_client=None)
    await cache.add_multiple_to_window("key", ["a", "b"], 60)


@pytest.mark.asyncio
async def test_add_multiple_to_window_calls_pipeline(mock_redis):
    redis, pipe = mock_redis
    cache = RedisTelemetryWindowCache(redis_client=redis)
    await cache.add_multiple_to_window("win:src-1:1234", ["a", "b"], 120)
    pipe.rpush.assert_called_once_with("win:src-1:1234", "a", "b")
    pipe.expire.assert_called_once_with("win:src-1:1234", 120)
    pipe.execute.assert_called_once()


@pytest.mark.asyncio
async def test_get_active_window_keys_returns_empty_when_no_redis():
    cache = RedisTelemetryWindowCache(redis_client=None)
    result = await cache.get_active_window_keys("win:*")
    assert result == []


@pytest.mark.asyncio
async def test_get_active_window_keys_returns_scan_results(mock_redis):
    redis, _ = mock_redis

    async def _async_iter(*args, **kwargs):
        for k in [b"win:src-1:100", b"win:src-2:200"]:
            yield k

    redis.scan_iter = MagicMock(return_value=_async_iter())
    cache = RedisTelemetryWindowCache(redis_client=redis)
    result = await cache.get_active_window_keys("win:*")
    assert len(result) == 2


@pytest.mark.asyncio
async def test_get_window_size_returns_zero_when_no_redis():
    cache = RedisTelemetryWindowCache(redis_client=None)
    result = await cache.get_window_size("any-key")
    assert result == 0


@pytest.mark.asyncio
async def test_get_window_size_returns_zero_for_empty_key():
    cache = RedisTelemetryWindowCache(redis_client=AsyncMock())
    result = await cache.get_window_size("")
    assert result == 0


@pytest.mark.asyncio
async def test_get_window_size_calls_llen(mock_redis):
    redis, _ = mock_redis
    redis.llen.return_value = 5
    cache = RedisTelemetryWindowCache(redis_client=redis)
    result = await cache.get_window_size("win:src-1:100")
    assert result == 5


@pytest.mark.asyncio
async def test_get_and_clear_window_returns_none_when_no_redis():
    cache = RedisTelemetryWindowCache(redis_client=None)
    result = await cache.get_and_clear_window("key")
    assert result is None


@pytest.mark.asyncio
async def test_get_and_clear_window_returns_events(mock_redis):
    redis, pipe = mock_redis
    events = [b'{"event":1}', b'{"event":2}']
    pipe.execute.return_value = [events, 1]
    cache = RedisTelemetryWindowCache(redis_client=redis)
    result = await cache.get_and_clear_window("win:src-1:100")
    assert result == events


@pytest.mark.asyncio
async def test_get_and_clear_window_returns_none_for_empty(mock_redis):
    redis, pipe = mock_redis
    pipe.execute.return_value = [[], 0]
    cache = RedisTelemetryWindowCache(redis_client=redis)
    result = await cache.get_and_clear_window("win:src-1:empty")
    assert result is None

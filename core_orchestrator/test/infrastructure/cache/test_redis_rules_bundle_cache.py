"""Tests for RedisRulesBundleCache."""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from core_orchestrator.infrastructure.cache.redis_rules_bundle_cache import (
    RedisRulesBundleCache,
    RULES_CACHE_KEY,
    RULES_VERSION_KEY,
    RULES_UPDATED_KEY,
)
from core_orchestrator.domain.models.rule_engine.rules import RulesBundle


def _make_bundle(version_hash: str = "vhash-1") -> RulesBundle:
    return RulesBundle(
        malicious_ua_keywords={"sqlmap": 30},
        sensitive_uris={"/admin": 50},
        sql_injection_patterns=["select *"],
        path_traversal_patterns=["../etc"],
        version_hash=version_hash,
        last_updated=datetime.now(timezone.utc),
    )


@pytest.fixture
def mock_redis():
    redis = AsyncMock()
    redis.pipeline = MagicMock()
    pipe = AsyncMock()
    pipe.__aenter__ = AsyncMock(return_value=pipe)
    pipe.__aexit__ = AsyncMock(return_value=False)
    redis.pipeline.return_value = pipe
    return redis, pipe


@pytest.mark.asyncio
async def test_get_bundle_returns_none_when_no_redis():
    cache = RedisRulesBundleCache(redis_client=None)
    result = await cache.get_bundle()
    assert result is None


@pytest.mark.asyncio
async def test_get_bundle_returns_none_when_key_missing(mock_redis):
    redis, _ = mock_redis
    redis.get.return_value = None
    cache = RedisRulesBundleCache(redis_client=redis)
    result = await cache.get_bundle()
    assert result is None


@pytest.mark.asyncio
async def test_get_bundle_returns_bundle_when_key_exists(mock_redis):
    redis, _ = mock_redis
    bundle = _make_bundle()
    raw = json.dumps(bundle.to_cache_dict())
    redis.get.return_value = raw
    cache = RedisRulesBundleCache(redis_client=redis)
    result = await cache.get_bundle()
    assert result is not None
    assert result.version_hash == "vhash-1"


@pytest.mark.asyncio
async def test_store_bundle_skips_when_no_redis():
    cache = RedisRulesBundleCache(redis_client=None)
    # Should not raise
    await cache.store_bundle(_make_bundle())


@pytest.mark.asyncio
async def test_store_bundle_writes_to_pipeline(mock_redis):
    redis, pipe = mock_redis
    bundle = _make_bundle("vhash-store")
    cache = RedisRulesBundleCache(redis_client=redis)
    await cache.store_bundle(bundle)
    pipe.set.assert_called()
    pipe.execute.assert_called_once()


@pytest.mark.asyncio
async def test_store_bundle_uses_custom_ttl(mock_redis):
    redis, pipe = mock_redis
    bundle = _make_bundle()
    cache = RedisRulesBundleCache(redis_client=redis)
    await cache.store_bundle(bundle, ttl_seconds=3600)
    # Verify set was called with ex=3600
    calls = pipe.set.call_args_list
    assert any(call.kwargs.get("ex") == 3600 for call in calls)


@pytest.mark.asyncio
async def test_store_bundle_without_last_updated(mock_redis):
    redis, pipe = mock_redis
    bundle = _make_bundle()
    bundle.last_updated = None
    cache = RedisRulesBundleCache(redis_client=redis)
    # Should not raise — falls back to datetime.now()
    await cache.store_bundle(bundle)
    pipe.execute.assert_called_once()


@pytest.mark.asyncio
async def test_invalidate_bundle_skips_when_no_redis():
    cache = RedisRulesBundleCache(redis_client=None)
    await cache.invalidate_bundle()  # should not raise


@pytest.mark.asyncio
async def test_invalidate_bundle_calls_delete(mock_redis):
    redis, _ = mock_redis
    cache = RedisRulesBundleCache(redis_client=redis)
    await cache.invalidate_bundle()
    redis.delete.assert_called_once_with(
        RULES_CACHE_KEY, RULES_VERSION_KEY, RULES_UPDATED_KEY
    )

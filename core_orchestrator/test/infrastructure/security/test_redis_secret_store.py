"""
Tests for RedisSecretStore.
All tests mock DatabaseManager to avoid real Redis connections.
"""
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Fixture: build a RedisSecretStore with a fully mocked Redis client
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_redis():
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock(return_value=True)
    redis.delete = AsyncMock(return_value=1)
    redis.exists = AsyncMock(return_value=0)
    return redis


@pytest.fixture
def secret_store(mock_redis):
    """Return a RedisSecretStore whose internals are fully mocked."""
    mock_db = MagicMock()
    mock_db.redis_client = mock_redis

    with patch(
        "core_orchestrator.infrastructure.security.redis_secret_store.DatabaseManager",
        return_value=mock_db,
    ):
        from core_orchestrator.infrastructure.security.redis_secret_store import RedisSecretStore
        store = RedisSecretStore()
    return store, mock_redis


# ---------------------------------------------------------------------------
# get_secret
# ---------------------------------------------------------------------------
class TestGetSecret:
    @pytest.mark.asyncio
    async def test_get_secret_found_in_redis(self, secret_store):
        store, mock_redis = secret_store
        mock_redis.get.return_value = b"my-secret-value"
        result = await store.get_secret("some-key")
        assert result == b"my-secret-value"
        mock_redis.get.assert_awaited_once_with("secret:some-key")

    @pytest.mark.asyncio
    async def test_get_secret_not_found_returns_none(self, secret_store):
        store, mock_redis = secret_store
        mock_redis.get.return_value = None
        result = await store.get_secret("unknown-key")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_secret_fallback_victim_app(self, secret_store):
        """The hardcoded dev fallback for 'victim-app-01' must return the default secret."""
        store, mock_redis = secret_store
        mock_redis.get.return_value = None
        result = await store.get_secret("victim-app-01")
        assert result == "sentinel_sk_live_v1_KLPLxqIZWPaelBI66EUVQKv6xHAMFqP9n"


# ---------------------------------------------------------------------------
# set_secret
# ---------------------------------------------------------------------------
class TestSetSecret:
    @pytest.mark.asyncio
    async def test_set_secret_stores_correctly(self, secret_store):
        store, mock_redis = secret_store
        await store.set_secret("pub-key", "super-secret")
        mock_redis.set.assert_awaited_once_with("secret:pub-key", "super-secret")


# ---------------------------------------------------------------------------
# delete_secret
# ---------------------------------------------------------------------------
class TestDeleteSecret:
    @pytest.mark.asyncio
    async def test_delete_existing_secret_returns_true(self, secret_store):
        store, mock_redis = secret_store
        mock_redis.delete.return_value = 1
        result = await store.delete_secret("pub-key")
        assert result is True
        mock_redis.delete.assert_awaited_once_with("secret:pub-key")

    @pytest.mark.asyncio
    async def test_delete_nonexistent_secret_returns_false(self, secret_store):
        store, mock_redis = secret_store
        mock_redis.delete.return_value = 0
        result = await store.delete_secret("missing-key")
        assert result is False


# ---------------------------------------------------------------------------
# blacklist_token
# ---------------------------------------------------------------------------
class TestBlacklistToken:
    @pytest.mark.asyncio
    async def test_blacklist_valid_future_token(self, secret_store):
        store, mock_redis = secret_store
        future = datetime.now(timezone.utc) + timedelta(minutes=30)
        await store.blacklist_token("jti-abc123", future)
        mock_redis.set.assert_awaited_once()
        call_args = mock_redis.set.call_args
        assert call_args[0][0] == "blacklist:jti-abc123"
        assert call_args[0][1] == "revoked"
        assert call_args[1]["ex"] > 0

    @pytest.mark.asyncio
    async def test_blacklist_naive_datetime_gets_utc(self, secret_store):
        """Naive datetime (no tzinfo) should be treated as UTC and stored."""
        store, mock_redis = secret_store
        # Use a far future naive datetime so TTL is definitely > 0
        future = datetime.now() + timedelta(hours=24)  # naive, far future
        await store.blacklist_token("jti-naive", future)
        # Should have been stored (TTL > 0)
        mock_redis.set.assert_awaited_once()
        call_args = mock_redis.set.call_args
        assert call_args[0][0] == "blacklist:jti-naive"

    @pytest.mark.asyncio
    async def test_blacklist_already_expired_token_skipped(self, secret_store):
        """Token already expired → should NOT call redis.set."""
        store, mock_redis = secret_store
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        await store.blacklist_token("jti-old", past)
        mock_redis.set.assert_not_awaited()


# ---------------------------------------------------------------------------
# is_token_blacklisted
# ---------------------------------------------------------------------------
class TestIsTokenBlacklisted:
    @pytest.mark.asyncio
    async def test_blacklisted_token_returns_true(self, secret_store):
        store, mock_redis = secret_store
        mock_redis.exists.return_value = 1
        result = await store.is_token_blacklisted("jti-abc123")
        assert result is True
        mock_redis.exists.assert_awaited_once_with("blacklist:jti-abc123")

    @pytest.mark.asyncio
    async def test_not_blacklisted_token_returns_false(self, secret_store):
        store, mock_redis = secret_store
        mock_redis.exists.return_value = 0
        result = await store.is_token_blacklisted("jti-unknown")
        assert result is False

    @pytest.mark.asyncio
    async def test_empty_jti_returns_false_without_redis_call(self, secret_store):
        store, mock_redis = secret_store
        result = await store.is_token_blacklisted("")
        assert result is False
        mock_redis.exists.assert_not_awaited()


# ---------------------------------------------------------------------------
# Constructor — redis=None raises RuntimeError
# ---------------------------------------------------------------------------
class TestConstructor:
    def test_constructor_raises_when_redis_is_none(self):
        mock_db = MagicMock()
        mock_db.redis_client = None

        with patch(
            "core_orchestrator.infrastructure.security.redis_secret_store.DatabaseManager",
            return_value=mock_db,
        ):
            from core_orchestrator.infrastructure.security.redis_secret_store import RedisSecretStore
            with pytest.raises(RuntimeError, match="None"):
                RedisSecretStore()

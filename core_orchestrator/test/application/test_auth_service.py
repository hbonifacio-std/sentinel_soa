from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock

import pytest

from core_orchestrator.application.modules.auth_clients.services.auth_service import AuthService
from core_orchestrator.domain.models.auth.user import UserInDB


def _build_user() -> UserInDB:
    return UserInDB(
        user_id="u-1",
        username="alice",
        email="alice@example.com",
        role="admin",
        is_active=True,
        hashed_password="hashed-value",
    )


@pytest.mark.asyncio
async def test_login_issues_token_using_injected_token_service() -> None:
    user_provider = AsyncMock()
    token_blacklist_repository = AsyncMock()
    token_service = Mock()
    ttl = timedelta(minutes=20)

    user = _build_user()
    user_provider.authenticate_user.return_value = user
    token_service.create_access_token.return_value = ("jwt-token", "jti-1")
    token_service.create_refresh_token.return_value = "refresh-jwt-token"

    service = AuthService(user_provider, token_blacklist_repository, token_service, ttl)

    result = await service.login("alice", "correct-password")

    assert result == (user, "jwt-token", "refresh-jwt-token")
    token_service.create_access_token.assert_called_once()
    assert token_service.create_access_token.call_args.kwargs == {
        "user_id": "u-1",
        "username": "alice",
        "role": "admin",
        "expires_delta": ttl,
    }


@pytest.mark.asyncio
async def test_logout_blacklists_token_jti_when_present() -> None:
    user_provider = AsyncMock()
    token_blacklist_repository = AsyncMock()
    token_service = Mock()
    ttl = timedelta(minutes=15)
    token_service.get_token_jti.return_value = "jti-abc"

    service = AuthService(user_provider, token_blacklist_repository, token_service, ttl)

    before_logout = datetime.now(timezone.utc)
    await service.logout("jwt-token")

    token_blacklist_repository.add_to_blacklist.assert_called_once()
    jti, expires_at = token_blacklist_repository.add_to_blacklist.call_args.args
    assert jti == "jti-abc"
    assert expires_at > before_logout + timedelta(minutes=14)


@pytest.mark.asyncio
async def test_logout_does_not_blacklist_when_jti_missing() -> None:
    user_provider = AsyncMock()
    token_blacklist_repository = AsyncMock()
    token_service = Mock()
    token_service.get_token_jti.return_value = None

    service = AuthService(
        user_provider,
        token_blacklist_repository,
        token_service,
        timedelta(minutes=15),
    )

    await service.logout("jwt-token")

    token_blacklist_repository.add_to_blacklist.assert_not_called()


@pytest.mark.asyncio
async def test_refresh_fails_when_refresh_token_blacklisted() -> None:
    user_provider = AsyncMock()
    token_blacklist_repository = AsyncMock()
    token_service = Mock()
    token_blacklist_repository.is_blacklisted.return_value = True
    token_service.verify_refresh_token.return_value = {"sub": "u-1", "jti": "refresh-jti-1"}

    service = AuthService(
        user_provider,
        token_blacklist_repository,
        token_service,
        timedelta(minutes=15),
    )

    result = await service.refresh_access_token("refresh-jwt-token")

    assert result is None
    user_provider.get_user_by_id.assert_not_called()


@pytest.mark.asyncio
async def test_revoke_refresh_token_blacklists_refresh_jti() -> None:
    user_provider = AsyncMock()
    token_blacklist_repository = AsyncMock()
    token_service = Mock()
    exp = int((datetime.now(timezone.utc) + timedelta(days=1)).timestamp())
    token_service.verify_refresh_token.return_value = {"sub": "u-1", "jti": "refresh-jti-1", "exp": exp}

    service = AuthService(
        user_provider,
        token_blacklist_repository,
        token_service,
        timedelta(minutes=15),
    )

    await service.revoke_refresh_token("refresh-jwt-token")

    token_blacklist_repository.add_to_blacklist.assert_called_once()
    jti, _ = token_blacklist_repository.add_to_blacklist.call_args.args
    assert jti == "refresh-jti-1"

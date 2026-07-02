from unittest.mock import AsyncMock, Mock

import pytest

from core_orchestrator.application.modules.auth_clients.services.user_service import UserService
from core_orchestrator.domain.models.auth.user import UserInDB


def _build_user() -> UserInDB:
    return UserInDB(
        user_id="u-1",
        username="alice",
        email="alice@example.com",
        role="analyst",
        is_active=True,
        hashed_password="hashed-value",
    )


@pytest.mark.asyncio
async def test_authenticate_user_returns_user_with_valid_password() -> None:
    repository = AsyncMock()
    password_hasher = Mock()
    service = UserService(repository, password_hasher)
    user = _build_user()

    repository.get_by_username.return_value = user
    password_hasher.verify_password.return_value = True

    authenticated = await service.authenticate_user("alice", "correct-password")

    assert authenticated == user
    password_hasher.verify_password.assert_called_once_with("correct-password", "hashed-value")


@pytest.mark.asyncio
async def test_authenticate_user_returns_none_with_invalid_password() -> None:
    repository = AsyncMock()
    password_hasher = Mock()
    service = UserService(repository, password_hasher)
    user = _build_user()

    repository.get_by_username.return_value = user
    password_hasher.verify_password.return_value = False

    authenticated = await service.authenticate_user("alice", "wrong-password")

    assert authenticated is None
    password_hasher.verify_password.assert_called_once_with("wrong-password", "hashed-value")


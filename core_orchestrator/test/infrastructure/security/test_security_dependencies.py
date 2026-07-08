import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi import HTTPException, status
from core_orchestrator.infrastructure.security.dependencies import (
    verify_api_key_header,
    verify_hmac_signature_header,
    get_current_user,
    get_admin_user,
    get_analyst_user
)
from core_orchestrator.domain.models.auth.user import UserInDB
from core_orchestrator.domain.models.auth.telemetry_client import TelemetryClientAuthContext

@pytest.mark.asyncio
async def test_verify_api_key_header_success():
    service = AsyncMock()
    context = TelemetryClientAuthContext(client_id="client-1", source_id="src-1", display_name="Client One")
    service.authorize_api_key.return_value = context
    
    result = await verify_api_key_header(
        request=MagicMock(),
        x_sentinel_client_id="client-1",
        x_sentinel_api_key="api-key",
        telemetry_client_service=service
    )
    assert result == context

@pytest.mark.asyncio
async def test_verify_api_key_header_unauthorized():
    service = AsyncMock()
    service.authorize_api_key.return_value = None
    
    with pytest.raises(HTTPException) as exc:
        await verify_api_key_header(
            request=MagicMock(),
            x_sentinel_client_id="client-1",
            x_sentinel_api_key="api-key",
            telemetry_client_service=service
        )
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED

@pytest.mark.asyncio
async def test_verify_hmac_signature_header_success():
    service = AsyncMock()
    context = TelemetryClientAuthContext(client_id="client-1", source_id="src-1", display_name="Client One")
    service.authorize_hmac.return_value = context
    
    request = MagicMock()
    request.body = AsyncMock(return_value=b"test-body")
    
    result = await verify_hmac_signature_header(
        request=request,
        x_public_key="pub-key",
        x_signature="sig",
        x_timestamp=12345,
        telemetry_client_service=service
    )
    assert result == context

@pytest.mark.asyncio
async def test_verify_hmac_signature_header_unauthorized():
    service = AsyncMock()
    service.authorize_hmac.return_value = None
    
    request = MagicMock()
    request.body = AsyncMock(return_value=b"test-body")
    
    with pytest.raises(HTTPException) as exc:
        await verify_hmac_signature_header(
            request=request,
            x_public_key="pub-key",
            x_signature="sig",
            x_timestamp=12345,
            telemetry_client_service=service
        )
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED

@pytest.mark.asyncio
@patch("core_orchestrator.infrastructure.security.dependencies.get_token_jti")
@patch("core_orchestrator.infrastructure.security.dependencies.is_token_blacklisted")
@patch("core_orchestrator.infrastructure.security.dependencies.decode_token")
async def test_get_current_user_success(mock_decode, mock_is_blacklisted, mock_get_jti):
    mock_get_jti.return_value = "jti-123"
    mock_is_blacklisted.return_value = False
    
    token_payload = MagicMock()
    token_payload.sub = "u-1"
    mock_decode.return_value = token_payload
    
    user_service = AsyncMock()
    dummy_user = UserInDB(
        user_id="u-1",
        username="alice",
        email="alice@example.com",
        role="admin",
        is_active=True,
        hashed_password="hashed_pwd"
    )
    user_service.get_user_by_id.return_value = dummy_user
    
    result = await get_current_user(token="token", user_service=user_service)
    assert result == dummy_user

@pytest.mark.asyncio
@patch("core_orchestrator.infrastructure.security.dependencies.get_token_jti")
@patch("core_orchestrator.infrastructure.security.dependencies.is_token_blacklisted")
async def test_get_current_user_blacklisted(mock_is_blacklisted, mock_get_jti):
    mock_get_jti.return_value = "jti-123"
    mock_is_blacklisted.return_value = True
    
    user_service = AsyncMock()
    with pytest.raises(HTTPException) as exc:
        await get_current_user(token="token", user_service=user_service)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "revoked" in exc.value.detail

@pytest.mark.asyncio
async def test_get_admin_user():
    admin_user = UserInDB(
        user_id="u-1", username="admin", email="admin@example.com", role="admin", is_active=True, hashed_password=""
    )
    regular_user = UserInDB(
        user_id="u-2", username="user", email="user@example.com", role="viewer", is_active=True, hashed_password=""
    )
    
    # Success
    assert await get_admin_user(admin_user) == admin_user
    
    # Forbidden
    with pytest.raises(HTTPException) as exc:
        await get_admin_user(regular_user)
    assert exc.value.status_code == status.HTTP_403_FORBIDDEN

@pytest.mark.asyncio
async def test_get_analyst_user():
    analyst_user = UserInDB(
        user_id="u-1", username="analyst", email="analyst@example.com", role="analyst", is_active=True, hashed_password=""
    )
    regular_user = UserInDB(
        user_id="u-2", username="user", email="user@example.com", role="viewer", is_active=True, hashed_password=""
    )
    
    # Success
    assert await get_analyst_user(analyst_user) == analyst_user
    
    # Forbidden
    with pytest.raises(HTTPException) as exc:
        await get_analyst_user(regular_user)
    assert exc.value.status_code == status.HTTP_403_FORBIDDEN

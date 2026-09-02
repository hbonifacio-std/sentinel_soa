import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime, timezone
from core_orchestrator.infrastructure.adapters.security.jwt_utils import (
    verify_hmac_signature,
    create_access_token,
    decode_token,
    get_token_jti,
    blacklist_token,
    is_token_blacklisted
)
from core_orchestrator.infrastructure.config.config import orchestrator_settings_deprecated as settings

def test_verify_hmac_signature():
    # Valid HMAC signature
    body = b"test-body"
    timestamp = int(datetime.now(timezone.utc).timestamp())
    public_key = "pub-key"
    secret = "secret-key"
    
    import hmac
    import hashlib
    message = f"{timestamp}:{body.decode('utf-8')}".encode('utf-8')
    sig = hmac.new(secret.encode('utf-8'), message, hashlib.sha256).hexdigest()
    
    redis_secrets_mock = {public_key: secret}
    
    assert verify_hmac_signature(body, sig, public_key, timestamp, redis_secrets_mock) is True
    
    # Replay window check
    old_timestamp = timestamp - (settings.hmac_replay_window_seconds + 10)
    assert verify_hmac_signature(body, sig, public_key, old_timestamp, redis_secrets_mock) is False
    
    # Missing secret check
    assert verify_hmac_signature(body, sig, "unknown-key", timestamp, redis_secrets_mock) is False
    
    # Invalid signature check
    assert verify_hmac_signature(body, "invalid-sig", public_key, timestamp, redis_secrets_mock) is False

def test_create_and_decode_jwt():
    user_id = "user-123"
    username = "test-user"
    role = "admin"
    
    token, jti = create_access_token(user_id, username, role)
    assert token is not None
    assert jti is not None
    
    payload = decode_token(token)
    assert payload is not None
    assert payload.sub == user_id
    assert payload.username == username
    assert payload.role == role
    assert payload.jti == jti
    
    # Extract jti directly
    extracted_jti = get_token_jti(token)
    assert extracted_jti == jti

def test_decode_invalid_jwt():
    assert decode_token("invalid-token-string") is None
    assert get_token_jti("invalid-token-string") is None

@patch("core_orchestrator.infrastructure.security.jwt_utils.redis_secrets")
def test_blacklist_operations(mock_redis_secrets):
    jti = "test-jti-123"
    expires = datetime.now(timezone.utc)
    
    blacklist_token(jti, expires)
    mock_redis_secrets.blacklist_token.assert_called_once_with(jti, expires)

@patch("core_orchestrator.infrastructure.security.jwt_utils.redis_secrets")
@pytest.mark.asyncio
async def test_is_token_blacklisted(mock_redis_secrets):
    mock_redis_secrets.is_token_blacklisted = AsyncMock(return_value=True)
    
    assert await is_token_blacklisted("blacklisted-jti") is True
    assert await is_token_blacklisted(None) is False
    mock_redis_secrets.is_token_blacklisted.assert_called_once_with("blacklisted-jti")

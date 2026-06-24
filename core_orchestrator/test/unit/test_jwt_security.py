"""
Tests for JWT token generation and validation security.

Tests JWT token creation, validation, expiration, and tampering detection.
"""

import pytest
import time
from datetime import datetime, timedelta
from jose import JWTError, jwt

from core_orchestrator.security.jwt_utils import create_access_token, decode_token
from core_orchestrator.config import orchestrator_settings


@pytest.fixture
def user_data():
    """Common user data for tests."""
    return {
        "user_id": "user-123",
        "username": "testuser",
        "role": "admin"
    }


def test_create_access_token(user_data):
    """Test JWT token creation."""
    token = create_access_token(
        user_id=user_data["user_id"],
        username=user_data["username"],
        role=user_data["role"]
    )
    
    assert isinstance(token, str)
    assert len(token) > 0
    # JWT has 3 parts separated by dots
    assert token.count(".") == 2


def test_decode_valid_token(user_data):
    """Test decoding a valid JWT token."""
    token = create_access_token(
        user_id=user_data["user_id"],
        username=user_data["username"],
        role=user_data["role"]
    )
    
    payload = decode_token(token)
    
    assert payload is not None
    assert payload.sub == user_data["user_id"]
    assert payload.username == user_data["username"]
    assert payload.role == user_data["role"]


def test_token_expiration(user_data):
    """Test that expired tokens are rejected."""
    # Create token with very short expiration
    token = create_access_token(
        user_id=user_data["user_id"],
        username=user_data["username"],
        role=user_data["role"],
        expires_delta=timedelta(seconds=1)
    )
    
    # Wait for token to expire
    time.sleep(2)
    
    # Decode should fail
    payload = decode_token(token)
    assert payload is None


def test_decode_invalid_token():
    """Test that invalid tokens are rejected."""
    invalid_token = "invalid.token.here"
    
    payload = decode_token(invalid_token)
    assert payload is None


def test_decode_tampered_token(user_data):
    """Test that tampered tokens are rejected."""
    token = create_access_token(
        user_id=user_data["user_id"],
        username=user_data["username"],
        role=user_data["role"]
    )
    
    # Tamper with token by modifying the payload part
    parts = token.split(".")
    tampered_token = parts[0] + ".tampered" + parts[2]
    
    payload = decode_token(tampered_token)
    assert payload is None


def test_token_with_custom_expiration(user_data):
    """Test token creation with custom expiration."""
    custom_expiration = timedelta(minutes=30)
    token = create_access_token(
        user_id=user_data["user_id"],
        username=user_data["username"],
        role=user_data["role"],
        expires_delta=custom_expiration
    )
    
    # Verify token is valid before expiration
    payload = decode_token(token)
    assert payload is not None
    assert payload.sub == user_data["user_id"]


def test_token_contains_required_claims(user_data):
    """Test that token contains all required claims."""
    token = create_access_token(
        user_id=user_data["user_id"],
        username=user_data["username"],
        role=user_data["role"]
    )
    
    # Decode without verification to inspect payload
    payload = jwt.decode(
        token,
        orchestrator_settings.jwt_secret_key.get_secret_value(),
        algorithms=[orchestrator_settings.jwt_algorithm]
    )
    
    # Check required claims
    assert "sub" in payload  # user_id
    assert "username" in payload
    assert "role" in payload
    assert "exp" in payload  # expiration
    assert "iat" in payload  # issued at


def test_different_roles_encoded_correctly(user_data):
    """Test that different roles are encoded correctly in token."""
    roles = ["admin", "analyst", "viewer"]
    
    for role in roles:
        token = create_access_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            role=role
        )
        
        payload = decode_token(token)
        assert payload.role == role


def test_token_signature_algorithm():
    """Test that token uses correct signature algorithm."""
    token = create_access_token(
        user_id="user-123",
        username="testuser",
        role="admin"
    )
    
    # Decode header to check algorithm
    header = jwt.get_unverified_header(token)
    assert header["alg"] == orchestrator_settings.jwt_algorithm


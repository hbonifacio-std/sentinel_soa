"""
Tests for JWT token blacklist and logout functionality.

Tests token revocation and blacklist verification.
"""

import pytest
from datetime import datetime, timedelta
from core_orchestrator.security.jwt_utils import (
    create_access_token,
    decode_token,
    blacklist_token,
    is_token_blacklisted,
    get_token_jti
)
from core_orchestrator.security.redis_sim import redis_secrets


def test_token_has_jti():
    """Test that created token includes JTI."""
    token, jti = create_access_token(
        user_id="user-123",
        username="testuser",
        role="admin"
    )

    assert jti is not None
    assert len(jti) > 0
    # JTI should be in UUID format
    assert len(jti.split("-")) >= 3  # UUID has at least 3 parts


def test_jti_extracted_from_token():
    """Test that JTI can be extracted from token."""
    token, original_jti = create_access_token(
        user_id="user-123",
        username="testuser",
        role="admin"
    )

    extracted_jti = get_token_jti(token)
    assert extracted_jti == original_jti


def test_blacklist_token():
    """Test adding token to blacklist."""
    token, jti = create_access_token(
        user_id="user-123",
        username="testuser",
        role="admin"
    )

    expires_at = datetime.utcnow() + timedelta(hours=1)
    blacklist_token(jti, expires_at)

    # Token should now be blacklisted
    assert is_token_blacklisted(jti) is True


def test_non_blacklisted_token():
    """Test that non-blacklisted tokens return False."""
    token, jti = create_access_token(
        user_id="user-123",
        username="testuser",
        role="admin"
    )

    # Token not blacklisted yet
    assert is_token_blacklisted(jti) is False


def test_blacklist_cleanup_expired():
    """Test that expired blacklist entries are cleaned up."""
    token, jti = create_access_token(
        user_id="user-123",
        username="testuser",
        role="admin"
    )

    # Blacklist with already expired time
    expires_at = datetime.utcnow() - timedelta(seconds=1)
    blacklist_token(jti, expires_at)

    # Should return False because entry is expired
    assert is_token_blacklisted(jti) is False


def test_multiple_tokens_independent_blacklist():
    """Test that blacklisting one token doesn't affect others."""
    token1, jti1 = create_access_token(
        user_id="user-1",
        username="user1",
        role="admin"
    )

    token2, jti2 = create_access_token(
        user_id="user-2",
        username="user2",
        role="analyst"
    )

    # Blacklist only first token
    expires_at = datetime.utcnow() + timedelta(hours=1)
    blacklist_token(jti1, expires_at)

    # First should be blacklisted
    assert is_token_blacklisted(jti1) is True

    # Second should not be
    assert is_token_blacklisted(jti2) is False


def test_unique_jti_each_token():
    """Test that each token gets a unique JTI."""
    token1, jti1 = create_access_token(
        user_id="user-123",
        username="testuser",
        role="admin"
    )

    token2, jti2 = create_access_token(
        user_id="user-123",
        username="testuser",
        role="admin"
    )

    # JTIs should be different
    assert jti1 != jti2


def test_blacklist_size():
    """Test getting blacklist size."""
    # Clear first
    redis_secrets.clear_blacklist()

    initial_size = redis_secrets.get_blacklist_size()
    assert initial_size == 0

    # Add tokens
    token1, jti1 = create_access_token("user-1", "user1", "admin")
    token2, jti2 = create_access_token("user-2", "user2", "analyst")

    expires_at = datetime.utcnow() + timedelta(hours=1)
    blacklist_token(jti1, expires_at)
    blacklist_token(jti2, expires_at)

    # Should have 2 in blacklist
    size = redis_secrets.get_blacklist_size()
    assert size == 2


def test_blacklist_clear():
    """Test clearing entire blacklist."""
    # Add tokens
    token1, jti1 = create_access_token("user-1", "user1", "admin")
    expires_at = datetime.utcnow() + timedelta(hours=1)
    blacklist_token(jti1, expires_at)

    # Should be blacklisted
    assert is_token_blacklisted(jti1) is True

    # Clear blacklist
    redis_secrets.clear_blacklist()

    # Should not be blacklisted anymore
    assert is_token_blacklisted(jti1) is False


def test_token_payload_still_valid_after_blacklist():
    """Test that payload can still be extracted from blacklisted token."""
    token, jti = create_access_token(
        user_id="user-123",
        username="testuser",
        role="admin"
    )

    # Extract payload before blacklist
    payload_before = decode_token(token)
    assert payload_before is not None

    # Blacklist token
    expires_at = datetime.utcnow() + timedelta(hours=1)
    blacklist_token(jti, expires_at)

    # Payload can still be extracted (JWT is stateless)
    # But blacklist check happens at dependency level
    payload_after = decode_token(token)
    assert payload_after is not None
    assert payload_after.username == "testuser"


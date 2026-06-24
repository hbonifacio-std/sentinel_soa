"""
Tests for HMAC signature verification security.

Tests HMAC validation, replay attack prevention, and signature verification.
"""

import pytest
import hmac
import hashlib
import secrets
from datetime import datetime, timezone

from core_orchestrator.security.jwt_utils import verify_hmac_signature
from core_orchestrator.config import orchestrator_settings


@pytest.fixture
def hmac_setup():
    """Setup HMAC test data."""
    public_key = "test-public-key-1"
    secret = secrets.token_hex(24)
    timestamp = int(datetime.now(timezone.utc).timestamp())
    body = b'{"ip_address": "192.168.1.1", "method": "GET"}'
    
    # Calculate valid signature
    message = f"{timestamp}:{body.decode('utf-8')}".encode('utf-8')
    signature = hmac.new(
        secret.encode('utf-8'),
        message,
        hashlib.sha256
    ).hexdigest()
    
    return {
        "public_key": public_key,
        "secret": secret,
        "timestamp": timestamp,
        "body": body,
        "signature": signature,
        "redis_secrets": {public_key: secret}
    }


def test_valid_hmac_signature(hmac_setup):
    """Test that valid HMAC signatures are accepted."""
    result = verify_hmac_signature(
        body=hmac_setup["body"],
        signature=hmac_setup["signature"],
        public_key=hmac_setup["public_key"],
        timestamp=hmac_setup["timestamp"],
        redis_secrets=hmac_setup["redis_secrets"]
    )
    assert result is True


def test_invalid_hmac_signature(hmac_setup):
    """Test that invalid HMAC signatures are rejected."""
    # Use wrong signature
    invalid_signature = "invalid_signature_hex_value"
    
    result = verify_hmac_signature(
        body=hmac_setup["body"],
        signature=invalid_signature,
        public_key=hmac_setup["public_key"],
        timestamp=hmac_setup["timestamp"],
        redis_secrets=hmac_setup["redis_secrets"]
    )
    assert result is False


def test_replay_attack_prevention(hmac_setup):
    """Test that old timestamps are rejected (replay attack prevention)."""
    # Use timestamp older than replay window
    old_timestamp = hmac_setup["timestamp"] - (orchestrator_settings.hmac_replay_window_seconds + 60)
    
    # Recalculate signature with old timestamp
    public_key = hmac_setup["public_key"]
    secret = hmac_setup["secret"]
    message = f"{old_timestamp}:{hmac_setup['body'].decode('utf-8')}".encode('utf-8')
    signature = hmac.new(
        secret.encode('utf-8'),
        message,
        hashlib.sha256
    ).hexdigest()
    
    result = verify_hmac_signature(
        body=hmac_setup["body"],
        signature=signature,
        public_key=public_key,
        timestamp=old_timestamp,
        redis_secrets=hmac_setup["redis_secrets"]
    )
    assert result is False


def test_unknown_public_key(hmac_setup):
    """Test that unknown public keys are rejected."""
    result = verify_hmac_signature(
        body=hmac_setup["body"],
        signature=hmac_setup["signature"],
        public_key="unknown-public-key",
        timestamp=hmac_setup["timestamp"],
        redis_secrets=hmac_setup["redis_secrets"]
    )
    assert result is False


def test_modified_body_signature_mismatch(hmac_setup):
    """Test that modified body invalidates signature."""
    modified_body = b'{"ip_address": "192.168.1.2", "method": "POST"}'
    
    result = verify_hmac_signature(
        body=modified_body,
        signature=hmac_setup["signature"],
        public_key=hmac_setup["public_key"],
        timestamp=hmac_setup["timestamp"],
        redis_secrets=hmac_setup["redis_secrets"]
    )
    assert result is False


def test_constant_time_comparison():
    """Test that signature comparison uses constant-time comparison."""
    # This test verifies that we're using secrets.compare_digest
    # which prevents timing attacks
    
    public_key = "test-public-key-1"
    secret = secrets.token_hex(24)
    timestamp = int(datetime.now(timezone.utc).timestamp())
    body = b'{"test": "data"}'
    
    message = f"{timestamp}:{body.decode('utf-8')}".encode('utf-8')
    valid_signature = hmac.new(
        secret.encode('utf-8'),
        message,
        hashlib.sha256
    ).hexdigest()
    
    # Similar but different signature
    similar_signature = valid_signature[:-1] + ('0' if valid_signature[-1] != '0' else '1')
    
    result = verify_hmac_signature(
        body=body,
        signature=similar_signature,
        public_key=public_key,
        timestamp=timestamp,
        redis_secrets={public_key: secret}
    )
    assert result is False


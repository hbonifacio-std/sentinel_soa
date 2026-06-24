"""
Security utilities for HMAC and JWT token handling.

Provides functions for HMAC signature verification and JWT token creation/validation
with support for token blacklist (logout functionality).
"""

import hmac
import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from core_orchestrator.config import orchestrator_settings
from core_orchestrator.models.user import TokenPayload


logger = logging.getLogger("core_orchestrator.security.jwt_utils")


# ============================================================================
# HMAC Signature Verification
# ============================================================================

def verify_hmac_signature(
    body: bytes,
    signature: str,
    public_key: str,
    timestamp: int,
    redis_secrets: dict[str, str],
) -> bool:
    """
    Verify HMAC-SHA256 signature for incoming telemetry.

    Args:
        body: Raw request body bytes
        signature: Signature from X-Signature header
        public_key: Public key from X-Public-Key header
        timestamp: Timestamp from X-Timestamp header
        redis_secrets: Dict mapping public_key to secret (simulated Redis)

    Returns:
        True if signature is valid, False otherwise
    """
    # Step 1: Verify timestamp is within replay window
    now = datetime.now(timezone.utc).timestamp()
    if abs(now - timestamp) > orchestrator_settings.hmac_replay_window_seconds:
        logger.warning(
            f"HMAC timestamp out of replay window: now={now}, provided={timestamp}, "
            f"window={orchestrator_settings.hmac_replay_window_seconds}s"
        )
        return False

    # Step 2: Retrieve secret from redis_secrets (simulated Redis)
    secret = redis_secrets.get(public_key)
    if not secret:
        logger.warning(f"Public key not found in Redis secrets: {public_key}")
        return False

    # Step 3: Calculate expected HMAC-SHA256
    message = f"{timestamp}:{body.decode('utf-8', errors='ignore')}".encode('utf-8')
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        message,
        hashlib.sha256
    ).hexdigest()

    # Step 4: Compare signatures using constant-time comparison
    is_valid = secrets.compare_digest(signature, expected_signature)

    if not is_valid:
        logger.warning(f"HMAC signature mismatch for public_key: {public_key}")

    return is_valid


# ============================================================================
# JWT Token Generation and Validation
# ============================================================================

def create_access_token(
    user_id: str,
    username: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> tuple[str, str]:
    """
    Create a JWT access token with unique JTI for logout support.
    
    Args:
        user_id: User identifier
        username: Username
        role: User role (admin, analyst, viewer)
        expires_delta: Optional custom expiration delta
    
    Returns:
        Tuple of (encoded_jwt_token, jti_id_for_blacklist)
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=orchestrator_settings.jwt_expiration_minutes)
    
    expire = datetime.now(timezone.utc) + expires_delta
    jti = str(uuid.uuid4())  # Unique JWT ID for this token instance
    
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": jti,  # JWT ID for revocation/blacklist
    }
    
    encoded_jwt = jwt.encode(
        payload,
        orchestrator_settings.jwt_secret_key.get_secret_value(),
        algorithm=orchestrator_settings.jwt_algorithm,
    )
    
    logger.info(f"Token created for user: {username} (role: {role}, jti: {jti})")
    return encoded_jwt, jti


def decode_token(token: str) -> Optional[TokenPayload]:
    """
    Decode and validate JWT token.
    
    Args:
        token: JWT token string
    
    Returns:
        TokenPayload if valid, None otherwise
    """
    try:
        payload = jwt.decode(
            token,
            orchestrator_settings.jwt_secret_key.get_secret_value(),
            algorithms=[orchestrator_settings.jwt_algorithm],
        )
        token_data = TokenPayload(
            sub=payload.get("sub"),
            username=payload.get("username"),
            role=payload.get("role"),
            exp=int(payload.get("exp", 0)),
            jti=payload.get("jti"),
        )
        return token_data
    except JWTError as e:
        logger.warning(f"Invalid token: {e}")
        return None


def get_token_jti(token: str) -> Optional[str]:
    """
    Extract JWT ID (jti) from token without validation.
    Useful for blacklisting without full validation.
    
    Args:
        token: JWT token string
    
    Returns:
        JTI if present, None otherwise
    """
    token_data = decode_token(token)
    if not token_data:
        return None
    return token_data.jti


def blacklist_token(jti: str, expires_at: datetime) -> None:
    """
    Add token to blacklist (revocation list).
    
    Args:
        jti: JWT ID to blacklist
        expires_at: When the token expires
    """
    from core_orchestrator.security.redis_sim import redis_secrets
    redis_secrets.blacklist_token(jti, expires_at)
    logger.info(f"Token added to blacklist: {jti}")


def is_token_blacklisted(jti: Optional[str]) -> bool:
    """
    Check if token has been blacklisted.
    
    Args:
        jti: JWT ID to check
    
    Returns:
        True if blacklisted, False otherwise
    """
    if not jti:
        return False
    
    from core_orchestrator.security.redis_sim import redis_secrets
    return redis_secrets.is_token_blacklisted(jti)



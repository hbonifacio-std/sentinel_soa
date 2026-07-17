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
from core_orchestrator.infrastructure.security.redis_secret_store import redis_secrets

# 1. Importamos PyJWT
import jwt

from core_orchestrator.infrastructure.config.config import orchestrator_settings as settings
from core_orchestrator.domain.models.auth.user import TokenPayload

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
    """
    # Step 1: Verify timestamp is within replay window
    now = datetime.now(timezone.utc).timestamp()
    if abs(now - timestamp) > settings.hmac_replay_window_seconds:
        logger.warning(
            f"HMAC timestamp out of replay window: now={now}, provided={timestamp}, "
            f"window={settings.hmac_replay_window_seconds}s"
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
# JWT Token Generation and Validation (Updated for PyJWT)
# ============================================================================

def create_access_token(
        user_id: str,
        username: str,
        role: str,
        expires_delta: Optional[timedelta] = None,
) -> tuple[str, str]:
    """
    Create a JWT access token with unique JTI for logout support.
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.jwt_expiration_minutes)

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

    # PyJWT maneja objetos datetime nativos para 'exp' e 'iat' perfectamente
    encoded_jwt = jwt.encode(
        payload,
        settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )

    logger.info(f"Token created for user: {username} (role: {role}, jti: {jti})")
    return encoded_jwt, jti


def create_refresh_token(
        user_id: str,
        expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a JWT refresh token (longer-lived than access token).
    Used to obtain new access tokens without re-authenticating.
    """
    if expires_delta is None:
        expires_delta = timedelta(days=7)  # Default 7 days

    expire = datetime.now(timezone.utc) + expires_delta
    jti = str(uuid.uuid4())

    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": jti,
    }

    encoded_jwt = jwt.encode(
        payload,
        settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )

    logger.info(f"Refresh token created for user: {user_id} (jti: {jti})")
    return encoded_jwt


def verify_refresh_token(token: str) -> Optional[dict]:
    """
    Verify and decode refresh token. Returns payload if valid, None otherwise.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
        )
        
        # Verify it's a refresh token
        if payload.get("type") != "refresh":
            logger.warning("Token is not a refresh token")
            return None
            
        return payload
    except jwt.PyJWTError as e:
        logger.warning(f"Invalid refresh token: {e}")
        return None


def decode_token(token: str) -> Optional[TokenPayload]:
    """
    Decode and validate JWT token using PyJWT.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
        )
        token_data = TokenPayload(
            sub=payload.get("sub"),
            username=payload.get("username"),
            role=payload.get("role"),
            exp=int(payload.get("exp", 0)),
            jti=payload.get("jti"),
        )
        return token_data
    except jwt.PyJWTError as e:  # <-- Cambiado de JWTError a jwt.PyJWTError
        logger.warning(f"Invalid token: {e}")
        return None


def get_token_jti(token: str) -> Optional[str]:
    """
    Extract JWT ID (jti) from token without validation.
    """
    token_data = decode_token(token)
    if not token_data:
        return None
    return token_data.jti


def blacklist_token(jti: str, expires_at: datetime) -> None:
    """
    Add token to blacklist (revocation list).
    """
    redis_secrets.blacklist_token(jti, expires_at)
    logger.info(f"Token added to blacklist: {jti}")


async def is_token_blacklisted(jti: Optional[str]) -> bool:
    """
    Check if token has been blacklisted.
    """
    if not jti:
        return False
    return await redis_secrets.is_token_blacklisted(jti)



"""
Security utilities for HMAC and JWT token handling.

Provides functions for HMAC signature verification and JWT token creation/validation
with support for token blacklist (logout functionality).
"""
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from core_orchestrator.infrastructure.dto.auth.auth_dto import TokenPayloadDto

import jwt
from core_orchestrator.infrastructure.config.config import orchestrator_settings_deprecated as settings


logger = logging.getLogger("core_orchestrator.security.jwt_utils")


def create_access_token(
        user_id: str,
        username: str,
        role: str,
        expires_delta: Optional[timedelta] = None,
) -> tuple[str, str]:
    """
    Generate a JSON Web Token (JWT) for user access and a unique identifier (JTI).

    Returns a signed JWT and a JTI string, which can be used for access control and
    identity verification. The token includes information about the user, their role,
    and the expiry time.

    Parameters:
    user_id: str
        The unique identifier of the user.
    username: str
        The username of the user.
    role: str
        The role assigned to the user (e.g., admin, regular user).
    expires_delta: Optional[timedelta]
        The amount of time after which the token will expire. Defaults to a
        predefined duration in settings if not provided.

    Returns:
    tuple[str, str]
        A tuple containing the encoded JWT and the JTI string.
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.jwt_expiration_minutes)

    expire = datetime.now(timezone.utc) + expires_delta
    jti = str(uuid.uuid4())

    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": jti
    }

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
    Generates a refresh token for a user.

    This function creates a JWT (JSON Web Token) that serves as a refresh token
    for user authentication. The token includes user-specific data, an expiration
    time, and a unique identifier, and is signed with a secret key using
    a specified algorithm.

    Args:
        user_id: The unique identifier of the user for whom the refresh token
            is generated.
        expires_delta: An optional timedelta value that specifies the duration
            until the token expires. If not provided, a default duration of 7
            days is used.

    Returns:
        A string representation of the encoded refresh token.
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
    Verifies the validity of a refresh token and decodes its payload.

    Decodes the provided JSON Web Token (JWT) and ensures it corresponds to a refresh
    token type. If the token is invalid, malformed, expired, or not of type "refresh",
    the function returns None. Otherwise, the payload is returned after successful
    validation.

    Parameters:
    token: str
        The refresh token to be decoded and verified. Must be a JSON Web Token
        conforming to the expected format and secret.

    Returns:
    Optional[dict]
        The payload of the decoded token if the token is valid and of type "refresh".
        Returns None if the token is invalid, expired, or not a refresh token.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
        )

        if payload.get("type") != "refresh":
            logger.warning("Token is not a refresh token")
            return None
            
        return payload
    except jwt.PyJWTError as e:
        logger.warning(f"Invalid refresh token: {e}")
        return None


def decode_token(token: str) -> Optional[TokenPayloadDto]:
    """
    Decodes a JWT token and extracts the payload if valid.

    This function attempts to decode a provided JWT token using the secret key and
    algorithm specified in the application settings. If the token is successfully
    decoded, it extracts the payload data and returns it as an instance of
    TokenPayloadDto. If the token is invalid or any error occurs during decoding,
    the function logs a warning and returns None.

    Args:
        token: The JWT token as a string.

    Returns:
        An instance of TokenPayloadDto contains the extracted payload data if the
        token is valid. Returns None if the token is invalid or an error occurs.

    Raises:
        Does not raise exceptions explicitly, but logs warnings for invalid tokens.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
        )
        token_data = TokenPayloadDto(
            sub=payload.get("sub"),
            username=payload.get("username"),
            role=payload.get("role"),
            exp=int(payload.get("exp", 0)),
            jti=payload.get("jti"),
        )
        return token_data
    except jwt.PyJWTError as e:
        logger.warning(f"Invalid token: {e}")
        return None


def get_token_jti(token: str) -> Optional[str]:
    """
    Extract the JTI (JWT ID) from a given token.

    This function decodes a provided JSON Web Token (JWT) to get its data payload,
    then retrieves the JTI value from the decoded payload if available. If the token
    is invalid or the JTI field is missing, the function returns None.

    Parameters:
    token (str): The JSON Web Token (JWT) from which the JTI will be extracted.

    Returns:
    Optional[str]: The JTI (JWT ID) extracted from the token, or None if the token
    is invalid or does not contain a JTI field.
    """
    token_data = decode_token(token)
    if not token_data:
        return None
    return token_data.jti
"""
FastAPI dependency providers for security.

Provides reusable dependencies for HMAC verification, JWT authentication, and RBAC.
"""

import logging
from fastapi import Depends, HTTPException, status, Header, Request
from fastapi.security import OAuth2PasswordBearer

from core_orchestrator.models.telemetry_client import TelemetryClientAuthContext
from core_orchestrator.security.jwt_utils import decode_token, is_token_blacklisted, get_token_jti
from core_orchestrator.services.user_service import UserService
from core_orchestrator.services.telemetry_client_service import telemetry_client_service
from core_orchestrator.models.user import UserInDB

logger = logging.getLogger("core_orchestrator.security.dependencies")

# OAuth2 scheme for JWT authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


async def verify_api_key_header(
        x_sentinel_client_id: str = Header(..., description="Unique Identifier for the client"),
        x_sentinel_api_key: str = Header(..., description="Secret API Key generated for the client"),
) -> TelemetryClientAuthContext:
    """
    FastAPI dependency to verify Client ID and API Key from request headers.
    Safe to use over HTTPS for high-throughput batch ingestion.

    Returns:
        str: The verified client_id to inject into the endpoint context if needed.
    """
    client_context = await telemetry_client_service.authorize_api_key(
        client_id=x_sentinel_client_id,
        api_key=x_sentinel_api_key,
    )

    if not client_context:
        logger.warning(f"Unauthorized API Key attempt for client_id: {x_sentinel_client_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Client ID or API Key"
        )

    logger.debug(f"API Key successfully verified for client: {x_sentinel_client_id}")

    return client_context
# ============================================================================
# HMAC Verification Dependency
# ============================================================================

async def verify_hmac_signature_header(
    request: Request,
    x_public_key: str = Header(..., description="Public key for HMAC verification"),
    x_signature: str = Header(..., description="HMAC-SHA256 signature"),
    x_timestamp: int = Header(..., description="Timestamp in seconds since epoch"),
) -> TelemetryClientAuthContext:
    """
    FastAPI dependency to verify HMAC signature from request headers.

    This dependency should be applied to telemetry ingestion endpoints.

    Args:
        request: FastAPI request object
        x_public_key: Public key identifier
        x_signature: HMAC-SHA256 signature (hex encoded)
        x_timestamp: Request timestamp

    Raises:
        HTTPException: If HMAC verification fails
    """
    # Get raw body from request
    body = await request.body()

    client_context = await telemetry_client_service.authorize_hmac(
        public_key=x_public_key,
        signature=x_signature,
        timestamp=x_timestamp,
        body=body,
    )

    if not client_context:
        logger.warning(f"HMAC verification failed for public_key: {x_public_key}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid HMAC signature"
        )

    logger.debug(f"HMAC signature verified for public_key: {x_public_key}")
    return client_context


# ============================================================================
# JWT Authentication Dependency
# ============================================================================

async def get_current_user(
    token: str = Depends(oauth2_scheme),
) -> UserInDB:
    """
    FastAPI dependency to get current authenticated user from JWT token.
    
    This dependency should be applied to endpoints requiring authentication.
    Also checks if token has been blacklisted (revoked via logout).
    
    Args:
        token: JWT access token from Authorization header
    
    Returns:
        Current user model
    
    Raises:
        HTTPException: If token is invalid, blacklisted, or user not found
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Check if token is blacklisted (user logged out)
    jti = get_token_jti(token)
    if is_token_blacklisted(jti):
        logger.warning(f"Attempt to use blacklisted token: {jti}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked (logged out)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Decode token
    token_data = decode_token(token)
    if not token_data:
        raise credentials_exception
    
    # Get user from database
    user = await UserService.get_user_by_id(token_data.sub)
    if not user or not user.is_active:
        raise credentials_exception
    
    logger.debug(f"User authenticated via JWT: {user.username}")
    return user


# ============================================================================
# RBAC (Role-Based Access Control) Dependencies
# ============================================================================

async def get_admin_user(
    current_user: UserInDB = Depends(get_current_user),
) -> UserInDB:
    """
    FastAPI dependency to ensure user has admin role.

    This dependency should be applied to admin-only endpoints.

    Args:
        current_user: Current authenticated user

    Returns:
        Current user if admin

    Raises:
        HTTPException: If user is not admin
    """
    if current_user.role != "admin":
        logger.warning(f"Unauthorized admin access attempt by user: {current_user.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required"
        )

    return current_user


async def get_analyst_user(
    current_user: UserInDB = Depends(get_current_user),
) -> UserInDB:
    """
    FastAPI dependency to ensure user has analyst or admin role.

    Args:
        current_user: Current authenticated user

    Returns:
        Current user if analyst/admin

    Raises:
        HTTPException: If user lacks required role
    """
    if current_user.role not in {"admin", "analyst"}:
        logger.warning(f"Unauthorized analyst access attempt by user: {current_user.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst or Admin role required"
        )

    return current_user


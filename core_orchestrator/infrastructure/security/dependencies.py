"""
FastAPI dependency providers for security.

Provides reusable dependencies for API key verification, HMAC verification, JWT authentication, and RBAC.
Unified authentication supports both tenant OAuth and telemetry client authentication.
"""
import hashlib
import hmac
import logging
from fastapi import Depends, Request, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from core_orchestrator.application.modules.auth_clients.services.telemetry_client_service import TelemetryClientService
from core_orchestrator.application.modules.auth_clients.services.tenant_service import TenantService
from core_orchestrator.application.modules.auth_clients.services.user_service import UserService
from core_orchestrator.domain.models.auth.telemetry_client import TelemetryClientAuthContext
from core_orchestrator.domain.models.auth.user import UserInDB

from core_orchestrator.infrastructure.api.dependencies import (
     get_tenant_service, get_telemetry_client_service, get_user_service
)
from core_orchestrator.infrastructure.security.jwt_utils import (
    get_token_jti, is_token_blacklisted, decode_token
)

logger = logging.getLogger("core_orchestrator.security.dependencies")

# OAuth2 scheme for JWT authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


# ============================================================================
# UNIFIED API KEY VERIFICATION (Tenant or Telemetry Client)
# ============================================================================

async def verify_api_key_header(
        x_sentinel_client_id: str = Header(alias="x-sentinel-client-id", default=None, description="Telemetry Client ID"),
        x_sentinel_api_key: str = Header(alias="x-sentinel-api-key", default=None, description="Telemetry API Key"),
        telemetry_client_service: TelemetryClientService = Depends(get_telemetry_client_service),
) -> TelemetryClientAuthContext:
    """
    API key verification for telemetry client ingestion.

    Requires both `X-Sentinel-Client-ID` and `X-Sentinel-Api-Key` headers and
    validates them against the authorized telemetry clients store.

    Returns:
        TelemetryClientAuthContext: The verified client context metadata.
    """
    if not x_sentinel_client_id or not x_sentinel_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing telemetry authentication headers"
        )

    client_context = await telemetry_client_service.authorize_api_key(
        client_id=x_sentinel_client_id,
    )
    computed_hash = hashlib.sha256(
        x_sentinel_api_key.encode("utf-8")
    ).hexdigest()
    if not client_context or hmac.compare_digest(computed_hash, client_context.api_key_hash) is False:
        logger.warning(f"Unauthorized API Key attempt for client_id: {x_sentinel_client_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Client ID or API Key"
        )

    logger.debug(f"API Key successfully verified for client: {x_sentinel_client_id}")
    return TelemetryClientAuthContext(
        client_id=client_context.client_id,
        display_name=client_context.display_name
    )


# ============================================================================
# JWT AUTHENTICATION DEPENDENCY
# ============================================================================

async def get_current_user(
        token: str = Depends(oauth2_scheme),
        user_service: UserService = Depends(get_user_service)
) -> UserInDB:
    """
    FastAPI dependency to get current authenticated user from JWT token.

    This dependency should be applied to endpoints requiring authentication.
    Also checks if token has been blacklisted (revoked via logout).
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Check if token is blacklisted (user logged out)
    jti = get_token_jti(token)
    if await is_token_blacklisted(jti):
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
    user = await user_service.get_user_by_id(token_data.sub)
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
    """
    if current_user.role not in {"admin", "analyst"}:
        logger.warning(f"Unauthorized analyst access attempt by user: {current_user.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst or Admin role required"
        )

    return current_user


async def get_analyst_user_with_client(
        current_user: UserInDB = Depends(get_analyst_user),
        tenant_service: TenantService = Depends(get_tenant_service),
) -> UserInDB:
    """Ensure the analyst/admin user is linked to an active tenant client."""
    if not current_user.client_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not assigned to any client"
        )

    tenant = await tenant_service.get_client_by_client_id(
        current_user.client_id,
        include_inactive=False,
    )
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User client is inactive or not authorized"
        )

    return current_user
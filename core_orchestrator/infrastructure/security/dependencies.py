"""
FastAPI dependency providers for security.

Provides reusable dependencies for HMAC verification, JWT authentication, and RBAC.
"""
import logging
from fastapi import Depends, Request, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

# ============================================================================
# ✨ IMPORTACIÓN DE DEPENDENCIAS CORE (Arquitectura Hexagonal)
# ============================================================================
# Asegúrate de que la ruta de importación coincida con la estructura de tu proyecto.
# Si tu archivo anterior se llama 'dependencies.py' en la raíz de 'core_orchestrator', sería así:

from core_orchestrator.application.services.telemetry_client_service import TelemetryClientService
from core_orchestrator.application.services.user_service import UserService
from core_orchestrator.domain.models.telemetry_client import TelemetryClientAuthContext
from core_orchestrator.domain.models.user import UserInDB
from core_orchestrator.infrastructure.api.dependencies import get_telemetry_client_service, get_user_service
from core_orchestrator.infrastructure.security.jwt_utils import get_token_jti, is_token_blacklisted, decode_token

# Nota: Asegúrate de tener importados tus modelos/contextos o ajusta según tus archivos:
# from core_orchestrator.domain.models import TelemetryClientAuthContext, UserInDB
# from core_orchestrator.infrastructure.security.jwt import get_token_jti, is_token_blacklisted, decode_token
# from core_orchestrator.application.services.user_service import UserService

logger = logging.getLogger("core_orchestrator.security.dependencies")

# OAuth2 scheme for JWT authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


# ============================================================================
# API Key Verification Dependency
# ============================================================================

async def verify_api_key_header(
        request: Request,
        x_sentinel_client_id: str = Header(..., description="Unique Identifier for the client"),
        x_sentinel_api_key: str = Header(..., description="Secret API Key generated for the client"),
        # ✨ Inyección nativa del servicio a través de la factoría de dependencias
        telemetry_client_service: TelemetryClientService = Depends(get_telemetry_client_service)
) -> TelemetryClientAuthContext:
    """
    FastAPI dependency to verify Client ID and API Key from request headers.
    Safe to use over HTTPS for high-throughput batch ingestion.

    Returns:
        TelemetryClientAuthContext: The verified client context metadata.
    """
    # ❌ ELIMINADO: Ya no se lee de 'request.app.state' para evitar el AttributeError

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
        # ✨ Inyección nativa del servicio a través de la factoría de dependencias
        telemetry_client_service: TelemetryClientService = Depends(get_telemetry_client_service)
) -> TelemetryClientAuthContext:
    """
    FastAPI dependency to verify HMAC signature from request headers.

    This dependency should be applied to telemetry ingestion endpoints.
    """
    # Get raw body from request
    body = await request.body()

    # ❌ ELIMINADO: Ya no depende del ciclo de vida global del 'app.state'

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
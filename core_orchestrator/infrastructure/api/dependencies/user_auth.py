"""
FastAPI dependency providers for security.

Provides reusable dependencies for API key verification, HMAC verification, JWT authentication, and RBAC.
Unified authentication supports both tenant OAuth and telemetry client authentication.
"""

import logging
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from core_orchestrator.application.modules.auth_clients.auth_service import AuthService
from core_orchestrator.application.modules.auth_clients.tenant_service import TenantService
from core_orchestrator.application.modules.auth_clients.user_service import UserService
from core_orchestrator.domain.entities.auth.user import UserInDB
from core_orchestrator.domain.exceptions.auth_exceptions import InvalidCredentialsError, UserInactiveError
from core_orchestrator.infrastructure.api.dependencies.general_dependencies import \
    get_user_service, get_tenant_service, get_auth_service
from core_orchestrator.infrastructure.dto.auth.auth_dto import UserResponseDTO
from core_orchestrator.infrastructure.adapters.security.jwt_utils import (
    get_token_jti, decode_token
)

logger = logging.getLogger("core_orchestrator.security.dependencies")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")



async def get_current_user(
        token: str = Depends(oauth2_scheme),
        user_service: UserService = Depends(get_user_service),
        user_auth: AuthService = Depends(get_auth_service)
) -> UserResponseDTO:
    """
    Asynchronously retrieves the current authenticated user based on the provided JWT token.

    This function validates the provided token, checks for blacklisted tokens, decodes
    the token to extract user data, and fetches the user from the user service. It ensures
    that the user exists and is active during the authentication process.

    Parameters:
        token (str): A Bearer token included in the HTTP request for authentication
        user_service (UserService): A dependency-injected service used for fetching user details
        user_auth (AuthService): A dependency-injected service used for authentication operations

    Returns:
        UserResponseDTO: A data transfer object containing the authenticated user's details.

    Raises:
        HTTPException: Raised if the token is invalid, blacklisted, or if the user is inactive or not found.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    jti = get_token_jti(token) or ""
    if await user_auth.is_token_blacklisted(jti):
        logger.warning(f"Attempt to use blacklisted token: {jti}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked (logged out)",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = decode_token(token)
    if not token_data:
        raise credentials_exception

    try:
        user = await user_service.get_by_user_id(token_data.sub)
    except InvalidCredentialsError as exc:
        logger.warning(f"User not found for sub '{token_data.sub}': {exc}")
        raise credentials_exception
    except UserInactiveError as exc:
        logger.warning(f"Inactive user attempt for sub '{token_data.sub}': {exc}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    logger.debug(f"User authenticated via JWT: {user.username}")
    return user


def get_admin_user(current_user: UserInDB = Depends(get_current_user)) -> UserInDB:
    """
    Retrieve the current user with an admin role.

    This function checks if the currently authenticated user has an "admin" role. If
    the user does not have the required role, a warning is logged, and an HTTPException
    is raised with a 403 Forbidden status. This function ensures only users with
    admin privileges can access certain functionality.

    Args:
        current_user: The user object retrieved through dependency injection. The
        object should represent the currently authenticated user.

    Returns:
        The user object if the user's role is "admin".

    Raises:
        HTTPException: If the current user does not have an "admin" role.
    """
    if current_user.role != "admin":
        logger.warning(f"Unauthorized admin access attempt by user: {current_user.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required"
        )

    return current_user


def get_analyst_user(current_user: UserInDB = Depends(get_current_user)) -> UserInDB:
    """
    Retrieves the current user with the role of either 'admin' or 'analyst'. If the
    user does not have the required role, an exception is raised.

    Args:
        current_user (UserInDB): The currently authenticated user. Defaults to the
            result of the `get_current_user` dependency.

    Returns:
        UserInDB: The current user with an authorized role.

    Raises:
        HTTPException: If the user's role is not 'admin' or 'analyst'.
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
    """
    Asynchronous function to retrieve an analyst user with an associated and active client.

    This function verifies that the current analyst user is assigned to a valid and active
    client in the tenant service. If the user lacks an associated client or if the client
    is inactive or unauthorized, an HTTPException is raised. Otherwise, the current user
    is returned.

    Args:
        current_user (UserInDB): The currently authenticated analyst user
        tenant_service (TenantService): The service is used to retrieve client details

    Raises:
        HTTPException: If the user is not assigned to any client.
        HTTPException: If the user's client is inactive or unauthorized.

    Returns:
        UserInDB: The currently authenticated user if the client validation succeeds.
    """
    if not current_user.client_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not assigned to any client"
        )

    tenant = await tenant_service.get_tenant(current_user.client_id)
    if not tenant or tenant.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User client is inactive or not authorized"
        )

    return current_user
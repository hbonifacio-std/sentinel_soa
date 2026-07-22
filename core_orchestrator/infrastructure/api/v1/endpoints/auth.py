"""
Authentication endpoints for user login and profile retrieval.

Provides OAuth2 password flow for obtaining JWT access tokens
and endpoints to retrieve current user information, with logout support.
"""

import logging
from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.security import OAuth2PasswordRequestForm

from core_orchestrator.application.modules.auth_clients.services.auth_service import AuthService
from core_orchestrator.infrastructure.api.dependencies import get_auth_service, get_db_manager
from core_orchestrator.domain.models.auth.user import TokenResponse, UserResponse
from core_orchestrator.infrastructure.security.dependencies import get_current_user
from core_orchestrator.infrastructure.api.rate_limiter import limiter

logger = logging.getLogger("core_orchestrator.api.auth")

router = APIRouter()



@router.post(
    "/token",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    tags=["Authentication"]
)
@limiter.limit("5/minute")
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    auth_service: AuthService = Depends(get_auth_service),
):
    """
    OAuth2 compatible token endpoint.
    
    Authenticates user with username and password, returns JWT access token.
    The refresh token is set as an HttpOnly cookie; the client_api_key is
    NOT included in this response (used only for telemetry, not the dashboard).
    
    Args:
        form_data: OAuth2 password request form (username and password)
    
    Returns:
        Token response with access token and user info
    
    Raises:
        HTTPException: If credentials are invalid
    """
    login_result = await auth_service.login(form_data.username, form_data.password)
    
    if not login_result:
        logger.warning(f"Failed authentication attempt for username: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user, access_token, refresh_token = login_result

    # Return token and user info
    user_response = UserResponse(
        user_id=user.user_id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        client_id=user.client_id,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )
    
    response = TokenResponse(
        access_token=access_token,
        refresh_token=None,  # Don't include in response body, only in cookie
        token_type="bearer",
        expires_in=3600,  # 1 hour
        user=user_response,
    )
    
    # Set refresh token in HttpOnly cookie (separate from response body)
    response_obj = response.model_dump(mode='json', exclude_none=True)
    from fastapi.responses import JSONResponse
    json_response = JSONResponse(content=response_obj)
    json_response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        max_age=7 * 24 * 60 * 60,  # 7 days
        httponly=True,
        secure=True,
        samesite="Strict"
    )
    
    return json_response


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    tags=["Authentication"]
)
async def get_current_user_info(
    current_user = Depends(get_current_user)
):
    """
    Get current authenticated user's profile.
    
    Args:
        current_user: Current authenticated user (injected via JWT)
    
    Returns:
        User profile information
    """
    user_response = UserResponse(
        user_id=current_user.user_id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        is_active=current_user.is_active,
        client_id=current_user.client_id,
        created_at=current_user.created_at,
        updated_at=current_user.updated_at,
    )
    
    logger.debug(f"User profile retrieved for: {current_user.username}")
    
    return user_response


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    tags=["Authentication"]
)
@limiter.limit("10/minute")
async def logout(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
):
    """
    Logout endpoint - adds current token to blacklist for immediate revocation.
    
    This ensures the token cannot be used again, even if not yet expired.
    
    Args:
        request: FastAPI request object to extract Authorization header.
        auth_service: Injected authentication service.
        current_user: Current authenticated user (verifies valid token).
    
    Returns:
        Success message
    """
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        await auth_service.logout(token)

    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        await auth_service.revoke_refresh_token(refresh_token)

    from fastapi.responses import JSONResponse
    response = JSONResponse(content={"message": "Logged out successfully"})
    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        secure=True,
        samesite="Strict",
    )
    logger.info("Logout completed. Access and refresh tokens revoked where applicable.")
    return response


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    tags=["Authentication"]
)
@limiter.limit("10/minute")
async def refresh_access_token(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
    db_manager = Depends(get_db_manager),
):
    """
    Refresh endpoint - obtain new access token using refresh token from cookie.
    
    The refresh token can be provided either:
    1. Via HttpOnly cookie (preferred - secure) - automatically extracted
    2. Via Authorization header as Bearer token (fallback for SPAs)
    
    Returns:
        New access token with updated expiration
    """
    refresh_token = None
    
    # Try to get from HttpOnly cookie first (secure)
    refresh_token = request.cookies.get("refresh_token")
    
    # Fallback: check Authorization header
    if not refresh_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            refresh_token = auth_header.split(" ")[1]
    
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided"
        )
    
    # Use refresh token to get new access token
    result = await auth_service.refresh_access_token(refresh_token)
    if not result:
        logger.warning("Failed to refresh token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    new_access_token, jti = result
    
    # Decode refresh token to get user_id
    from core_orchestrator.infrastructure.security.jwt_utils import verify_refresh_token
    payload = verify_refresh_token(refresh_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    user_id = payload.get("sub")
    
    # Get user info
    auth_db = db_manager.get_auth_db()
    user_doc = await auth_db.users.find_one({"user_id": user_id})
    
    if not user_doc:
        raise HTTPException(status_code=401, detail="User not found")
    
    user_response = UserResponse(
        user_id=user_id,
        username=user_doc.get("username"),
        email=user_doc.get("email"),
        role=user_doc.get("role"),
        is_active=user_doc.get("is_active"),
        client_id=user_doc.get("client_id"),
        created_at=user_doc.get("created_at"),
        updated_at=user_doc.get("updated_at"),
    )
    
    response_data = TokenResponse(
        access_token=new_access_token,
        refresh_token=None,  # Keep refresh token only in HttpOnly cookie
        token_type="bearer",
        expires_in=3600,
        user=user_response,
    )
    
    from fastapi.responses import JSONResponse
    json_response = JSONResponse(content=response_data.model_dump(mode="json", exclude_none=True))
    
    # Optionally update refresh token cookie
    json_response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        max_age=7 * 24 * 60 * 60,
        httponly=True,
        secure=True,
        samesite="Strict"
    )
    
    logger.info(f"Access token refreshed for user: {user_id}")
    return json_response

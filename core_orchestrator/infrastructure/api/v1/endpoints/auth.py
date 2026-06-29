"""
Authentication endpoints for user login and profile retrieval.

Provides OAuth2 password flow for obtaining JWT access tokens
and endpoints to retrieve current user information, with logout support.
"""

import logging
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.security import OAuth2PasswordRequestForm

from core_orchestrator.application.services.auth_service import AuthService
from core_orchestrator.infrastructure.api.dependencies import get_auth_service
from core_orchestrator.domain.models.user import TokenResponse, UserResponse
from core_orchestrator.infrastructure.security.dependencies import get_current_user

logger = logging.getLogger("core_orchestrator.api.auth")

router = APIRouter()


@router.post(
    "/token",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    tags=["Authentication"]
)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    OAuth2 compatible token endpoint.
    
    Authenticates user with username and password, returns JWT access token.
    
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
    
    user, access_token = login_result
    
    # Return token and user info
    user_response = UserResponse(
        user_id=user.user_id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=user_response,
    )


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
async def logout(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
    current_user = Depends(get_current_user)
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
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing Authorization header"
        )
    
    token = auth_header.split(" ")[1]
    
    await auth_service.logout(token)
    logger.info(f"User {current_user.username} logged out successfully.")
    
    return {"message": "Logged out successfully"}



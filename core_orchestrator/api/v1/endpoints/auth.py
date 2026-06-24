"""
Authentication endpoints for user login and profile retrieval.

Provides OAuth2 password flow for obtaining JWT access tokens
and endpoints to retrieve current user information, with logout support.
"""

import logging
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.security import OAuth2PasswordRequestForm

from core_orchestrator.models.user import TokenResponse, UserResponse
from core_orchestrator.security.jwt_utils import create_access_token, blacklist_token, get_token_jti
from core_orchestrator.security.dependencies import get_current_user
from core_orchestrator.services.user_service import UserService

logger = logging.getLogger("core_orchestrator.api.auth")

router = APIRouter()


@router.post(
    "/token",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    tags=["Authentication"]
)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
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
    # Authenticate user
    user = await UserService.authenticate_user(form_data.username, form_data.password)
    
    if not user:
        logger.warning(f"Failed authentication attempt for username: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token (returns tuple: token, jti)
    access_token, jti = create_access_token(
        user_id=user.user_id,
        username=user.username,
        role=user.role,
    )
    
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
    
    logger.info(f"Token issued for user: {user.username} (jti: {jti})")
    
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
    current_user = Depends(get_current_user),
    request: Request = None
):
    """
    Logout endpoint - adds current token to blacklist for immediate revocation.
    
    This ensures the token cannot be used again, even if not yet expired.
    
    Args:
        current_user: Current authenticated user (verifies valid token)
        request: FastAPI request object to extract Authorization header
    
    Returns:
        Success message
    """
    # Extract token from Authorization header
    auth_header = request.headers.get("Authorization", "") if request else ""
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]  # Remove "Bearer " prefix
    else:
        # Fallback - shouldn't happen if get_current_user passed
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization header malformed"
        )
    
    # Extract JTI and blacklist the token
    jti = get_token_jti(token)
    if jti:
        from core_orchestrator.config import orchestrator_settings
        
        # Calculate token expiration time
        expires_delta = timedelta(minutes=orchestrator_settings.jwt_expiration_minutes)
        expires_at = datetime.now(timezone.utc) + expires_delta
        
        blacklist_token(jti, expires_at)
        logger.info(f"User {current_user.username} logged out (token: {jti})")
    else:
        logger.warning(f"Could not extract JTI for logout, user: {current_user.username}")
    
    return {"message": "Logged out successfully"}



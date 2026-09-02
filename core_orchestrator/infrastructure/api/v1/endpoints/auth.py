"""
Authentication endpoints for user login and profile retrieval.

Provides OAuth2 password flow for getting JWT access tokens
and endpoints to retrieve current user information, with logout support.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, HTTPException, status, Depends, Request, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm

from core_orchestrator.application.modules.auth_clients.auth_service import AuthService
from core_orchestrator.domain.exceptions.auth_exceptions import InvalidCredentialsError, UserInactiveError, \
    InvalidTokenError, TokenRevokedError
from core_orchestrator.infrastructure.api.dependencies.general_dependencies import get_auth_service
from core_orchestrator.infrastructure.dto.auth.auth_dto import TokenResponseDTO, UserResponseDTO
from core_orchestrator.infrastructure.api.dependencies.user_auth import get_current_user
from core_orchestrator.infrastructure.rate_limit.rate_limiter import limiter

logger = logging.getLogger("core_orchestrator.api.auth")

router = APIRouter()
REFRESH_TOKEN_COOKIE_NAME = "refresh_token"
COOKIE_MAX_AGE = 7 * 24 * 60 * 60  # 7 días


def _set_refresh_token_cookie(response: Response, refresh_token: str) -> None:
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE_NAME,
        value=refresh_token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="strict",
    )

def _clear_refresh_token_cookie(response: Response) -> None:
    response.delete_cookie(
        key=REFRESH_TOKEN_COOKIE_NAME,
        httponly=True,
        secure=True,
        samesite="strict",
    )

@router.post(
    "/token",
    response_model=TokenResponseDTO,
    status_code=status.HTTP_200_OK,
    tags=["Authentication"]
)
@limiter.limit("5/minute")
async def login_for_access_token(
    request: Request,
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
):
    """
    Handles user authentication by providing access and refresh tokens.

    This endpoint authenticates a user using the provided username and password.
    If authentication is successful, an access token and a refresh token are returned.
    The refresh token is stored as a secure cookie in the response. The endpoint is
    rate-limited to prevent abuse.

    Args:
        request: The HTTP request object, containing metadata about the incoming HTTP request.
        response: The HTTP response object, used to send HTTP responses to the client.
        form_data: Contains the username and password entered by the client. Must conform
            to the OAuth2PasswordRequestForm specification.
        auth_service: The authentication service instance is responsible for validating credentials
            and generating tokens.

    Raises:
        HTTPException: Returns a 401 UNAUTHORIZED status code if the provided credentials
            are invalid or if the user account is inactive.

    Returns:
        TokenResponseDTO: A data transfer object containing the access token and the
            refresh token for the authenticated user.
    """
    try:
        token_response = await auth_service.login(
            form_data.username,
            form_data.password
        )
        _set_refresh_token_cookie(response, token_response.refresh_token)

        return token_response
    except (InvalidCredentialsError, UserInactiveError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.get(
    "/me",
    response_model=UserResponseDTO,
    status_code=status.HTTP_200_OK,
    tags=["Authentication"]
)
async def get_current_user_info(
    current_user: Annotated[UserResponseDTO, Depends(get_current_user)]
):
    """
    Retrieve information about the currently authenticated user.

    This endpoint returns profile information of the currently logged-in user
    based on their authentication token. It requires the user to be authenticated.

    Args:
        current_user (UserResponseDTO): The currently authenticated user, automatically
        retrieved and injected by the dependency.

    Returns:
        UserResponseDTO: The profile information of the currently authenticated user.
    """
    logger.debug(f"User profile retrieved for: {current_user.username}")
    return current_user


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    tags=["Authentication"]
)
@limiter.limit("10/minute")
async def logout(
    request: Request,
    response: Response,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    refresh_token: Annotated[str | None, Cookie(alias=REFRESH_TOKEN_COOKIE_NAME)] = None
):
    """
    Handles user logout by invalidating access and refresh tokens and clearing the refresh
    token cookie from the client's browser.

    This endpoint requires a valid authentication context and supports a maximum of 10
    requests per minute.

    Args:
        request (Request): The incoming HTTP request object, used to access the
            Authorization header for the access token

        response (Response): The outgoing HTTP response object, used to manage the
            refresh token cookie

        auth_service (AuthService): A service that handles authentication-related logic,
            provided as a dependency

        refresh_token (str | None): Optional. The refresh token provided as a cookie,
            retrieved using the REFRESH_TOKEN_COOKIE_NAME constant alias

    Returns:
        dict: A dictionary containing a confirmation message upon successful logout.
    """
    access_token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        access_token = auth_header.split(" ")[1]

    await auth_service.logout(access_token=access_token, refresh_token=refresh_token)
    _clear_refresh_token_cookie(response)

    return {"message": "Logged out successfully"}


@router.post(
    "/refresh",
    response_model=TokenResponseDTO,
    status_code=status.HTTP_200_OK,
    tags=["Authentication"]
)
@limiter.limit("10/minute")
async def refresh_access_token(
    request: Request,
    response: Response,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    cookie_refresh_token: Annotated[str | None, Cookie(alias=REFRESH_TOKEN_COOKIE_NAME)] = None,
):
    """
    Handles the generation of a new access token using a valid refresh token.

    This endpoint allows clients to get a new access token by providing a valid
    refresh token. The token can be provided either through a cookie or an
    Authorization header with the Bearer scheme.

    Parameters:
        request (Request): The HTTP request object containing headers and other
            request metadata

        response (Response): The HTTP response object for setting the refresh token
            cookie if applicable
        auth_service (AuthService): The authentication service instance is responsible
            for managing token operations. It is injected via dependency injection
        cookie_refresh_token (str | None): An optional refresh token passed through
            a cookie. Defaults to None

    Raises:
        HTTPException: status 401 if no refresh token is provided or if
            the token is invalid, revoked, or belongs to an inactive user.

    Returns:
        TokenResponseDTO: A DTO containing the new access token and associated data.
    """
    token_to_use = cookie_refresh_token or None
    if not token_to_use:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token_to_use = auth_header.split(" ")[1]

    if not token_to_use:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided",
        )

    try:
        token_response = await auth_service.refresh_access_token(token_to_use)
        _set_refresh_token_cookie(response, token_to_use)

        return token_response
    except (InvalidTokenError, TokenRevokedError, UserInactiveError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        )

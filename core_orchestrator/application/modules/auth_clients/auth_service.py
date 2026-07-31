import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from core_orchestrator.application.modules.auth_clients.user_service import UserService
from core_orchestrator.domain.exceptions.auth_exceptions import InvalidTokenError, TokenRevokedError
from core_orchestrator.domain.ports import TokenBlacklistRepositoryPort, TokenProviderPort
from core_orchestrator.infrastructure.dto.auth.auth_dto import TokenResponseDTO, UserResponseDTO

logger = logging.getLogger(__name__)


class AuthService:
    """
    Provides authentication-related services, including user login, access token renewal,
    token revocation, and token blacklist checks.

    AuthService manages the authentication process for users, including issuing access and refresh tokens,
    renewing access tokens, logging users out by revoking their tokens, and verifying if tokens have been
    blacklisted. It integrates with a user management service, token provider, and a token blacklist repository.

    Attributes:
        user_service (UserService): The service responsible for managing user authentication and user-related actions
        token_blacklist_repo (TokenBlacklistRepositoryPort): The repository for handling token blacklisting
        token_service (TokenProviderPort): The service responsible for issuing and verifying tokens
        access_token_expires_delta (timedelta): The expiration duration for access tokens
        refresh_token_expires_delta (timedelta): The expiration duration for refresh tokens defaults to 7 days
            if not provided.
    """
    def __init__(
            self,
            user_service: UserService,
            token_blacklist_repo: TokenBlacklistRepositoryPort,
            token_service: TokenProviderPort,
            access_token_expires_delta: timedelta,
            refresh_token_expires_delta: timedelta,
    ):
        """
        Initializes the authentication service with the required dependencies and
        configuration for token expiration.

        Attributes:
            user_service (UserService): A service for managing user-related operations,
                such as authentication and user information retrieval
            token_blacklist_repo (TokenBlacklistRepositoryPort): A repository interface
                for managing blacklisted tokens to support secure revocation
            token_service (TokenProviderPort): A service for generating and managing
                authentication tokens (access and refresh tokens)
            access_token_expires_delta (timedelta): The duration specifying how long
                the access token remains valid after generation
            refresh_token_expires_delta (timedelta): The duration specifying how long the
                refresh token remains valid after generation. Defaults to 7 days if not
                explicitly provided.
        """
        self.user_service = user_service
        self.token_blacklist_repo = token_blacklist_repo
        self.token_service = token_service
        self.access_token_expires_delta = access_token_expires_delta
        self.refresh_token_expires_delta = refresh_token_expires_delta or timedelta(days=7)

    async def login(self, username: str, password: str) -> TokenResponseDTO:
        """
        Asynchronously authenticates a user and generates access and refresh tokens.
        This method verifies the user's credentials using the supplied username and
         password and then generates a pair of tokens - an access token and a refresh
        token. The access token is used for short-lived access to protected resources,
        while the refresh token is used to generate a new access token once it expires.
        It also logs the issuance of the token for debugging purposes.

        Parameters:
            username: str
                The username of the user attempting to log in.
            password: str
                The password of the user attempting to log in.

        Returns:
            TokenResponseDTO
                A data transfer object containing the generated access token, refresh
                token, token type, expiration time (in seconds), and user information.
        """

        user = await self.user_service.authenticate_user(username, password)

        access_token, jti = self.token_service.create_access_token(
            user_id=user.user_id,
            username=user.username,
            role=user.role,
            expires_delta=self.access_token_expires_delta,
        )

        refresh_token = self.token_service.create_refresh_token(
            user_id=user.user_id,
            expires_delta=self.refresh_token_expires_delta,
        )

        logger.debug(f"Token issued to the user: {user.username} (jti: {jti})")
        user_response = UserResponseDTO.model_validate(user)
        return TokenResponseDTO(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=int(self.access_token_expires_delta.total_seconds()),
            user=user_response,
        )

    async def refresh_access_token(self, refresh_token: str) -> TokenResponseDTO:
        """
        Refreshes and generates a new access token using the provided refresh token.

        This method validates the provided refresh token, ensures that it has not been
        revoked, and generates a new access token for the user associated with the
        refresh token. It also logs the renewal of the access token and returns the
        response containing the new access token, along with other token-related
        information and user details.

        Arguments:
            refresh_token (str): The refresh token used for generating a new access
            token.

        Raises:
            InvalidTokenError: If the refresh token is invalid, expired, or does not
            contain a valid user identifier.
            TokenRevokedError: If the refresh token has been revoked.

        Returns:
            TokenResponseDTO: A data transfer object containing the new access token,
            the provided refresh token, token type, expiration time in seconds, and
            user details.
        """
        payload = self.token_service.verify_refresh_token(refresh_token)
        if not payload:
            raise InvalidTokenError("Refresh token invalid or expired")

        refresh_jti = payload.get("jti")
        if not isinstance(refresh_jti, str) or await self.token_blacklist_repo.is_blacklisted(refresh_jti):
            raise TokenRevokedError("The refresh token has been revoked.")

        user_id = payload.get("sub")
        if not isinstance(user_id,str):
            raise InvalidTokenError("Token without user identifier")

        user = await self.user_service.get_by_user_id(user_id)

        new_access_token, jti = self.token_service.create_access_token(
            user_id=user.user_id,
            username=user.username,
            role=user.role,
            expires_delta=self.access_token_expires_delta,
        )

        logger.info(f"Access token renewed for the user: {user.username} (jti: {jti})")
        user_response = UserResponseDTO.model_validate(user)
        return TokenResponseDTO(
            access_token=new_access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=int(self.access_token_expires_delta.total_seconds()),
            user=user_response,
        )

    async def logout(self, access_token: Optional[str] = None, refresh_token: Optional[str] = None) -> None:
        """
        Handles the logout process by adding the provided tokens to the blacklist to prevent future use.
        This involves blacklisting both access and refresh tokens if provided, ensuring their invalidation.

        Parameters:
            access_token (Optional[str]): The access token to be blacklisted. If not provided, this step is skipped
            refresh_token (Optional[str]): The refresh token to be blacklisted. If not provided, this step is skipped.

        Returns:
            None

        Raises:
            Does not explicitly raise exceptions in the method body but relies on upstream services for token verification
            and may raise exceptions indirectly if tokens are invalid or other errors occur.
        """
        if access_token:
            jti = self.token_service.get_token_jti(access_token)
            if jti:
                expires_at = datetime.now(timezone.utc) + self.access_token_expires_delta
                await self.token_blacklist_repo.add_to_blacklist(jti, expires_at)

        if refresh_token:
            payload = self.token_service.verify_refresh_token(refresh_token)
            if payload:
                refresh_jti = payload.get("jti")
                exp = payload.get("exp")
                if isinstance(refresh_jti,str) and isinstance(exp,(int, float)):
                    expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
                    await self.token_blacklist_repo.add_to_blacklist(refresh_jti, expires_at)

    async def is_token_blacklisted(self,     jti: str) -> bool:
        """
        Determines if a given token, identified by its JTI, is blacklisted.

        This method queries the token blacklist repository to check if the
        provided token is present in the blacklist.

        Parameters:
        jti: str
            The unique identifier of the token (JWT ID) to verify.

        Returns:
        bool
            True if the token is blacklisted, otherwise False.
        """
        return await self.token_blacklist_repo.is_blacklisted(jti)
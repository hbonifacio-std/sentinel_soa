import logging
from datetime import timedelta, datetime, timezone
from typing import Optional, Tuple

from core_orchestrator.domain.models.auth.user import UserInDB
from core_orchestrator.domain.ports.auth.user_provider import UserProvider
from core_orchestrator.domain.ports.auth.token_service import TokenServicePort
from core_orchestrator.domain.ports.auth.token_blacklist_repository import TokenBlacklistRepository

logger = logging.getLogger(__name__)

class AuthService:
    def __init__(
        self,
        user_provider: UserProvider,
        token_blacklist_repository: TokenBlacklistRepository,
        token_service: TokenServicePort,
        access_token_expires_delta: timedelta,
        refresh_token_expires_delta: timedelta = None,
    ):
        self.user_provider = user_provider
        self.token_blacklist_repo = token_blacklist_repository
        self.token_service = token_service
        self.access_token_expires_delta = access_token_expires_delta
        self.refresh_token_expires_delta = refresh_token_expires_delta or timedelta(days=7)

    async def login(self, username: str, password: str) -> Optional[Tuple[UserInDB, str, str]]:
        """
        Authenticates a user and returns the user object, access token, and refresh token.
        
        Returns:
            Tuple[UserInDB, access_token, refresh_token] or None if authentication fails
        """
        user = await self.user_provider.authenticate_user(username, password)
        if not user:
            return None

        # Generate access token (short-lived: 15-60 minutes)
        access_token, jti = self.token_service.create_access_token(
            user_id=user.user_id,
            username=user.username,
            role=user.role,
            expires_delta=self.access_token_expires_delta,
        )
        
        # Generate refresh token (long-lived: 7 days)
        refresh_token = self.token_service.create_refresh_token(
            user_id=user.user_id,
            expires_delta=self.refresh_token_expires_delta,
        )
        
        logger.info(f"Token issued for user: {user.username} (jti: {jti})")
        return user, access_token, refresh_token

    async def refresh_access_token(self, refresh_token: str) -> Optional[Tuple[str, str]]:
        """
        Generates a new access token using a valid refresh token.
        
        Returns:
            Tuple[new_access_token, refresh_token_jti] or None if refresh fails
        """
        # Validate and extract claims from refresh token
        payload = self.token_service.verify_refresh_token(refresh_token)
        if not payload:
            logger.warning("Invalid or expired refresh token")
            return None

        refresh_jti = payload.get("jti")
        if not refresh_jti:
            logger.warning("Refresh token missing JTI")
            return None

        if await self.token_blacklist_repo.is_blacklisted(refresh_jti):
            logger.warning("Refresh token has been revoked")
            return None

        user_id = payload.get("sub")
        if not user_id:
            logger.warning("Invalid refresh token payload")
            return None
        
        # Retrieve user to get updated info
        user = await self.user_provider.get_user_by_id(user_id)
        if not user or not user.is_active:
            logger.warning(f"User {user_id} not found or inactive during token refresh")
            return None
        
        # Generate new access token
        new_access_token, jti = self.token_service.create_access_token(
            user_id=user.user_id,
            username=user.username,
            role=user.role,
            expires_delta=self.access_token_expires_delta,
        )
        
        logger.info(f"Access token refreshed for user: {user.username}")
        return new_access_token, jti

    async def revoke_refresh_token(self, refresh_token: str) -> None:
        """
        Revokes a refresh token by blacklisting its JTI until its expiration.
        """
        payload = self.token_service.verify_refresh_token(refresh_token)
        if not payload:
            return

        refresh_jti = payload.get("jti")
        exp = payload.get("exp")
        if not refresh_jti or not exp:
            return

        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            return

        await self.token_blacklist_repo.add_to_blacklist(refresh_jti, expires_at)
        logger.info(f"Refresh token revoked (jti: {refresh_jti})")

    async def logout(self, token: str):
        """
        Logs out a user by blacklisting the current token.
        """
        jti = self.token_service.get_token_jti(token)
        if jti:
            expires_at = datetime.now(timezone.utc) + self.access_token_expires_delta
            await self.token_blacklist_repo.add_to_blacklist(jti, expires_at)
            logger.info(f"User logged out (token JTI: {jti})")

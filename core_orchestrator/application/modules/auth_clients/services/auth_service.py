import logging
from datetime import timedelta, datetime, timezone
from typing import Optional

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
    ):
        self.user_provider = user_provider
        self.token_blacklist_repo = token_blacklist_repository
        self.token_service = token_service
        self.access_token_expires_delta = access_token_expires_delta

    async def login(self, username: str, password: str) -> Optional[tuple[UserInDB, str]]:
        """
        Authenticates a user and returns the user object and a JWT token.
        """
        user = await self.user_provider.authenticate_user(username, password)
        if not user:
            return None

        access_token, jti = self.token_service.create_access_token(
            user_id=user.user_id,
            username=user.username,
            role=user.role,
            expires_delta=self.access_token_expires_delta,
        )
        logger.info(f"Token issued for user: {user.username} (jti: {jti})")
        return user, access_token

    async def logout(self, token: str):
        """
        Logs out a user by blacklisting the current token.
        """
        jti = self.token_service.get_token_jti(token)
        if jti:
            expires_at = datetime.now(timezone.utc) + self.access_token_expires_delta
            await self.token_blacklist_repo.add_to_blacklist(jti, expires_at)
            logger.info(f"User logged out (token JTI: {jti})")


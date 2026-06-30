import logging
from datetime import timedelta, datetime, timezone
from typing import Optional

from core_orchestrator.infrastructure.config.config import orchestrator_settings
from core_orchestrator.domain.models.user import UserInDB
from core_orchestrator.domain.ports.user_provider import UserProvider
from core_orchestrator.domain.ports.token_blacklist_repository import TokenBlacklistRepository
from core_orchestrator.infrastructure.security.jwt_utils import create_access_token, get_token_jti

logger = logging.getLogger(__name__)

class AuthService:
    def __init__(
        self,
        user_provider: UserProvider,
        token_blacklist_repository: TokenBlacklistRepository,
    ):
        self.user_provider = user_provider
        self.token_blacklist_repo = token_blacklist_repository

    async def login(self, username: str, password: str) -> Optional[tuple[UserInDB, str]]:
        """
        Authenticates a user and returns the user object and a JWT token.
        """
        user = await self.user_provider.authenticate_user(username, password)
        if not user:
            return None

        access_token, jti = create_access_token(
            user_id=user.user_id,
            username=user.username,
            role=user.role,
        )
        logger.info(f"Token issued for user: {user.username} (jti: {jti})")
        return user, access_token

    async def logout(self, token: str):
        """
        Logs out a user by blacklisting the current token.
        """
        jti = get_token_jti(token)
        if jti:
            expires_delta = timedelta(minutes=orchestrator_settings.jwt_expiration_minutes)
            expires_at = datetime.now(timezone.utc) + expires_delta
            await self.token_blacklist_repo.add_to_blacklist(jti, expires_at)
            logger.info(f"User logged out (token JTI: {jti})")

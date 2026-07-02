from datetime import datetime, timezone
import logging
from redis.asyncio import Redis

from core_orchestrator.domain.ports.auth.token_blacklist_repository import TokenBlacklistRepository

logger = logging.getLogger(__name__)

class RedisTokenBlacklistRepository(TokenBlacklistRepository):
    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        self.BLACKLIST_PREFIX = "blacklist:"

    async def add_to_blacklist(self, jti: str, expires_at: datetime):
        now = datetime.now(timezone.utc)
        
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        ttl_seconds = int((expires_at - now).total_seconds())

        if ttl_seconds <= 0:
            logger.debug(f"Token {jti} has already expired, not adding to blacklist.")
            return

        key = f"{self.BLACKLIST_PREFIX}{jti}"
        await self.redis.set(key, "revoked", ex=ttl_seconds)
        logger.info(f"Token JTI added to blacklist: {jti} (TTL: {ttl_seconds}s)")

    async def is_blacklisted(self, jti: str) -> bool:
        if not jti:
            return False
        key = f"{self.BLACKLIST_PREFIX}{jti}"
        exists = await self.redis.exists(key)
        return exists > 0

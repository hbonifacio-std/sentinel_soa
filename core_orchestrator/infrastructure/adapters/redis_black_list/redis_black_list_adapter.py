import logging
from datetime import datetime, timezone
from redis.asyncio import Redis

from core_orchestrator.domain.exceptions.database_exceptions import DatabaseError
from core_orchestrator.domain.ports import TokenBlacklistRepositoryPort

logger = logging.getLogger(__name__)

class RedisTokenBlacklistAdapter(TokenBlacklistRepositoryPort):
    """
    Handles blacklisting of tokens using a Redis backend.

    This class provides functionality to manage and query blacklisted tokens
    using a Redis database. It is designed to interact with access tokens
    identified by their unique Token Identifier (JTI). Blacklisted tokens are
    stored with an expiration time based on their associated TTL (Time-To-Live).
    """
    def __init__(self, redis_client: Redis |None = None):
        """
        Initializes the object, setting up the connection to a Redis client for managing
        the token blacklist. Requires a valid Redis client instance to perform operations.

        Attributes:
            redis_client (Redis): The Redis client instance for interacting with the token
            blacklist.

        Raises:
            DatabaseError: If the Redis client is not provided during initialization.
        """
        if redis_client is None:
            raise DatabaseError("Redis client is required for token blacklist.")

        self.redis = redis_client
        self.BLACKLIST_PREFIX = "blacklist:auth:"

    async def add_to_blacklist(self, jti: str, expires_at: datetime) -> None:
        """
        Marks a JWT token as revoked by adding it to a Redis blacklist with a time-to-live (TTL).

        The method calculates the remaining TTL based on the expiration timestamp of the token and
        stores the token identifier (JTI) in the Redis database with a corresponding TTL. If the
        expiration timestamp is already past or is invalid, the method terminates without taking
        any action.

        Parameters:
            jti: str
                The unique identifier of the JWT token to be revoked.
            expires_at: datetime
                The expiration datetime of the JWT token being blacklisted. The datetime
                must include a timezone; otherwise, it will be assumed as UTC.

        Returns:
            None

        Raises:
            None
        """
        now = datetime.now(timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        ttl_seconds = int((expires_at - now).total_seconds())

        if ttl_seconds <= 0:
            return

        key = f"{self.BLACKLIST_PREFIX}{jti}"
        await self.redis.set(key, "revoked", ex=ttl_seconds)
        logger.info(f"JTI token marked as revoked in Redis:: {jti} (TTL: {ttl_seconds}s)")

    async def is_blacklisted(self, jti: str) -> bool:
        """
        Check if a given token identifier (JTI) is blacklisted.

        This method checks the presence of the given JTI in the Redis database with a
        specific blacklist prefix. If the JTI exists in the blacklist, it indicates
        that the token is invalid and should not be processed further.

        Args:
            jti (str): The token identifier to be checked for blacklisting.

        Returns:
            bool: True if the JTI is blacklisted, False otherwise.
        """
        if not jti:
            return False
        key = f"{self.BLACKLIST_PREFIX}{jti}"
        return (await self.redis.exists(key)) > 0
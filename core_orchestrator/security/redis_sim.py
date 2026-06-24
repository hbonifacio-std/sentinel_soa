"""
Simulated Redis client for storing API secrets (public key -> secret mappings)
and JWT token blacklist for logout functionality.

This is a development/testing utility. In production, use a real Redis instance.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger("core_orchestrator.security.redis_sim")


class RedisSecretStore:
    """
    In-memory secret store simulating Redis functionality for HMAC verification
    and JWT token blacklist.
    
    Stores:
    - Public keys to their corresponding secrets for API authentication
    - Blacklisted JWT tokens (for logout functionality)
    
    This is used during development and testing.
    """
    
    def __init__(self):
        """Initialize with default test secrets and empty blacklist."""
        # Default test secrets for development
        self._store = {
            "victim-app-01": "sentinel_sk_live_v1_KLPLxqIZWPaelBI66EUVQKv6xHAMFqP9n",
        }
        # Token blacklist: token_id -> expiration_timestamp
        self._blacklist = {}
        logger.info(f"RedisSecretStore initialized with {len(self._store)} secrets and empty blacklist")
    
    def get_secret(self, public_key: str) -> str | None:
        """
        Retrieve a secret by public key.
        
        Args:
            public_key: Public key identifier
        
        Returns:
            Secret string if found, None otherwise
        """
        return self._store.get(public_key)
    
    def set_secret(self, public_key: str, secret: str) -> None:
        """
        Store or update a secret.
        
        Args:
            public_key: Public key identifier
            secret: Secret string to store
        """
        self._store[public_key] = secret
        logger.info(f"Secret updated for public_key: {public_key}")
    
    def delete_secret(self, public_key: str) -> bool:
        """
        Delete a secret.
        
        Args:
            public_key: Public key identifier
        
        Returns:
            True if secret was deleted, False if it didn't exist
        """
        if public_key in self._store:
            del self._store[public_key]
            logger.info(f"Secret deleted for public_key: {public_key}")
            return True
        return False
    
    def get_all_secrets(self) -> dict[str, str]:
        """
        Get all stored secrets (for testing only).
        
        Returns:
            Dictionary of all public_key -> secret mappings
        """
        return self._store.copy()
    
    def clear(self) -> None:
        """Clear all stored secrets."""
        self._store.clear()
        logger.info("All secrets cleared from RedisSecretStore")
    
    # ============================================================================
    # JWT Blacklist Operations (for Logout)
    # ============================================================================
    
    def blacklist_token(self, token_jti: str, expires_at: datetime) -> None:
        """
        Add a token to the blacklist (revoke it).
        
        Args:
            token_jti: Token JWT ID (unique identifier)
            expires_at: When the token expires (we clean up after this)
        """
        self._blacklist[token_jti] = self._normalize_utc(expires_at)
        logger.info(f"Token blacklisted: {token_jti} (expires at {expires_at})")
        # Cleanup old entries
        self._cleanup_expired_blacklist()
    
    def is_token_blacklisted(self, token_jti: str) -> bool:
        """
        Check if a token has been blacklisted (revoked).
        
        Args:
            token_jti: Token JWT ID to check
        
        Returns:
            True if token is blacklisted, False otherwise
        """
        if token_jti not in self._blacklist:
            return False
        
        # Check if blacklist entry has expired
        expiration = self._normalize_utc(self._blacklist[token_jti])
        if datetime.now(timezone.utc) > expiration:
            # Clean up expired entry
            del self._blacklist[token_jti]
            return False
        
        return True
    
    def _cleanup_expired_blacklist(self) -> None:
        """Remove expired entries from blacklist."""
        now = datetime.now(timezone.utc)
        expired_tokens = [
            jti for jti, exp_time in self._blacklist.items()
            if now > self._normalize_utc(exp_time)
        ]
        
        for jti in expired_tokens:
            del self._blacklist[jti]
            logger.debug(f"Cleaned up expired blacklist entry: {jti}")
        
        if expired_tokens:
            logger.debug(f"Cleaned {len(expired_tokens)} expired tokens from blacklist")
    
    def get_blacklist_size(self) -> int:
        """Get current size of blacklist."""
        self._cleanup_expired_blacklist()
        return len(self._blacklist)

    @staticmethod
    def _normalize_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    
    def clear_blacklist(self) -> None:
        """Clear all blacklisted tokens."""
        self._blacklist.clear()
        logger.info("JWT blacklist cleared")


# Global instance for development
redis_secrets = RedisSecretStore()


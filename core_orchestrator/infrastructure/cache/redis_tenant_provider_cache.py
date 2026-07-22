"""Redis cache implementation for tenant AI provider configurations."""

import json
import logging
from typing import Optional, Any
from redis.asyncio import Redis

logger = logging.getLogger(__name__)


class RedisTenantProviderCache:
    """Redis cache for tenant provider and model configs to avoid heavy DB lookups on frequent log events."""

    TTL_SECONDS = 300  # 5 minutes
    KEY_PREFIX = "tenant:provider_cfg:"

    def __init__(self, redis_client: Optional[Redis]):
        self._redis = redis_client

    async def get(self, client_id: str) -> Optional[dict]:
        """Fetch cached tenant provider payload dictionary if present."""
        if not self._redis:
            return None
        try:
            key = f"{self.KEY_PREFIX}{client_id}"
            raw = await self._redis.get(key)
            if raw:
                return json.loads(raw)
        except Exception as e:
            logger.warning(f"Error reading tenant provider cache for {client_id}: {e}")
        return None

    async def set(self, client_id: str, data: dict) -> None:
        """Cache tenant provider payload dictionary."""
        if not self._redis:
            return
        try:
            key = f"{self.KEY_PREFIX}{client_id}"
            raw = json.dumps(data)
            await self._redis.set(key, raw, ex=self.TTL_SECONDS)
        except Exception as e:
            logger.warning(f"Error setting tenant provider cache for {client_id}: {e}")

    async def invalidate(self, client_id: str) -> None:
        """Invalidate tenant provider cache entry when admin changes settings."""
        if not self._redis:
            return
        try:
            key = f"{self.KEY_PREFIX}{client_id}"
            await self._redis.delete(key)
        except Exception as e:
            logger.warning(f"Error invalidating tenant provider cache for {client_id}: {e}")

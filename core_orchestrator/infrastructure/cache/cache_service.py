import json
import logging
import os
from types import SimpleNamespace
from typing import Optional, List, Any
from datetime import datetime, timezone

from redis.asyncio.lock import Lock

from core_orchestrator.infrastructure.config.database import DatabaseManager
from core_orchestrator.domain.models.rules import RulesBundle

logger = logging.getLogger(__name__)

RULES_CACHE_KEY = "rules:active:all"
RULES_VERSION_KEY = "rules:metadata:version_hash"
RULES_UPDATED_KEY = "rules:metadata:last_updated"
DEFAULT_RULES_TTL = int(os.getenv("RULES_CACHE_TTL_SECONDS", "86400"))

class CacheService:
    def __init__(self, db_manager: DatabaseManager):
        self.redis = db_manager.redis_client

    async def get(self, key: str) -> Optional[str]:
        """Gets a value from the cache by key."""
        if not self.redis:
            logger.warning("Redis client not connected; cannot get key %s", key)
            return None
        value = await self.redis.get(key)
        if value:
            return value.decode('utf-8')
        return None

    async def set(self, key: str, value: Any, expire_seconds: int):
        """Sets a value in the cache with an expiration."""
        if not self.redis:
            logger.warning("Redis client not connected; cannot set key %s", key)
            return
        await self.redis.set(key, value, ex=expire_seconds)

    async def get_ttl(self, key: str) -> int:
        """Gets the TTL for a key."""
        if not self.redis:
            logger.warning("Redis client not connected; cannot get TTL for key %s", key)
            return -2
        return await self.redis.ttl(key)

    def lock(self, key: str, timeout: int) -> Lock:
        """Creates a distributed lock."""
        if not self.redis:
            # This is not ideal, but we need to return a lock-like object.
            # A better solution would be a NullObject pattern for the lock.
            # For now, this will raise an attribute error if redis is not available.
            logger.error("Redis client not connected; cannot create lock for key %s", key)
        return self.redis.lock(key, timeout=timeout)

    async def cache_rules(self, bundle: RulesBundle, ttl_seconds: int = DEFAULT_RULES_TTL) -> bool:
        if not self.redis:
            logger.warning("Redis rules client no conectado; omitiendo caché")
            return False

        payload = json.dumps(bundle.to_cache_dict())
        updated = bundle.last_updated.isoformat() if bundle.last_updated else datetime.now(timezone.utc).isoformat()

        async with self.redis.pipeline(transaction=True) as pipe:
             await pipe.set(RULES_CACHE_KEY, payload, ex=ttl_seconds)
             await pipe.set(RULES_VERSION_KEY, bundle.version_hash, ex=ttl_seconds)
             await pipe.set(RULES_UPDATED_KEY, updated, ex=ttl_seconds)
             await pipe.execute()

        return True

    async def get_cached_rules(self) -> Optional[RulesBundle]:
        if not self.redis:
            return None
        raw = await self.redis.get(RULES_CACHE_KEY)
        return RulesBundle.from_cache_dict(json.loads(raw)) if raw else None

    async def invalidate_rules_cache(self) -> bool:
        """Deletes linked cache keys to force a clean reload."""
        if not self.redis:
            return False
        await self.redis.delete(RULES_CACHE_KEY, RULES_VERSION_KEY, RULES_UPDATED_KEY)
        logger.info("Rules cache invalidated.")
        return True

    async def add_multiple(self, key: str, events: List[any], expire_seconds:int):
        payloads = [event.model_dump_json() for event in events]

        async with self.redis.pipeline(transaction=True) as pipe:
            await pipe.rpush(key, *payloads)
            await pipe.expire(key, expire_seconds)
            await pipe.execute()


    async def get_client_by_id(self, client_id: str):
        if self.redis:
            data = await self.redis.get(f"client:{client_id}")
            if data:
                # Redis devuelve bytes, lo decodificamos y pasamos a objeto de Python
                client_dict = json.loads(data.decode('utf-8') if isinstance(data, bytes) else data)
                return SimpleNamespace(**client_dict)  # O tu modelo respectivo
        return None
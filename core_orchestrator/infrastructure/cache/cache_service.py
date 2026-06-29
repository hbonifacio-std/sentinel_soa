import json
import logging
import os
from typing import Optional, List
from datetime import datetime, timezone
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

    async def add_multiple(self, key: str, events: List[any], expire_seconds:int):
        payloads = [event.model_dump_json() for event in events]

        async with self.redis.pipeline(transaction=True) as pipe:
            await pipe.rpush(key, *payloads)
            await pipe.expire(key, expire_seconds)
            await pipe.execute()

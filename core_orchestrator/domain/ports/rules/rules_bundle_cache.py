# core_orchestrator/domain/ports/rules_bundle_cache.py
from abc import ABC, abstractmethod
from typing import Optional

from core_orchestrator.domain.models.rule_engine.rules import RulesBundle


class RulesBundleCachePort(ABC):
    """
    Port for managing the active rules bundle in a cache.
    Supports tenant-scoped isolation via cache_key_suffix parameter.
    """

    @abstractmethod
    async def get_bundle(self, cache_key_suffix: Optional[str] = None) -> Optional[RulesBundle]:
        """Retrieves the active rules bundle from the cache.
        
        Args:
            cache_key_suffix: Optional tenant identifier for key isolation.
        """
        raise NotImplementedError

    @abstractmethod
    async def store_bundle(self, bundle: RulesBundle, cache_key_suffix: Optional[str] = None, ttl_seconds: Optional[int] = None):
        """Stores a rules bundle in the cache.
        
        Args:
            bundle: RulesBundle to cache.
            cache_key_suffix: Optional tenant identifier for key isolation.
            ttl_seconds: Optional time-to-live in seconds.
        """
        raise NotImplementedError

    @abstractmethod
    async def invalidate_bundle(self, cache_key_suffix: Optional[str] = None):
        """Invalidates/deletes the active rules bundle from the cache.
        
        Args:
            cache_key_suffix: Optional tenant identifier for key isolation.
        """
        raise NotImplementedError

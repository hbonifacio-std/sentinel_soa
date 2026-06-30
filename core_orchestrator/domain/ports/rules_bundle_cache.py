# core_orchestrator/domain/ports/rules_bundle_cache.py
from abc import ABC, abstractmethod
from typing import Optional

from core_orchestrator.domain.models.rules import RulesBundle


class RulesBundleCachePort(ABC):
    """
    Port for managing the active rules bundle in a cache.
    """

    @abstractmethod
    async def get_bundle(self) -> Optional[RulesBundle]:
        """Retrieves the active rules bundle from the cache."""
        raise NotImplementedError

    @abstractmethod
    async def store_bundle(self, bundle: RulesBundle, ttl_seconds: Optional[int] = None):
        """Stores a rules bundle in the cache."""
        raise NotImplementedError

    @abstractmethod
    async def invalidate_bundle(self):
        """Invalidates/deletes the active rules bundle from the cache."""
        raise NotImplementedError

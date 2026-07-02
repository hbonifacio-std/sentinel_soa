# core_orchestrator/domain/ports/cache_port.py
from abc import ABC, abstractmethod
from typing import Any, Optional


class CachePort(ABC):
    """
    An abstract port defining the interface for a generic key-value cache.
    """

    @abstractmethod
    async def get(self, key: str) -> Optional[Any]:
        """Gets a value from the cache by key."""
        raise NotImplementedError

    @abstractmethod
    async def set(self, key: str, value: Any, expire_seconds: Optional[int] = None):
        """Sets a value in the cache with an optional expiration."""
        raise NotImplementedError

    @abstractmethod
    async def delete(self, key: str):
        """Deletes a value from the cache by key."""
        raise NotImplementedError

# core_orchestrator/domain/ports/telemetry_window_cache.py
from abc import ABC, abstractmethod
from typing import List, Any, Optional


class TelemetryWindowCachePort(ABC):
    """
    Port for abstracting the caching mechanism for telemetry windows.
    This decouples the TelemetryProcessingService from a specific
    cache implementation (e.g., Redis lists).
    """

    @abstractmethod
    async def add_to_window(self, key: str, value: Any, expire_seconds: int):
        """Adds a single event to a window."""
        raise NotImplementedError

    @abstractmethod
    async def add_multiple_to_window(self, key: str, values: List[Any], expire_seconds: int):
        """Adds multiple events to a window efficiently."""
        raise NotImplementedError

    @abstractmethod
    async def get_active_window_keys(self, pattern: str) -> List[str]:
        """Gets all keys matching a certain pattern."""
        raise NotImplementedError

    @abstractmethod
    async def get_window_size(self, key: str) -> int:
        """Returns the number of events in a window."""
        raise NotImplementedError

    @abstractmethod
    async def get_and_clear_window(self, key: str) -> Optional[List[Any]]:
        """Atomically retrieves all events from a window and deletes it."""
        raise NotImplementedError

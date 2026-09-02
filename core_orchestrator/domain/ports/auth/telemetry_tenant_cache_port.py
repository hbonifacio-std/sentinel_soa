"""
Defines the repository interface for telemetry client persistence.
"""
from abc import ABC, abstractmethod
from typing import List, Optional

from core_orchestrator.domain.entities.auth.telemetry_client import TelemetryClientInDB, TelemetryClientCreate
from core_orchestrator.domain.entities.auth.tenant import Tenant


class TelemetryTenantCachePort(ABC):
    """
    Defines an abstract base class for telemetry tenant cache operations.

    This class serves as a blueprint for caching mechanisms used to store and retrieve
    telemetry tenant information. It ensures a consistent interface for building cache
    keys, fetching tenant data from a cache, caching tenant data, and invalidating
    specific cache entries.
    """

    @abstractmethod
    def _build_key(self, client_id: str) -> str:
        """
        Builds a key for the given client identifier.

        This method is an abstract method and should be implemented by subclasses
        to define the logic for constructing a key based on a client identifier.

        Parameters:
        client_id : str
            The unique identifier for the client.

        Returns:
        str
            A string representing the constructed key.

        Raises:
        NotImplementedError
            If the method is not implemented by a subclass.
        """
        pass

    @abstractmethod
    async def fetch_cached_tenant(self, client_id: str) -> Optional[str]:
        """
        Abstract method to fetch the cached tenant identifier based on the client ID.

        This method is intended to be implemented in a subclass. It retrieves the
        cached tenant identifier associated with the provided client ID, if available.

        Parameters:
        client_id: str
            The identifier of the client for which the cached tenant is to be retrieved.

        Returns:
        Optional[str]
            The tenant identifier if found in the cache, otherwise None.
        """
        pass


    @abstractmethod
    async def cache_tenant(self,client_id: str, tenant: str) -> None:
        """
        An abstract method to cache tenant information.

        This method is a coroutine and must be implemented by subclasses to define
        how tenant information should be cached.

        Parameters:
            tenant (Tenant): The tenant to be cached.
        """
        pass
    
    async def invalidate(self, client_id: str) -> None:
        """
        Invalidates a specific client session.

        This method removes the session or cached authentication for a given
        client ID, effectively logging out the client or invalidating their
        current authentication state.

        Parameters:
        client_id: str
            The ID of the client whose session is to be invalidated.

        Returns:
            None
        """
        pass


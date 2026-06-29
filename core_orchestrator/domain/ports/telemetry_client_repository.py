"""
Defines the repository interface for telemetry client persistence.
"""
from abc import ABC, abstractmethod
from typing import List, Optional

from core_orchestrator.domain.models.telemetry_client import TelemetryClientInDB, TelemetryClientCreate


class TelemetryClientRepository(ABC):
    """
    Port for telemetry client persistence operations.
    """

    @abstractmethod
    async def get(self, client_id: str) -> Optional[TelemetryClientInDB]:
        """
        Retrieves a telemetry client by its ID.
        """
        pass

    @abstractmethod
    async def get_by_public_key(self, public_key: str) -> Optional[TelemetryClientInDB]:
        """
        Retrieves a telemetry client by its public key.
        """
        pass

    @abstractmethod
    async def create(self, client_create: TelemetryClientCreate) -> TelemetryClientInDB:
        """
        Creates a new telemetry client.
        """
        pass
    
    @abstractmethod
    async def list_all(self, include_inactive: bool = False) -> List[TelemetryClientInDB]:
        """
        Lists all telemetry clients.
        """
        pass

    @abstractmethod
    async def upsert(self, client_create: TelemetryClientCreate, overwrite_existing: bool) -> tuple[TelemetryClientInDB, bool, bool]:
        """
        Upserts a telemetry client.
        """
        pass
    
    async def get_by_client_id(self, client_id: str, include_inactive: bool = False) -> Optional[TelemetryClientInDB]:
        """
        Retrieves a telemetry client by its client_id.
        """
        pass


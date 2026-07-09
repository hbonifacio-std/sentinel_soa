"""
Tenant repository port definition.

Defines the interface for tenant persistence operations.
Supports both multi-tenancy and telemetry client authentication.
"""

from abc import ABC, abstractmethod
from typing import Optional, List

from core_orchestrator.domain.models.auth.tenant import TenantInDB, TenantCreate


class TenantRepository(ABC):
    """Port for tenant persistence operations."""

    @abstractmethod
    async def get(self, tenant_id: str) -> Optional[TenantInDB]:
        """Get tenant by ID."""
        pass

    @abstractmethod
    async def get_by_api_key_hash(self, api_key_hash: str) -> Optional[TenantInDB]:
        """Get tenant by API key hash (for tenant authentication)."""
        pass

    @abstractmethod
    async def get_by_client_id(self, client_id: str, include_inactive: bool = False) -> Optional[TenantInDB]:
        """Get tenant by client ID (for telemetry client authentication)."""
        pass

    @abstractmethod
    async def get_by_api_key(self, api_key: str) -> Optional[TenantInDB]:
        """Get tenant by telemetry API key (for direct API key auth)."""
        pass

    @abstractmethod
    async def get_by_hmac_public_key(self, public_key: str) -> Optional[TenantInDB]:
        """Get tenant by HMAC public key (for HMAC signature verification)."""
        pass

    @abstractmethod
    async def create(self, tenant_create: TenantCreate, api_key_hash: str, api_key_plaintext: str) -> TenantInDB:
        """Create a new tenant."""
        pass

    @abstractmethod
    async def list_all(self, include_inactive: bool = False) -> List[TenantInDB]:
        """List all tenants."""
        pass

    @abstractmethod
    async def update(self, tenant_id: str, **kwargs) -> Optional[TenantInDB]:
        """Update tenant fields."""
        pass

    @abstractmethod
    async def delete(self, tenant_id: str) -> bool:
        """Delete a tenant."""
        pass

    @abstractmethod
    async def ensure_indexes(self) -> None:
        """Ensure database indexes are created."""
        pass

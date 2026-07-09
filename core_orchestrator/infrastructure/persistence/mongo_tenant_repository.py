"""
MongoDB implementation of the tenant repository.
"""

import logging
from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from core_orchestrator.infrastructure.config.database import DatabaseManager
from core_orchestrator.domain.ports.auth.tenant_repository import TenantRepository
from core_orchestrator.domain.models.auth.tenant import TenantInDB, TenantCreate

logger = logging.getLogger(__name__)


class MongoTenantRepository(TenantRepository):
    """
    MongoDB implementation for tenant persistence.
    Supports both tenant authentication and telemetry client authentication.
    """

    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager
        self.collection = db_manager.get_auth_db()["tenants"]

    async def get(self, tenant_id: str) -> Optional[TenantInDB]:
        tenant_doc = await self.collection.find_one({"tenant_id": tenant_id})
        if tenant_doc:
            return TenantInDB(**tenant_doc)
        return None

    async def get_by_api_key_hash(self, api_key_hash: str) -> Optional[TenantInDB]:
        """Get tenant by tenant API key hash (for tenant OAuth flow)."""
        tenant_doc = await self.collection.find_one({"api_key_hash": api_key_hash})
        if tenant_doc:
            return TenantInDB(**tenant_doc)
        return None

    async def get_by_client_id(self, client_id: str, include_inactive: bool = False) -> Optional[TenantInDB]:
        """Get tenant by client_id (for telemetry client authentication)."""
        query = {"client_id": client_id}
        if not include_inactive:
            query["is_active"] = True
        
        tenant_doc = await self.collection.find_one(query)
        if tenant_doc:
            return TenantInDB(**tenant_doc)
        return None

    async def get_by_api_key(self, api_key: str) -> Optional[TenantInDB]:
        """Get tenant by telemetry API key (for direct API key auth)."""
        tenant_doc = await self.collection.find_one({
            "api_key": api_key,
            "is_active": True
        })
        if tenant_doc:
            return TenantInDB(**tenant_doc)
        return None

    async def get_by_hmac_public_key(self, public_key: str) -> Optional[TenantInDB]:
        """Get tenant by HMAC public key (for HMAC signature verification)."""
        tenant_doc = await self.collection.find_one({
            "hmac_public_key": public_key,
            "is_active": True
        })
        if tenant_doc:
            return TenantInDB(**tenant_doc)
        return None

    async def create(
        self, 
        tenant_create: TenantCreate, 
        api_key_hash: str, 
        api_key_plaintext: str
    ) -> TenantInDB:
        """Create a new tenant with API key hash and plaintext."""
        now = datetime.now(timezone.utc)

        tenant_doc = {
            "tenant_id": tenant_create.tenant_id,
            "display_name": tenant_create.display_name,
            "api_key_hash": api_key_hash,
            "api_key_plaintext": api_key_plaintext,
            "rate_limit_per_minute": tenant_create.rate_limit_per_minute,
            "is_active": tenant_create.is_active,
            "client_id": tenant_create.client_id,
            "source_id": tenant_create.source_id,
            "description": tenant_create.description,
            "api_key": tenant_create.api_key,
            "hmac_public_key": tenant_create.hmac_public_key,
            "hmac_secret": tenant_create.hmac_secret,
            "created_at": now,
            "updated_at": now,
        }

        await self.collection.insert_one(tenant_doc)
        logger.info(f"Tenant created: {tenant_create.tenant_id} ({tenant_create.display_name})")

        return TenantInDB(**tenant_doc)

    async def list_all(self, include_inactive: bool = False) -> List[TenantInDB]:
        query = {} if include_inactive else {"is_active": True}
        cursor = self.collection.find(query)
        tenants = await cursor.to_list(length=None)
        return [TenantInDB(**doc) for doc in tenants]

    async def update(self, tenant_id: str, **kwargs) -> Optional[TenantInDB]:
        """Update tenant fields."""
        if not kwargs:
            return await self.get(tenant_id)

        kwargs["updated_at"] = datetime.now(timezone.utc)
        
        result = await self.collection.find_one_and_update(
            {"tenant_id": tenant_id},
            {"$set": kwargs},
            return_document=True
        )
        
        if result:
            return TenantInDB(**result)
        return None

    async def delete(self, tenant_id: str) -> bool:
        """Delete a tenant."""
        result = await self.collection.delete_one({"tenant_id": tenant_id})
        if result.deleted_count > 0:
            logger.info(f"Tenant deleted: {tenant_id}")
            return True
        return False

    async def ensure_indexes(self) -> None:
        """Ensure unique indexes required by the tenants collection."""
        await self.collection.create_index("tenant_id", unique=True)
        await self.collection.create_index("api_key_hash", unique=True, sparse=True)
        await self.collection.create_index("client_id", unique=True, sparse=True)
        await self.collection.create_index("api_key", unique=True, sparse=True)
        await self.collection.create_index("hmac_public_key", unique=True, sparse=True)

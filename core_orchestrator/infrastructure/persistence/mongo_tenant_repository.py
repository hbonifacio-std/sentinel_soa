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
        self.collection = db_manager.get_auth_db()["authorized_telemetry_clients"]

    async def get(self, tenant_id: str) -> Optional[TenantInDB]:
        tenant_doc = await self.collection.find_one({"client_id": tenant_id})
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

    async def create(
        self, 
        tenant_create: TenantCreate, 
        api_key_hash: str, 
        api_key_plaintext: str
    ) -> TenantInDB:
        """Create a new tenant with API key hash (plaintext not stored)."""
        now = datetime.now(timezone.utc)

        tenant_doc = {
            "client_id": tenant_create.client_id,
            "display_name": tenant_create.display_name,
            "api_key_hash": api_key_hash,
            "rate_limit_per_minute": getattr(tenant_create, 'rate_limit_per_minute', 60),
            "is_active": getattr(tenant_create, 'is_active', True),
            "description": tenant_create.description,
            "created_at": now,
            "updated_at": now,
        }

        await self.collection.insert_one(tenant_doc)
        logger.info(f"Tenant created: {tenant_create.client_id} ({tenant_create.display_name})")

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
            {"client_id": tenant_id},
            {"$set": kwargs},
            return_document=True
        )
        
        if result:
            return TenantInDB(**result)
        return None

    async def delete(self, tenant_id: str) -> bool:
        """Delete a tenant."""
        result = await self.collection.delete_one({"client_id": tenant_id})
        if result.deleted_count > 0:
            logger.info(f"Tenant deleted: {tenant_id}")
            return True
        return False

    async def ensure_indexes(self) -> None:
        """Ensure unique indexes required by the tenants collection."""
        await self.collection.create_index("client_id", unique=True)
        await self.collection.create_index([("client_id", 1), ("ai_providers.provider", 1)])

    async def update_provider(self, client_id: str, provider_config: dict) -> Optional[TenantInDB]:
        """Add or update an AI provider configuration for a tenant."""
        now = datetime.now(timezone.utc)
        # Pull existing provider configuration if present
        provider_name = provider_config["provider"]
        await self.collection.update_one(
            {"client_id": client_id},
            {"$pull": {"ai_providers": {"provider": provider_name}}}
        )
        # Push new provider configuration
        result = await self.collection.find_one_and_update(
            {"client_id": client_id},
            {
                "$push": {"ai_providers": provider_config},
                "$set": {"updated_at": now}
            },
            return_document=True
        )
        if result:
            return TenantInDB(**result)
        return None

    async def remove_provider(self, client_id: str, provider_name: str) -> Optional[TenantInDB]:
        """Remove an AI provider configuration and associated models for a tenant."""
        now = datetime.now(timezone.utc)
        tenant = await self.get(client_id)
        if not tenant:
            return None

        # Clean models tied to this provider
        new_models = {
            mid: mdef.model_dump() for mid, mdef in tenant.available_models.items()
            if mdef.provider != provider_name
        }
        new_default = tenant.default_log_analysis_model_id
        if new_default and new_default not in new_models:
            new_default = None

        result = await self.collection.find_one_and_update(
            {"client_id": client_id},
            {
                "$pull": {"ai_providers": {"provider": provider_name}},
                "$set": {
                    "available_models": new_models,
                    "default_log_analysis_model_id": new_default,
                    "updated_at": now
                }
            },
            return_document=True
        )
        if result:
            return TenantInDB(**result)
        return None

    async def update_model(self, client_id: str, model_id: str, model_def: dict) -> Optional[TenantInDB]:
        """Add or update a model definition in the tenant's available_models map."""
        now = datetime.now(timezone.utc)
        result = await self.collection.find_one_and_update(
            {"client_id": client_id},
            {
                "$set": {
                    f"available_models.{model_id}": model_def,
                    "updated_at": now
                }
            },
            return_document=True
        )
        if result:
            return TenantInDB(**result)
        return None

    async def remove_model(self, client_id: str, model_id: str) -> Optional[TenantInDB]:
        """Remove a model definition from tenant's available_models map."""
        now = datetime.now(timezone.utc)
        tenant = await self.get(client_id)
        if not tenant:
            return None

        new_default = tenant.default_log_analysis_model_id
        if new_default == model_id:
            new_default = None

        result = await self.collection.find_one_and_update(
            {"client_id": client_id},
            {
                "$unset": {f"available_models.{model_id}": ""},
                "$set": {
                    "default_log_analysis_model_id": new_default,
                    "updated_at": now
                }
            },
            return_document=True
        )
        if result:
            return TenantInDB(**result)
        return None

    async def set_default_log_analysis_model(self, client_id: str, model_id: Optional[str]) -> Optional[TenantInDB]:
        """Set or unset the default model used for background log analysis."""
        now = datetime.now(timezone.utc)
        result = await self.collection.find_one_and_update(
            {"client_id": client_id},
            {
                "$set": {
                    "default_log_analysis_model_id": model_id,
                    "updated_at": now
                }
            },
            return_document=True
        )
        if result:
            return TenantInDB(**result)
        return None

    async def set_default_mongo_translator_model(self, client_id: str, model_id: Optional[str]) -> Optional[TenantInDB]:
        """Set or unset the default model used for NLQ to MongoDB query translation."""
        now = datetime.now(timezone.utc)
        result = await self.collection.find_one_and_update(
            {"client_id": client_id},
            {
                "$set": {
                    "default_mongo_translator_model_id": model_id,
                    "updated_at": now
                }
            },
            return_document=True
        )
        if result:
            return TenantInDB(**result)
        return None

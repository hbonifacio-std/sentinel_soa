"""
Tenant service - Application layer use cases for tenant management.

Orchestrates tenant creation, retrieval, and management with proper validation.
Also handles telemetry client authentication (API keys, HMAC verification).
"""

import logging
import secrets
import hashlib
import hmac
import time
from typing import Optional, List, Tuple

from core_orchestrator.domain.ports.auth.tenant_repository import TenantRepository
from core_orchestrator.domain.models.auth.tenant import TenantInDB, TenantCreate, TenantResponseWithKey
from core_orchestrator.domain.models.auth.telemetry_client import TelemetryClientAuthContext
from core_orchestrator.infrastructure.security.api_key_utils import (
    hash_api_key,
    verify_api_key,
    is_bcrypt_hash,
    is_sha256_hash,
)

logger = logging.getLogger(__name__)


class TenantService:
    """
    Service for tenant management operations.
    
    Handles business logic for:
    - Creating, updating, and managing tenants
    - Tenant API key generation and validation
    - Telemetry client authentication (API keys, HMAC signatures)
    - HMAC signature verification for incoming telemetry
    """

    def __init__(self, tenant_repository: TenantRepository):
        self.tenant_repository = tenant_repository

    # ========== TENANT MANAGEMENT ==========

    async def create_tenant(self, tenant_create: TenantCreate) -> TenantResponseWithKey:
        """
        Create a new tenant with auto-generated API key.
        
        Args:
            tenant_create: Tenant creation request (only client_id, display_name, description)
            
        Returns:
            Tenant response with plaintext API key (shown only once)
        """
        # Generate secure API key
        api_key_plaintext = f"sk_{secrets.token_urlsafe(32)}"
        # 2. Hash SHA-256 ultra rápido
        api_key_hash = hashlib.sha256(api_key_plaintext.encode("utf-8")).hexdigest()
        
        # Create tenant with generated API key
        tenant_in_db = await self.tenant_repository.create(
            tenant_create=tenant_create,
            api_key_hash=api_key_hash,
            api_key_plaintext=api_key_plaintext
        )
        
        # Return with plaintext key (only shown once)
        return TenantResponseWithKey(
            client_id=tenant_in_db.client_id,
            display_name=tenant_in_db.display_name,
            description=tenant_in_db.description,
            rate_limit_per_minute=tenant_in_db.rate_limit_per_minute,
            is_active=tenant_in_db.is_active,
            created_at=tenant_in_db.created_at,
            updated_at=tenant_in_db.updated_at,
            api_key_plaintext=api_key_plaintext
        )

    async def get_tenant(self, tenant_id: str) -> Optional[TenantInDB]:
        """Get tenant by ID."""
        return await self.tenant_repository.get(tenant_id)

    async def get_tenant_by_api_key(self, api_key: str) -> Optional[TenantInDB]:
        """
        Get tenant by tenant API key (authenticate the key).
        
        Args:
            api_key: Plaintext API key
            
        Returns:
            Tenant if key is valid and active, None otherwise
        """
        # Retrieve tenant by client_id first (if available)
        # Then verify the API key using constant-time comparison
        tenants = await self.tenant_repository.list_all(include_inactive=False)
        
        for tenant in tenants:
            # Support both SHA256 (legacy) and bcrypt (new) formats
            if is_bcrypt_hash(tenant.api_key_hash):
                # New bcrypt format - use constant-time comparison
                if verify_api_key(api_key, tenant.api_key_hash):
                    logger.info(f"API key verified for tenant: {tenant.client_id}")
                    return tenant
            elif is_sha256_hash(tenant.api_key_hash):
                # Legacy SHA256 format - still supported but should migrate
                api_key_sha256 = hashlib.sha256(api_key.encode()).hexdigest()
                if api_key_sha256 == tenant.api_key_hash:
                    logger.warning(
                        f"Legacy SHA256 hash detected for tenant: {tenant.client_id}. "
                        "Please migrate to bcrypt on next authentication."
                    )
                    return tenant
        
        logger.warning(f"No tenant found for API key")
        return None

    async def list_tenants(self, include_inactive: bool = False) -> List[TenantInDB]:
        """List all tenants."""
        return await self.tenant_repository.list_all(include_inactive=include_inactive)

    async def update_tenant(self, tenant_id: str, **kwargs) -> Optional[TenantInDB]:
        """Update tenant fields."""
        return await self.tenant_repository.update(tenant_id, **kwargs)

    async def deactivate_tenant(self, tenant_id: str) -> Optional[TenantInDB]:
        """Deactivate a tenant."""
        return await self.tenant_repository.update(tenant_id, is_active=False)

    async def activate_tenant(self, tenant_id: str) -> Optional[TenantInDB]:
        """Activate a tenant."""
        return await self.tenant_repository.update(tenant_id, is_active=True)

    async def delete_tenant(self, tenant_id: str) -> bool:
        """Delete a tenant (use with caution)."""
        return await self.tenant_repository.delete(tenant_id)

    # ========== TELEMETRY CLIENT AUTHENTICATION ==========

    async def authorize_api_key(self, client_id: str, api_key: str) -> Optional[TelemetryClientAuthContext]:
        """
        Authorize a telemetry client via API key.
        
        Args:
            client_id: The client identifier
            api_key: The API key
            
        Returns:
            TelemetryClientAuthContext if valid, None otherwise
        """
        # Get tenant by client_id
        tenant = await self.tenant_repository.get_by_client_id(client_id, include_inactive=False)
        if not tenant:
            logger.warning(f"Client not found: {client_id}")
            return None
        
        # Verify API key matches
        if tenant.api_key != api_key:
            logger.warning(f"Invalid API key for client: {client_id}")
            return None
        
        return TelemetryClientAuthContext(
            client_id=tenant.client_id,
            display_name=tenant.display_name,
            hmac_public_key=tenant.hmac_public_key,
        )

    async def authorize_hmac(
        self,
        public_key: str,
        signature: str,
        timestamp: int,
        body: bytes
    ) -> Optional[TelemetryClientAuthContext]:
        """
        Authorize a telemetry client via HMAC signature.
        
        Args:
            public_key: The HMAC public key (identifier)
            signature: The HMAC-SHA256 signature
            timestamp: Request timestamp (seconds since epoch)
            body: Request body
            
        Returns:
            TelemetryClientAuthContext if signature valid, None otherwise
        """
        # Get tenant by HMAC public key
        tenant = await self.tenant_repository.get_by_hmac_public_key(public_key)
        if not tenant:
            logger.warning(f"Tenant not found for public key: {public_key}")
            return None
        
        # Verify timestamp is recent (within 5 minutes)
        current_time = int(time.time())
        if abs(current_time - timestamp) > 300:
            logger.warning(f"Timestamp too old for public key: {public_key}")
            return None
        
        # Reconstruct signature
        message = f"{timestamp}:{body.decode('utf-8')}"
        expected_signature = hmac.new(
            tenant.hmac_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Constant-time comparison
        if not hmac.compare_digest(signature, expected_signature):
            logger.warning(f"HMAC verification failed for public key: {public_key}")
            return None
        
        return TelemetryClientAuthContext(
            client_id=tenant.client_id,
            display_name=tenant.display_name,
            hmac_public_key=tenant.hmac_public_key,
        )

    async def get_client_by_client_id(self, client_id: str, include_inactive: bool = False) -> Optional[TenantInDB]:
        """Get tenant acting as telemetry client by client_id."""
        return await self.tenant_repository.get_by_client_id(client_id, include_inactive=include_inactive)

    async def list_clients(self, include_inactive: bool = False) -> List[TenantInDB]:
        """List all tenants that are telemetry clients."""
        tenants = await self.tenant_repository.list_all(include_inactive=include_inactive)
        return [t for t in tenants if t.client_id]

    async def upsert_client(self, client_create: TenantCreate, overwrite_existing: bool = False) -> Tuple[TenantInDB, bool, bool]:
        """
        Upsert a telemetry client (from migration or bootstrap).
        
        Returns:
            Tuple of (tenant, is_new, is_updated)
        """
        existing = await self.get_client_by_client_id(client_create.client_id, include_inactive=True)
        
        if existing:
            if overwrite_existing:
                # Update existing
                updated = await self.update_tenant(
                    existing.client_id,
                    api_key=client_create.api_key,
                    hmac_public_key=client_create.hmac_public_key,
                    hmac_secret=client_create.hmac_secret,
                    display_name=client_create.display_name,
                    description=client_create.description,
                    is_active=client_create.is_active,
                )
                return updated, False, True
            else:
                return existing, False, False
        else:
            # Create new
            api_key_plaintext = f"sk_{secrets.token_urlsafe(32)}"
            api_key_hash = hashlib.sha256(api_key_plaintext.encode()).hexdigest()
            created = await self.tenant_repository.create(client_create, api_key_hash, api_key_plaintext)
            return created, True, False

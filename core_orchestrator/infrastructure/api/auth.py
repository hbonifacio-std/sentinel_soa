import os
import hashlib
from dataclasses import dataclass
from fastapi import Header, HTTPException, Request, status, Depends
from core_orchestrator.infrastructure.config.database import DatabaseManager
from core_orchestrator.infrastructure.api.dependencies import get_db_manager
from core_orchestrator.domain.models.auth.telemetry_client import TelemetryClientAuthContext
from core_orchestrator.infrastructure.security.dependencies import verify_api_key_header


@dataclass
class TenantContext:
    client_id: str
    display_name: str
    rate_limit_per_minute: int


async def require_api_key(x_api_key: str = Header(default=None)):
    """Simple API key check used for machine-to-machine authentication.

    Fail-closed: if SENTINEL_API_KEY is not configured, reject requests.
    """
    API_KEY = os.getenv("SENTINEL_API_KEY")
    if not API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured on this server.",
        )
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )
    return True


async def _get_tenant_and_validate_key(
    client_id: str,
    api_key: str,
    auth_db
) -> dict:
    """
    Retrieve tenant by client_id and validate API key hash.
    
    Args:
        client_id: Tenant client identifier
        api_key: Plaintext API key from request header
        auth_db: MongoDB auth database instance
        
    Returns:
        Tenant document if valid, None otherwise
        
    Process:
        1. Query tenant by client_id in authorized_telemetry_clients
        2. Verify tenant is active
        3. Hash provided API key (SHA256)
        4. Compare with stored api_key_hash
    """
    if not client_id or not api_key or auth_db is None:
        return None
    
    # Step 1: Get tenant by client_id from authorized_telemetry_clients collection
    tenant_doc = await auth_db["authorized_telemetry_clients"].find_one({
        "client_id": client_id,
        "is_active": True
    })

    if not tenant_doc:
        return None
    
    # Step 2: Validate API key hash matches
    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    stored_hash = tenant_doc.get("api_key_hash")
    
    if not stored_hash or api_key_hash != stored_hash:
        return None
    
    return tenant_doc


async def get_tenant_context(
    request: Request,
    x_api_key: str = Header(default=None, alias="x-sentinel-api-key"),
    x_client_id: str = Header(default=None, alias="x-sentinel-client-id"),
    db_manager: DatabaseManager = Depends(get_db_manager),
    client: TelemetryClientAuthContext = Depends(verify_api_key_header),
) -> TenantContext:
    """Derive the tenant context.

    Behavior:
      - Primary: X-Sentinel-API-Key + X-Sentinel-Client-ID → Query by client_id + validate hash
      - Fallback: Verified telemetry client context (for backwards compatibility)
      - Fail-closed if ENFORCE_TENANT_AUTH=true and no valid credentials
    """
    enforce = os.getenv("ENFORCE_TENANT_AUTH", "false").lower() == "true"

    # If DB is not connected and enforcement is on, fail fast
    if db_manager.mongo_client is None:
        if enforce:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, 
                "Tenant resolution requires a connected database."
            )
        # fallback to derived tenant below

    auth_db = None
    if db_manager.mongo_client is not None:
        auth_db = db_manager.get_auth_db()

    # Primary flow: explicit tenant API key + client_id headers
    if x_api_key and x_client_id and auth_db is not None:
        tenant_doc = await _get_tenant_and_validate_key(x_client_id, x_api_key, auth_db)
        if tenant_doc:
            client_id = tenant_doc["client_id"]
            request.state.client_id = client_id
            request.state.tenant_rate = int(tenant_doc.get("rate_limit_per_minute", 60))
            return TenantContext(
                client_id=client_id,
                display_name=tenant_doc.get("display_name", client_id),
                rate_limit_per_minute=int(tenant_doc.get("rate_limit_per_minute", 60)),
            )
        # API key validation failed
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key or inactive tenant.")

    # No explicit tenant key provided
    if enforce:
        # Fail closed in enforced mode
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing tenant API key or client ID headers.")

    # Backwards-compatible fallback: derive tenant from verified telemetry client
    # (useful for tests and PoC environments where tenants are not yet registered)
    if client:
        derived_client = client.client_id
        request.state.client_id = derived_client
        request.state.tenant_rate = int(os.getenv("DEFAULT_TENANT_RATE", "60"))
        return TenantContext(
            client_id=derived_client,
            display_name=client.display_name,
            rate_limit_per_minute=int(os.getenv("DEFAULT_TENANT_RATE", "60")),
        )

    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Could not determine tenant context.")

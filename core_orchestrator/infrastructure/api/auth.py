import os
import hashlib
from dataclasses import dataclass
from fastapi import Header, HTTPException, Request, status, Depends
from core_orchestrator.infrastructure.config.database import DatabaseManager
from core_orchestrator.infrastructure.api.dependencies import get_db_manager
from core_orchestrator.domain.models.auth.telemetry_client import TelemetryClientAuthContext
from core_orchestrator.infrastructure.security.dependencies import verify_api_key_header


def _normalize_tenant_id(value: str) -> str:
    if value.startswith("tenant:"):
        return value.split("tenant:", 1)[1]
    return value

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


async def get_tenant_context(
    request: Request,
    x_api_key: str = Header(default=None),
    db_manager: DatabaseManager = Depends(get_db_manager),
    client: TelemetryClientAuthContext = Depends(verify_api_key_header),
) -> TenantContext:
    """Derive the tenant context.

    Behavior:
      - If ENFORCE_TENANT_AUTH=true: require the X-API-Key header and resolve tenant via DB.
      - Otherwise (default for backwards compatibility), if no X-API-Key header is present
        but a verified telemetry client exists (via verify_api_key_header), derive a
        transient tenant context from the client. This preserves tests and legacy flows.
    """
    enforce = os.getenv("ENFORCE_TENANT_AUTH", "false").lower() == "true"

    # If DB is not connected and enforcement is on, fail fast
    if db_manager.mongo_client is None:
        if enforce:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Tenant resolution requires a connected database.")
        # fallback to derived tenant below

    auth_db = None
    if db_manager.mongo_client is not None:
        auth_db = db_manager.get_auth_db()

    # Primary flow: explicit tenant API key header
    if x_api_key and auth_db is not None:
        key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()
        tenant_doc = await auth_db.tenants.find_one({"api_key_hash": key_hash, "is_active": True})
        if not tenant_doc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or inactive tenant credentials.")

        client_id = tenant_doc["client_id"]
        client_id = _normalize_tenant_id(client_id)
        request.state.client_id = client_id
        request.state.tenant_rate = int(tenant_doc.get("rate_limit_per_minute", 60))
        return TenantContext(
            client_id=client_id,
            display_name=tenant_doc.get("display_name", client_id),
            rate_limit_per_minute=int(tenant_doc.get("rate_limit_per_minute", 60)),
        )

    # No explicit tenant key provided
    if enforce:
        # Fail closed in enforced mode
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing tenant API key header.")

    # Backwards-compatible fallback: derive tenant from verified telemetry client
    # (useful for tests and PoC environments where tenants are not yet registered)
    if client:
        derived_client = _normalize_tenant_id(client.client_id)
        request.state.client_id = derived_client
        request.state.tenant_rate = int(os.getenv("DEFAULT_TENANT_RATE", "60"))
        return TenantContext(
            client_id=derived_client,
            display_name=client.display_name,
            rate_limit_per_minute=int(os.getenv("DEFAULT_TENANT_RATE", "60")),
        )

    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Could not determine tenant context.")

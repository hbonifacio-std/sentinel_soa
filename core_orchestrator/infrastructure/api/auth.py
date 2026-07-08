import os
import hashlib
from dataclasses import dataclass
from fastapi import Header, HTTPException, Request, status

@dataclass
class TenantContext:
    tenant_id: str
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


async def get_tenant_context(request: Request, x_api_key: str = Header(default=None)) -> TenantContext:
    """Derive a tenant context from the provided API key.

    This implementation is intentionally minimal: it maps the single configured
    SENTINEL_API_KEY to a default tenant. In production, replace with a DB lookup
    that resolves api_key_hash -> tenant document.
    """
    if not x_api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing X-API-Key header.")

    configured = os.getenv("SENTINEL_API_KEY")
    if configured and x_api_key == configured:
        tenant_id = os.getenv("DEFAULT_TENANT_ID", "default-tenant")
    else:
        # Unknown key — reject
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid tenant credentials.")

    request.state.tenant_id = tenant_id
    return TenantContext(
        tenant_id=tenant_id,
        display_name=tenant_id,
        rate_limit_per_minute=int(os.getenv("DEFAULT_TENANT_RATE", "60")),
    )

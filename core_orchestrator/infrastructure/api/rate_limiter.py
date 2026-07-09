import os
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request
import os

redis_host = os.getenv("REDIS_HOST", "localhost")
redis_port = os.getenv("REDIS_PORT", "6379")
redis_password = os.getenv("REDIS_PASSWORD", "")

if redis_password:
    redis_uri = f"redis://:{redis_password}@{redis_host}:{redis_port}/0"
else:
    redis_uri = f"redis://{redis_host}:{redis_port}/0"


def tenant_or_ip_key(request: Request) -> str:
    """Key function that prefers tenant_id (if set in request.state) over remote IP.

    This ensures rate limiting is applied per tenant rather than per-IP where possible.
    """
    tenant_id = getattr(request.state, "client_id", None)
    if tenant_id:
        return f"{tenant_id}"
    return get_remote_address(request)


limiter = Limiter(
    key_func=tenant_or_ip_key,
    storage_uri=redis_uri
)

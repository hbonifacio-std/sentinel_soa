from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from core_orchestrator.infrastructure.config.settings import orchestrator_settings


def tenant_or_ip_key(request: Request) -> str:
    """
    Generates a unique key based on tenant identification or client IP address.

    This function extracts the `client_id` from the request's state, if available, to generate
    a key identifying the tenant. If no `client_id` is present, it falls back to using the client's
    IP address, which is retrieved from the `X-Forwarded-For` header or the remote address of the
    request.

    Parameters:
        request (Request): The HTTP request object containing state and headers.

    Returns:
        str: A unique key in the format of `tenant:<tenant_id>` if a tenant ID is available,
        or `ip:<client_ip>` if it defaults to the client IP address.
    """
    tenant_id = getattr(request.state, "client_id", None)
    if tenant_id:
        return f"tenant:{tenant_id}"

    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        client_ip = x_forwarded_for.split(",")[0].strip()
    else:
        client_ip = get_remote_address(request)

    return f"ip:{client_ip}"


def _get_redis_auth_uri() -> str:
    """
    Constructs the Redis authentication URI based on the configuration settings.

    This function uses settings defined in `orchestrator_settings.database_redis`,
    which contains values necessary to construct the Redis URI, such as host, port,
    database, and optional password. If a password is present, it is included in
    the constructed URI. Otherwise, an unauthenticated URI is returned.

    Returns:
        str: A formatted Redis authentication URI.
    """
    redis_cfg = orchestrator_settings.database_redis

    host = redis_cfg.host
    port = redis_cfg.port
    db = redis_cfg.auth_db
    password = redis_cfg.password.get_secret_value() if redis_cfg.password else ""

    if password:
        return f"redis://:{password}@{host}:{port}/{db}"
    return f"redis://{host}:{port}/{db}"


def create_limiter(use_memory: bool = False) -> Limiter:
    """
    Creates and returns a configured Limiter instance for rate limiting.

    This function determines the storage backend for the Limiter based on
    the provided arguments and sets up the Limiter with a fixed-window
    strategy. It also specifies a key function and ensures errors are
    swallowed during rate-limiting operations.

    Parameters:
    use_memory: bool, optional
        If True, an in-memory storage backend is used. Otherwise, a
        Redis-based storage backend is configured.

    Returns:
    Limiter
        A configured Limiter instance for rate limiting.
    """
    storage_uri = "memory://" if use_memory else _get_redis_auth_uri()

    return Limiter(
        key_func=tenant_or_ip_key,
        storage_uri=storage_uri,
        strategy="fixed-window",
        swallow_errors=True,
        default_limits=["500/hour", "50/minute"]
    )
limiter = create_limiter()
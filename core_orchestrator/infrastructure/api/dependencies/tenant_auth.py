import logging

from fastapi import Header, HTTPException, Request, status, Depends

from core_orchestrator.application.modules.auth_clients.tenant_service import TenantService
from core_orchestrator.infrastructure.adapters.security.tenant_auth_adapter import TenantContext, validate_tenant_api_key
from core_orchestrator.infrastructure.api.dependencies.general_dependencies import get_db_manager, get_tenant_service
from core_orchestrator.infrastructure.config.settings import orchestrator_settings
from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
from core_orchestrator.domain.entities.auth.telemetry_client import TelemetryClientAuthContext

logger = logging.getLogger("core_orchestrator.security.dependencies")

async def verify_api_key_header(
        x_sentinel_client_id: str = Header(alias="x-sentinel-client-id", default=None, description="Telemetry Client ID"),
        x_sentinel_api_key: str = Header(alias="x-sentinel-api-key", default=None, description="Telemetry API Key"),
        telemetry_client_service: TenantService = Depends(get_tenant_service),
) -> TelemetryClientAuthContext:
    """
    API key verification for telemetry client ingestion.

    Requires both `X-Sentinel-Client-ID` and `X-Sentinel-Api-Key` headers and
    validates them against the authorized telemetry clients store.

    Returns:
        TelemetryClientAuthContext: The verified client context metadata.
    """
    if not x_sentinel_client_id or not x_sentinel_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing telemetry authentication headers"
        )

    client_context = await telemetry_client_service.authorize_api_key(
        client_id=x_sentinel_client_id,
        api_key=x_sentinel_api_key
    )

    if not client_context:
        logger.warning(f"Unauthorized API Key attempt for client_id: {x_sentinel_client_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Client ID or API Key"
        )

    logger.debug(f"API Key successfully verified for client: {x_sentinel_client_id}")
    return TelemetryClientAuthContext(
        client_id=client_context.client_id,
        display_name=client_context.display_name
    )

def get_source_id(
        x_sentinel_source_id: str = Header(..., alias="x-sentinel-source-id",
                                           description="Unique identifier of the telemetry source")
) -> str:
    """Extract and validate source_id from request headers.

    Required for multitenant batch ingestion to segregate telemetry by data source.
    Ensures the header is not empty (whitespace-trimmed).
    """
    if not x_sentinel_source_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Sentinel-Source-ID header cannot be empty"
        )
    return x_sentinel_source_id

def require_api_key(x_api_key: str = Header(default=None)):
    api_key = orchestrator_settings.mcp.api_key_mcp.get_secret_value()
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured on this server.",
        )
    if x_api_key != api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )
    return True


async def get_tenant_context(
    request: Request,
    x_api_key: str = Header(default=None, alias="x-sentinel-api-key"),
    x_client_id: str = Header(default=None, alias="x-sentinel-client-id"),
    db_manager: DatabaseManager = Depends(get_db_manager),
    client: TelemetryClientAuthContext = Depends(verify_api_key_header),
) -> TenantContext:

    enforce = orchestrator_settings.tenant_config.enforce_auth
    default_tenant_rate = orchestrator_settings.tenant_config.default_rate_limit

    if db_manager.mongo_client is None and enforce:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Tenant resolution requires a connected database."
            )

    auth_db = db_manager.get_auth_db() if db_manager.mongo_client is not None else None

    if x_api_key and x_client_id and auth_db is not None:
        tenant_doc = await validate_tenant_api_key(x_client_id, x_api_key, auth_db)
        if tenant_doc:
            client_id = tenant_doc["client_id"]
            display_name = tenant_doc.get("display_name", "No display name provided.")
            request.state.client_id = client_id
            request.state.tenant_rate = int(tenant_doc.get("rate_limit_per_minute", 60))
            return TenantContext(
                client_id=client_id,
                display_name=display_name,
                rate_limit_per_minute=int(tenant_doc.get("rate_limit_per_minute", 60)),
            )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key or inactive tenant.")

    if enforce:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing tenant API key or client ID headers.")

    if client:
        derived_client = client.client_id
        request.state.client_id = derived_client
        request.state.tenant_rate =default_tenant_rate
        return TenantContext(
            client_id=derived_client,
            display_name=client.display_name,
            rate_limit_per_minute=default_tenant_rate,
        )

    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Could not determine tenant context.")
"""
Entry Point and Master Configuration for the Core Orchestrator.

Initializes the FastAPI application, orchestrates the MCP subprocess lifecycles,
and mounts the HTTP routes exposed to the corporate network.
"""
import logging
import inspect
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, status, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from core_orchestrator.domain.exceptions.domain_exceptions import DomainException
from core_orchestrator.application.modules.telemetry.telemetry_analysis_orchestrator_service import TelemetryAnalysisOrchestratorService
from core_orchestrator.infrastructure.api.container import get_container
from core_orchestrator.infrastructure.api.dependencies.general_dependencies import get_agent_runner
from core_orchestrator.infrastructure.api.security_headers import SecurityHeadersMiddleware

from core_orchestrator.infrastructure.api.v1.endpoints import (
    analytics, auth, forensic, rules as refactored_rules_router,
    telemetry as agent_telemetry, users, tenants, tenant_ai_providers
)
from core_orchestrator.infrastructure.config.config import orchestrator_settings_deprecated
from core_orchestrator.infrastructure.handlers.exceptions import (
    validation_exception_handler,
    unhandled_exception_handler, domain_exception_handler,
)

from core_orchestrator.infrastructure.rate_limit.rate_limiter import limiter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("core_orchestrator.main")



@asynccontextmanager
async def app_lifespan(_: FastAPI):
    """
    Asynchronous lifecycle handler (FastAPI Lifespan), delegating to a central container.
    """
    logger.info("=== STARTING SYSTEM BOOT CONFIGURATION ===")
    container = get_container()
    try:
        await container.startup()
        logger.info("=== CORE ORCHESTRATOR DEPLOYED AND OPERATIONAL ===")
        yield
    except Exception as e:
        logger.exception(f"Fatal error during startup: {e}", exc_info=True)
        yield
    finally:
        logger.info("=== INITIATING RESOURCE SHUTDOWN PROCESS ===")
        await container.shutdown()
        logger.info("=== SYSTEM SHUT DOWN CORRECTLY ===")


app = FastAPI(
    title="AI Agent Orchestration Framework - Core",
    version="1.0.0",
    description="Service-oriented platform for intrusion prevention through web telemetry analysis.",
    lifespan=app_lifespan
)


app.state.limiter = limiter



app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(DomainException, domain_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)


app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=orchestrator_settings_deprecated.get_trusted_hosts()
)


app.add_middleware(SecurityHeadersMiddleware)


cors_origins = orchestrator_settings_deprecated.get_cors_origins()
logger.info(f"CORS allowed origins: {cors_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "x-sentinel-client-id",
        "x-sentinel-api-key",
        "x-sentinel-source-id",
        "X-Api-Key"
    ],
)

# Injection and inclusion of version 1 endpoint routers
app.include_router(
    auth.router,
    prefix="/api/v1/auth",
    tags=["Authentication"]
)
app.include_router(
    users.router,
    prefix="/api/v1/users",
    tags=["User Management"]
)
app.include_router(
    tenants.router,
    prefix="/api/v1/tenants",
    tags=["Tenant Management"]
)
app.include_router(
    tenant_ai_providers.router,
    prefix="/api/v1/tenants",
    tags=["Tenant AI Provider Management"]
)
app.include_router(
    agent_telemetry.router,
    prefix="/api/v1/telemetry",
    tags=["Telemetry Ingestion"],
)
app.include_router(
    analytics.router,
    prefix="/api/v1",
    tags=["Analytics"]
)
app.include_router(
    forensic.router,
    prefix="/api/v1/forensic",
    tags=["Forensic"],
)
app.include_router(
    refactored_rules_router.router, # ✨ Using the new refactored router
    prefix="/api/v1/rules",
    tags=["Rules Management"],
)


@app.get("/health", status_code=status.HTTP_200_OK, tags=["System Health"])
async def health_check(agent_runner: Annotated[TelemetryAnalysisOrchestratorService, Depends(get_agent_runner)]):
    """
    Basic monitoring endpoint to check the operational availability of the API.
    """
    mcp_connected = False
    if agent_runner:
        active_probe = getattr(agent_runner, "is_mcp_healthy", None)
        probe_declared = (
            "is_mcp_healthy" in getattr(agent_runner, "__dict__", {})
            or hasattr(type(agent_runner), "is_mcp_healthy")
        )
        if active_probe and probe_declared:
            try:
                probe_result = active_probe()
                if inspect.isawaitable(probe_result):
                    mcp_connected = await probe_result
                else:
                    mcp_connected = bool(probe_result)
            except Exception as exc:
                logger.warning("MCP active health check failed: %s", exc)
                mcp_connected = False
        else:
            mcp_connected = bool(getattr(agent_runner, "is_mcp_connected", False))
    logger.info(f"component core_orchestrator ::  MCP status: {mcp_connected}")
    return {
        "status": "healthy",
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("core_orchestrator.main:app", host="0.0.0.0", port=8000, reload=True)

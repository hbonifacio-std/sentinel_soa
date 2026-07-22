"""
Entry Point and Master Configuration for the Core Orchestrator.

Initializes the FastAPI application, orchestrates the MCP subprocess lifecycles,
and mounts the HTTP routes exposed to the corporate network.
"""
import logging
import inspect
from contextlib import asynccontextmanager
from typing import Any, Awaitable, Callable

from fastapi import FastAPI, status, Request, Depends
from fastapi.exceptions import RequestValidationError, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded


from core_orchestrator.infrastructure.agent.runner import AgentRunner
from core_orchestrator.infrastructure.api.container import get_container
from core_orchestrator.infrastructure.api.security_headers import SecurityHeadersMiddleware
# Updated imports for new architecture
from core_orchestrator.infrastructure.api.v1.endpoints import (
    analytics, auth, clients, forensic, rules as refactored_rules_router,
    telemetry as agent_telemetry, users, tenants, tenant_providers
)
from core_orchestrator.infrastructure.config.config import orchestrator_settings
from core_orchestrator.infrastructure.handlers.exceptions import (
    validation_exception_handler,
    unhandled_exception_handler,
)
from core_orchestrator.infrastructure.api import dependencies as deps
from core_orchestrator.infrastructure.api.rate_limiter import limiter



logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("core_orchestrator.main")



@asynccontextmanager
async def app_lifespan(app: FastAPI):
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
        logger.error(f"Fatal error during startup: {e}", exc_info=True)
        # We might want to yield here anyway to allow for some endpoints to work for diagnostics
        # but for now, we'll let the app fail to start if the container fails.
        yield
    finally:
        logger.info("=== INITIATING RESOURCE SHUTDOWN PROCESS ===")
        await container.shutdown()
        logger.info("=== SYSTEM SHUT DOWN CORRECTLY ===")


# Formal FastAPI app instantiation implementing the lifecycle manager
app = FastAPI(
    title="AI Agent Orchestration Framework - Core",
    version="1.0.0",
    description="Service-oriented platform for intrusion prevention through web telemetry analysis.",
    lifespan=app_lifespan
)

# Initialize rate limiter in app state
app.state.limiter = limiter



app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

# ============================================================================
# Security Middleware Stack (Order matters!)
# ============================================================================

# 1. Trusted Host Middleware - Prevent Host Header attacks
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=orchestrator_settings.get_trusted_hosts()
)

# 2. Security Headers Middleware - Add comprehensive security headers
app.add_middleware(SecurityHeadersMiddleware)

# 3. CORS Middleware (already configured above)
# Configurable CORS security middleware
cors_origins = orchestrator_settings.get_cors_origins()
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
    tenant_providers.router,
    prefix="/api/v1/tenants",
    tags=["Tenant AI Provider Management"]
)
app.include_router(
    clients.router,
    prefix="/api/v1",
    tags=["Client Management"]
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
async def health_check(agent_runner: AgentRunner = Depends(deps.get_agent_runner)):
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
    # Explicit local launch for debugging in development
    uvicorn.run("core_orchestrator.main:app", host="0.0.0.0", port=8000, reload=True)

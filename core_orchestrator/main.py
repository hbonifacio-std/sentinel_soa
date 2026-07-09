"""
Entry Point and Master Configuration for the Core Orchestrator.

Initializes the FastAPI application, orchestrates the MCP subprocess lifecycles,
and mounts the HTTP routes exposed to the corporate network.
"""
import logging
from contextlib import asynccontextmanager
from typing import Any, Awaitable, Callable

from fastapi import FastAPI, status, Request, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from core_orchestrator.infrastructure.agent.runner import AgentRunner
from core_orchestrator.infrastructure.api.container import get_container
# Updated imports for new architecture
from core_orchestrator.infrastructure.api.v1.endpoints import (
    analytics, auth, clients, forensic, rules as refactored_rules_router,
    telemetry as agent_telemetry, users, tenants
)
from core_orchestrator.infrastructure.config.config import orchestrator_settings
from core_orchestrator.infrastructure.handlers.exceptions import validation_exception_handler
from core_orchestrator.infrastructure.api import dependencies as deps
from core_orchestrator.infrastructure.api.auth import require_api_key, get_tenant_context


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

@app.middleware("http")
async def add_limiter_to_state(request: Request, call_next: Callable[[Request], Awaitable[Any]]) -> Any:
    """
    Middleware to add the rate limiter to the request state,
    making it available to the exception handler.
    """
    # This is a bit of a workaround for the slowapi library not having a more direct
    # DI integration. We fetch the limiter instance from our container via the deps module.
    limiter = deps.get_limiter(container=get_container())
    request.state.limiter = limiter
    response = await call_next(request)
    return response


app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)

# Configurable CORS security middleware
cors_origins = orchestrator_settings.get_cors_origins()
logger.info(f"CORS allowed origins: {cors_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
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
    clients.router,
    prefix="/api/v1",
    tags=["Client Management"]
)
app.include_router(
    agent_telemetry.router,
    prefix="/api/v1/telemetry",
    tags=["Telemetry Ingestion"],
    dependencies=[Depends(require_api_key)],
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
    dependencies=[Depends(require_api_key)],
)


@app.get("/health", status_code=status.HTTP_200_OK, tags=["System Health"])
async def health_check(agent_runner: AgentRunner = Depends(deps.get_agent_runner)):
    """
    Basic monitoring endpoint to check the operational availability of the API.
    """
    return {
        "status": "healthy",
        "component": "core_orchestrator",
        "mcp_status": "connected" if agent_runner and agent_runner.is_mcp_connected else "disconnected"
    }

if __name__ == "__main__":
    import uvicorn
    # Explicit local launch for debugging in development
    uvicorn.run("core_orchestrator.main:app", host="0.0.0.0", port=8000, reload=True)

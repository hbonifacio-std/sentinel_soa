"""
Entry Point and Master Configuration for the Core Orchestrator.

Initializes the FastAPI application, orchestrates the MCP subprocess lifecycles,
and mounts the HTTP routes exposed to the corporate network.
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, status, Request, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi import Limiter

from core_orchestrator.agent.runner import AgentRunner
from core_orchestrator.domain.ports.telemetry_repository import TelemetryRepository
# Updated imports for new architecture
from core_orchestrator.infrastructure.api.v1.endpoints import (
    analytics, auth, clients, rules as refactored_rules_router,
    telemetry as agent_telemetry, users
)
from core_orchestrator.infrastructure.config.config import orchestrator_settings
from core_orchestrator.exeptions.exeptions import validation_exception_handler
from core_orchestrator.application.services.rules_engine_service import init_rules_engine
from core_orchestrator.infrastructure.api import dependencies as deps


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("core_orchestrator.main")


@asynccontextmanager
async def app_lifespan(app: FastAPI):
    """
    Asynchronous lifecycle handler (FastAPI Lifespan).
    Ensures the MCP client starts its concurrent subprocesses BEFORE
    opening the HTTP API gates, and shuts them down cleanly when the service stops.
    """
    logger.info("=== STARTING SYSTEM BOOT CONFIGURATION ===")

    db_manager = deps.get_db_manager()
    agent_runner = deps.get_agent_runner(
        telemetry_processing_service=deps.get_telemetry_processing_service(
            cache_service=deps.get_cache_service(db_manager)
        ),
        redis_client=deps.get_redis_client(db_manager),
        telemetry_service=deps.get_telemetry_service(
            repo=deps.get_telemetry_repository(
                db_manager=db_manager
            )
        )
    )
    # Lazily start the agent subsystem and MCP stdio tunnels
    await agent_runner.initialize_subsytem()

    try:
        rule_service = deps.get_rule_service(
            rule_repo=deps.get_rule_repository(db_manager),
            audit_repo=deps.get_audit_repository(db_manager),
            redis=deps.get_redis_client(db_manager)
        )
        rules_engine = init_rules_engine(rules_service=rule_service)

        await rules_engine.initialize()

        logger.info("RulesEngine loaded and ready.")
    except Exception as e:
        logger.warning(f"Failed to boot RulesEngine (DB may not be reachable): {e}. Continuing startup...")

    logger.info("=== CORE ORCHESTRATOR DEPLOYED AND OPERATIONAL ON PORT ===")
    yield
    logger.info("=== INITIATING RESOURCE SHUTDOWN PROCESS ===")
    await agent_runner.shutdown_subsytem()

    db_manager = deps.get_db_manager()
    if db_manager.mongo_client:
        await db_manager.mongo_client.close()
    if db_manager.redis_client:
        await db_manager.redis_client.close()

    logger.info("=== SYSTEM SHUT DOWN CORRECTLY ===")


# Formal FastAPI app instantiation implementing the lifecycle manager
app = FastAPI(
    title="AI Agent Orchestration Framework - Core",
    version="1.0.0",
    description="Service-oriented platform for intrusion prevention through web telemetry analysis.",
    lifespan=app_lifespan
)

@app.middleware("http")
async def add_limiter_to_state(request: Request, call_next):
    """
    Middleware to add the rate limiter to the request state,
    making it available to the exception handler.
    """
    request.state.limiter = deps.get_limiter()
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
    allow_headers=["*"],
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
    clients.router,
    prefix="/api/v1",
    tags=["Client Management"]
)
app.include_router(
    agent_telemetry.router,
    prefix="/api/v1/telemetry",
    tags=["Telemetry Ingestion"]
)
app.include_router(
    analytics.router,
    prefix="/api/v1",
    tags=["Analytics"]
)
app.include_router(
    refactored_rules_router.router, # ✨ Using the new refactored router
    prefix="/api/v1/rules",
    tags=["Rules Management"]
)


@app.get("/health", status_code=status.HTTP_200_OK, tags=["System Health"])
async def health_check(agent_runner: AgentRunner = Depends(deps.get_agent_runner)):
    """
    Basic monitoring endpoint to check the operational availability of the API.
    """
    return {
        "status": "healthy",
        "component": "core_orchestrator",
        "mcp_status": "connected" if agent_runner.agent is not None else "disconnected"
    }

if __name__ == "__main__":
    import uvicorn
    # Explicit local launch for debugging in development
    uvicorn.run("core_orchestrator.main:app", host="0.0.0.0", port=8000, reload=True)

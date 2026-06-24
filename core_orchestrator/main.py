"""
Entry Point and Master Configuration for the Core Orchestrator.

Initializes the FastAPI application, orchestrates the MCP subprocess lifecycles,
and mounts the HTTP routes exposed to the corporate network.
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from core_orchestrator.api.v1.endpoints import agent_telemetry, analytics, rules_management, auth
from core_orchestrator.agent.runner import agent_runner
from core_orchestrator.exeptions.exeptions import validation_exception_handler
from core_orchestrator.services.database import db
from core_orchestrator.services.bootstrap_service import bootstrap_service
from core_orchestrator.services.limiter import limiter
from core_orchestrator.services.rules_engine import get_rules_engine
from core_orchestrator.config import orchestrator_settings

# Centralized production logging configuration
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

    # Connect to databases
    await db.connect_to_mongo()
    await db.connect_to_redis()

    if orchestrator_settings.bootstrap_on_startup:
        try:
            bootstrap_summary = await bootstrap_service.run_startup_bootstrap()
            logger.info("Startup bootstrap completed: %s", bootstrap_summary.model_dump())
        except Exception as e:
            logger.error(f"Startup bootstrap failed: {e}", exc_info=True)
            raise

    # Load heuristic rules from MongoDB / Redis into RulesEngine
    rules_engine = get_rules_engine()
    await rules_engine.initialize()

    # Lazily start the agent subsystem and MCP stdio tunnels
    await agent_runner.initialize_subsytem()

    logger.info("=== CORE ORCHESTRATOR DEPLOYED AND OPERATIONAL ON PORT ===")
    yield

    logger.info("=== INITIATING RESOURCE SHUTDOWN PROCESS ===")
    # Shut down MCP child server subprocesses to avoid zombie processes in the OS
    await agent_runner.shutdown_subsytem()

    # Disconnect from databases
    await db.close_mongo_connection()
    await db.close_redis_connection()

    logger.info("=== SYSTEM SHUT DOWN CORRECTLY ===")


# Formal FastAPI app instantiation implementing the lifecycle manager
app = FastAPI(
    title="AI Agent Orchestration Framework - Core",
    version="1.0.0",
    description="Service-oriented platform for intrusion prevention through web telemetry analysis.",
    lifespan=app_lifespan
)


app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.state.limiter = limiter

# Configurable CORS security middleware
cors_origins = orchestrator_settings.get_cors_origins()
logger.info(f"CORS allowed origins: {cors_origins}")

app.add_middleware(
    CORSMiddleware,  # type: ignore[arg-type]
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
    rules_management.router,
    prefix="/api/v1/rules",
    tags=["Rules Management"]
)


@app.get("/health", status_code=status.HTTP_200_OK, tags=["System Health"])
async def health_check():
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

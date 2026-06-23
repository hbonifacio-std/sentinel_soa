"""
AI Agent Orchestration Runner Module.

Serves as the unified entry point for the REST API to send telemetry payloads
to the agent's cognitive engine and its MCP tools.
"""

import asyncio
import json
import logging
from typing import Dict, Any, Optional

from core_orchestrator.config import orchestrator_settings as settings
from core_orchestrator.agent.mcp_client import MCPClientManager
from core_orchestrator.agent.orchestrator import OrchestratorAgent
from core_orchestrator.services.database import db
from core_orchestrator.services.window_manager import window_manager

logger = logging.getLogger("core_orchestrator.agent.runner")


class AgentRunner:
    """
    Facade responsible for managing the in-memory persistence of the MCP client
    and coordinating concurrent calls to the orchestrator agent.
    """

    def __init__(self):
        self.mcp_manager: Optional[MCPClientManager] = None
        self.agent: Optional[OrchestratorAgent] = None
        self._initialization_task: Optional[asyncio.Task] = None
        self._window_processor_handle: Optional[asyncio.Task] = None
        self._initialized: bool = False

    async def _init_mcp_background(self) -> None:
        """
        Initializes MCP in the background without blocking FastAPI.
        """
        try:
            logger.info("Initializing MCP subsystem...")
            if not self.mcp_manager:
                self.mcp_manager = MCPClientManager(
                    server_script_path=settings.mcp_log_analysis_server_cmd)

            await self.mcp_manager.start_server_session(timeout=60.0)
            self.agent = OrchestratorAgent(mcp_manager=self.mcp_manager)
            self._initialized = True
            logger.info(
                "Agent subsystem and MCP Servers deployed successfully.")
        except Exception as exc:
            logger.error(
                f"Error initializing MCP in the background: {str(exc)}", exc_info=True)
            self._initialized = False
            raise

    async def get_redis_lock(self, lock_key: str, timeout: int = 10):
        """Provides a Redis distributed lock independent of MCP agent state."""
        if db.redis_client is None:
            raise RuntimeError("Redis client is not initialized.")
        return db.redis_client.lock(lock_key, timeout=timeout)

    async def _window_processor_task(self):
        """
        Background task that processes telemetry windows from Redis.
        NOTE: This is a simple approach. For a production system, this could
        be improved by using Redis keyspace notifications to process windows
        as soon as they expire, rather than polling.
        """
        while True:
            try:
                keys = await window_manager.get_active_windows()
                for key in keys:
                    decoded_key = key.decode("utf-8")
                    # We try to get a lock for this key to avoid duplicate processing
                    lock = await self.get_redis_lock(f"lock:{decoded_key}")
                    if await lock.acquire(blocking=False):
                        try:
                            ttl = await db.redis_client.ttl(key)
                            # If the key is about to expire, we process it
                            if ttl < 10:  # 10-second threshold
                                telemetry_window = await window_manager.process_window(decoded_key)
                                if telemetry_window:
                                    asyncio.create_task(self.run_analysis(
                                        telemetry_window.model_dump()))
                        finally:
                            await lock.release()
            except Exception as e:
                logger.error(
                    f"Error in window processor: {e}", exc_info=True)
            # Wait 5 seconds before the next iteration
            await asyncio.sleep(5)

    async def initialize_subsytem(self) -> None:
        """
        Initializes MCP first, then starts the window processor task.
        """
        logger.info("Initializing Agent subsystem and MCP Channels...")
        await self._init_mcp_background()
        self._window_processor_handle = asyncio.create_task(
            self._window_processor_task())
        logger.info("Agent subsystem ready and window processor running.")

    async def wait_for_mcp_ready(self, timeout: float = 30.0) -> bool:
        """
        Waits for MCP to be ready. Useful for the first requests.
        """
        if self._initialized:
            return True

        if self._initialization_task is None:
            logger.error("Agent subsystem is not initialized")
            return False

        try:
            await asyncio.wait_for(self._initialization_task, timeout=timeout)
            return self._initialized
        except asyncio.TimeoutError:
            logger.error(
                f"Timeout waiting for MCP to initialize (>{timeout}s)")
            return False

    async def run_analysis(self, telemetry_window: Dict[str, Any]) -> str:
        """
        Sends a preprocessed time window of HTTP events to the agent for evaluation.
        """
        if not self.agent:
            logger.error("The agent subsystem has not been initialized. Skipping analysis.")
            return json.dumps({
                "status": "error",
                "error": "The agent subsystem has not been initialized.",
                "threat_detected": False,
                "threat_level": "NONE"
            })

        return await self.agent.process_telemetry_window(telemetry_window)

    async def shutdown_subsytem(self) -> None:
        """
        Gracefully releases open resources and subprocesses.
        """
        if self._window_processor_handle:
            self._window_processor_handle.cancel()
            try:
                await self._window_processor_handle
            except asyncio.CancelledError:
                pass
        if self.mcp_manager:
            logger.info("Shutting down MCP communication channels...")
            try:
                await self.mcp_manager.close()
            except RuntimeError as exc:
                logger.warning("MCP shutdown completed with runtime warning: %s", exc)
            logger.info("MCP subsystem shut down correctly.")


# Global singleton instance to be shared throughout the FastAPI application
agent_runner = AgentRunner()

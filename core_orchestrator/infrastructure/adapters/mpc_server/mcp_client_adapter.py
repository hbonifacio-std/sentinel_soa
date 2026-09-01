"""MCP client for the Core Orchestrator.

Uses the MCP Python SDK over native SSE so the core can talk to the
`mcp_server` container without relying on streamable HTTP keep-alive.
"""

import asyncio
import logging
import os
from typing import Any, Dict, Optional
from mcp import ClientSession, ListToolsResult
from mcp.client.sse import sse_client as _sse_client

from core_orchestrator.domain.exceptions.mcp_exceptions import MCPConfigurationError, MCPConnectionError, \
    MCPTimeoutError, MCPClientError, MCPToolExecutionError
from core_orchestrator.domain.ports.mcp_server.mcp_client_port import MCPClientPort
from core_orchestrator.infrastructure.config.settings import orchestrator_settings

logger = logging.getLogger("core_orchestrator.mcp_client")

_MCP_SSE_CONNECT_TIMEOUT_SECONDS = 1200.0
_MCP_START_SERVER_SESSION_TIMEOUT_SECONDS = 10.0
_MCP_SSE_READ_TIMEOUT_SECONDS = 1200.0
_MCP_SESSION_HEARTBEAT_TIMEOUT_SECONDS = 15.0
_MCP_SERVER_SSE_PATH = "/sse"


class MCPClientManagerAdapter(MCPClientPort):
    """
    Manages the lifecycle, configuration, and usage of an MCP client.
    """

    def __init__(self, max_retries: int = 3):
        self._settings = orchestrator_settings.mcp
        self._transport_cm = None
        self._session_cm = None
        self._session: Optional[ClientSession] = None
        self._reconnect_lock = asyncio.Lock()
        self._call_semaphore = asyncio.Semaphore(10)
        self._max_retries = max_retries
        self._token_session = self._settings.api_key_mcp
        self._url = self._settings.url

    def _build_sse_url(self) -> str:
        if not self._url:
            raise MCPConfigurationError(
                setting_name="MCP_SERVER_URL",
                message="Environment variable is empty or not defined."
            )
        return f"{self._url}{_MCP_SERVER_SSE_PATH}"

    async def _open_sse_session(self, url: str) -> ClientSession:
        if not self._token_session:
            raise MCPConfigurationError(
                setting_name="MCP_INTERNAL_TOKEN",
                message="Authentication token is required for MCP SSE transport connection."
            )

        headers = {"Authorization": f"Bearer {self._token_session.get_secret_value()}"}

        try:
            self._transport_cm = _sse_client(
                url,
                headers=headers,
                timeout=_MCP_SSE_CONNECT_TIMEOUT_SECONDS,
                sse_read_timeout=_MCP_SSE_READ_TIMEOUT_SECONDS,
            )
            transport = await self._transport_cm.__aenter__()
            read_stream, write_stream = transport[0], transport[1]
        except Exception as exc:
            raise MCPConnectionError(url=url, original_error=exc) from exc

        try:
            # FIX 1: read_timeout_seconds debe ser float/int, no timedelta
            self._session_cm = ClientSession(
                read_stream,
                write_stream,
                read_timeout_seconds=float(_MCP_SSE_READ_TIMEOUT_SECONDS),
            )
            self._session = await self._session_cm.__aenter__()
            if self._session is None:
                raise MCPConnectionError(
                    url=url,
                    original_error=RuntimeError("ClientSession context manager returned None on entry.")
                )
            await self._session.initialize()
            return self._session
        except Exception as exc:
            await self.close()
            raise MCPConnectionError(url=url, original_error=exc) from exc

    async def start_server_session(self) -> ClientSession:
        transport_mode = (os.getenv("MCP_TRANSPORT") or "sse").lower()
        logger.info("Starting MCP session in transport mode: %s", transport_mode)

        if transport_mode != "sse":
            raise MCPConfigurationError(
                setting_name="MCP_TRANSPORT",
                message=f"Unsupported transport mode '{transport_mode}'. Only 'sse' is supported."
            )

        url = self._build_sse_url()
        logger.info("Configuring MCP client to connect to %s", url)

        try:
            async with asyncio.timeout(_MCP_START_SERVER_SESSION_TIMEOUT_SECONDS):
                return await self._open_sse_session(url)

        except asyncio.TimeoutError as exc:
            raise MCPTimeoutError(
                operation="start_server_session",
                timeout_seconds=_MCP_START_SERVER_SESSION_TIMEOUT_SECONDS
            ) from exc
        except MCPClientError:
            raise
        except Exception as exc:
            logger.critical("Fatal error connecting to MCP server: %s", exc, exc_info=True)
            raise MCPConnectionError(url=url, original_error=exc) from exc

    async def _ensure_active_session(self) -> ClientSession:

        if self._session is not None:
            if await self.is_session_healthy():
                return self._session

        async with self._reconnect_lock:
            if self._session is not None:
                if await self.is_session_healthy():
                    return self._session
                await self.close()

            logger.info("No active MCP session found. Connecting to the MCP server...")
            return await self.start_server_session()

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]):
        last_exc: Optional[Exception] = None
        for attempt in range(1, self._max_retries + 1):
            try:
                async with self._call_semaphore:
                    session = await self._ensure_active_session()
                    logger.info("Calling MCP tool '%s' (attempt %d/%d)", tool_name, attempt, self._max_retries)
                    return await asyncio.shield(session.call_tool(tool_name, arguments))
            except Exception as exc:
                last_exc = exc
                logger.exception(
                    "MCP call '%s' failed (attempt %d/%d): %s",
                    tool_name, attempt, self._max_retries, exc,
                )
                async with self._reconnect_lock:
                    await self.close()

                await asyncio.sleep(min(2 ** attempt, 4))

        raise MCPToolExecutionError(
            tool_name=tool_name,
            attempts=self._max_retries,
            last_error=last_exc
        )

    async def get_tool_list(self) -> ListToolsResult:
        try:
            session = await self._ensure_active_session()
            return await asyncio.shield(session.list_tools())
        except Exception as exc:
            logger.warning("Failed to load MCP tool list: %s", exc, exc_info=True)
            raise MCPConnectionError(url=self._url, original_error=exc) from exc

    async def is_session_healthy(self) -> bool:
        if self._session is None:
            return False
        try:
            await asyncio.wait_for(
                self._session.list_tools(),
                timeout=_MCP_SESSION_HEARTBEAT_TIMEOUT_SECONDS
            )
            return True
        except Exception as e:
            logger.warning("MCP session health check failed: %s", e, exc_info=True)
            return False

    async def close(self):
        async with self._reconnect_lock:
            if self._session_cm:
                logger.info("Closing MCP session...")
                try:
                    await self._session_cm.__aexit__(None, None, None)
                except Exception as e:
                    logger.exception("Error exiting session context manager: %s", e)
                finally:
                    self._session_cm = None
                    self._session = None

            if self._transport_cm:
                try:
                    await self._transport_cm.__aexit__(None, None, None)
                except Exception as e:
                    logger.exception("Error exiting transport context manager: %s", e)
                finally:
                    self._transport_cm = None

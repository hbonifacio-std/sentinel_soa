"""MCP client for the Core Orchestrator.

Uses the MCP Python SDK directly over streamable HTTP so the core can talk to the
`mcp_server` container without pulling the FastMCP client extras that conflict
with the FastAPI stack.
"""

import asyncio
import logging
import os
from typing import Any, Dict, Optional

try:
    from mcp import ClientSession
except ImportError:  # pragma: no cover - import path differs slightly by SDK version
    from mcp.client.session import ClientSession  # type: ignore

try:
    from mcp.client.streamable_http import streamable_http_client as _streamable_http_client
except ImportError:  # pragma: no cover
    from mcp.client.streamable_http import streamablehttp_client as _streamable_http_client  # type: ignore


logger = logging.getLogger("core_orchestrator.mcp_client")


class MCPClientManager:
    """Manages a persistent MCP session against the HTTP MCP server."""

    def __init__(self, server_script_path: Optional[str] = None):
        self.server_script_path = server_script_path
        self._transport_cm = None
        self._session_cm = None
        self._session: Optional[ClientSession] = None

    async def _open_http_session(self, url: str) -> ClientSession:
        self._transport_cm = _streamable_http_client(url)
        transport = await self._transport_cm.__aenter__()

        try:
            read_stream, write_stream = transport[0], transport[1]
        except Exception as exc:  # pragma: no cover - defensive against SDK shape changes
            raise RuntimeError(f"Unexpected MCP transport payload from {url}: {transport!r}") from exc

        self._session_cm = ClientSession(read_stream, write_stream)
        self._session = await self._session_cm.__aenter__()
        await self._session.initialize()
        return self._session

    async def start_server_session(self, timeout: float = 60.0) -> ClientSession:
        transport_mode = (os.getenv("MCP_TRANSPORT") or "http").lower()
        logger.info("Starting MCP session in transport mode: %s", transport_mode)

        if transport_mode != "http":
            raise RuntimeError(
                "Only HTTP transport is supported in the Dockerized core. Set MCP_TRANSPORT=http.")

        host = os.getenv("MCP_SERVER_HOST") or "mcp_server"
        port = int(os.getenv("MCP_SERVER_PORT") or 8080)
        url = f"http://{host}:{port}/mcp"
        logger.info("Configuring MCP client to connect to %s", url)

        try:
            return await asyncio.wait_for(self._open_http_session(url), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise RuntimeError(f"Timeout initializing MCP session after {timeout}s") from exc
        except Exception as exc:
            logger.critical("Fatal error connecting to MCP server: %s", exc, exc_info=True)
            raise RuntimeError(f"Could not initialize MCP session: {exc}") from exc

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        if not self._session:
            raise RuntimeError("The MCP client session is not active.")

        logger.info("Invoking remote MCP tool: %s", tool_name)
        try:
            result = await self._session.call_tool(tool_name, arguments)
            return result
        except Exception as exc:
            logger.error("Failure executing call for '%s': %s", tool_name, exc, exc_info=True)
            return {"error": f"Exception during remote tool execution: {exc}"}

    async def close(self):
        if self._session_cm:
            logger.info("Closing MCP session...")
            await self._session_cm.__aexit__(None, None, None)
            self._session_cm = None
            self._session = None
        if self._transport_cm:
            await self._transport_cm.__aexit__(None, None, None)
            self._transport_cm = None

"""MCP client for the Core Orchestrator.

Uses the MCP Python SDK over native SSE so the core can talk to the
`mcp_server` container without relying on streamable HTTP keep-alives.
"""

import asyncio
from datetime import timedelta
import logging
import os
from typing import Any, Dict, Optional

try:
    from mcp import ClientSession
except ImportError:
    from mcp.client.session import ClientSession
try:
    from mcp.client.sse import sse_client as _sse_client
except ImportError:
    from mcp.client.sse import sse_client as _sse_client


logger = logging.getLogger("core_orchestrator.mcp_client")

_MCP_SSE_CONNECT_TIMEOUT_SECONDS = 1200.0
_MCP_SSE_READ_TIMEOUT_SECONDS = 1200.0
_MCP_SESSION_HEARTBEAT_TIMEOUT_SECONDS = 15.0
_MCP_SERVER_SSE_PATH = "/sse"


class MCPClientManager:
    """Manages a persistent MCP session against the MCP SSE server."""

    def __init__(self, server_script_path: Optional[str] = None, max_retries: int = 3):
        self.server_script_path = server_script_path
        self._transport_cm = None
        self._session_cm = None
        self._session: Optional[ClientSession] = None
        self._reconnect_lock = asyncio.Lock()
        self._call_semaphore = asyncio.Semaphore(10)
        self._max_retries = max_retries

    def _build_sse_url(self) -> str:
        host = os.getenv("MCP_SERVER_HOST") or "mcp_server"
        port = int(os.getenv("MCP_SERVER_PORT") or 8080)
        sse_path = os.getenv("MCP_SERVER_SSE_PATH") or _MCP_SERVER_SSE_PATH
        if not sse_path.startswith("/"):
            sse_path = f"/{sse_path}"
        return f"http://{host}:{port}{sse_path}"

    async def _open_sse_session(self, url: str) -> ClientSession:
        headers = {}
        mcp_token = os.getenv("MCP_INTERNAL_TOKEN")
        if mcp_token:
            headers["Authorization"] = f"Bearer {mcp_token}"

        self._transport_cm = _sse_client(
            url,
            headers=headers,
            timeout=_MCP_SSE_CONNECT_TIMEOUT_SECONDS,
            sse_read_timeout=_MCP_SSE_READ_TIMEOUT_SECONDS,
        )
        transport = await self._transport_cm.__aenter__()

        try:
            read_stream, write_stream = transport[0], transport[1]
        except Exception as exc:
            raise RuntimeError(f"Unexpected MCP transport payload from {url}: {transport!r}") from exc

        self._session_cm = ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=timedelta(seconds=_MCP_SSE_READ_TIMEOUT_SECONDS),
        )
        self._session = await self._session_cm.__aenter__()
        await self._session.initialize()
        return self._session

    async def start_server_session(self, timeout: float = 600.0) -> ClientSession:
        transport_mode = (os.getenv("MCP_TRANSPORT") or "sse").lower()
        logger.info("Starting MCP session in transport mode: %s", transport_mode)

        if transport_mode != "sse":
            raise RuntimeError("Only SSE transport is supported in the Dockerized core. Set MCP_TRANSPORT=sse.")

        url = self._build_sse_url()
        logger.info("Configuring MCP client to connect to %s", url)

        try:
            return await asyncio.wait_for(self._open_sse_session(url), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise RuntimeError(f"Timeout initializing MCP session after {timeout}s") from exc
        except Exception as exc:
            logger.critical("Fatal error connecting to MCP server: %s", exc, exc_info=True)
            raise RuntimeError(f"Could not initialize MCP session: {exc}") from exc

    async def _ensure_active_session(self) -> ClientSession:
        """Verifica si la sesión existe y sigue respondiendo. Si no, intenta reconectar."""
        if self._session:
            try:
                await asyncio.wait_for(
                    self._session.list_tools(),
                    timeout=_MCP_SESSION_HEARTBEAT_TIMEOUT_SECONDS,
                )
                return self._session
            except Exception:
                logger.warning("La sesión MCP existente no responde (Timeout/Disconnect). Limpiando e intentando reconexión...")
                await self.close()

        logger.info("Reconectando automáticamente al servidor MCP...")
        return await self.start_server_session()

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Call a remote MCP tool with concurrency limits and retry/backoff.

        Ensures there's an active session up-front (fail-fast if reconnection cannot be
        established). After that, attempts the call with bounded concurrency and retries
        on transient errors, performing reconnection between attempts.
        """
        # Fail-fast: ensure we can obtain an active session before attempting retries
        try:
            await self._ensure_active_session()
        except Exception as reconn_exc:
            logger.error("No se pudo restablecer la sesión MCP antes de ejecutar la herramienta.")
            raise RuntimeError(f"The MCP client session is not active. Reconnection failed: {reconn_exc}")

        last_exc: Optional[Exception] = None
        for attempt in range(1, self._max_retries + 1):
            try:
                async with self._call_semaphore:
                    # Ensure session is still valid; _ensure_active_session will reconnect if needed
                    session = await self._ensure_active_session()
                    logger.info("Calling MCP tool '%s' (attempt %d/%d)", tool_name, attempt, self._max_retries)
                    return await session.call_tool(tool_name, arguments)
            except Exception as exc:
                last_exc = exc
                logger.error(
                    "MCP call '%s' failed (attempt %d/%d): %s",
                    tool_name, attempt, self._max_retries, exc,
                )
                # Force a session refresh for the next attempt
                self._session = None
                await asyncio.sleep(min(2 ** attempt, 8))

        logger.error("MCP call '%s' failed after %d attempts: %s", tool_name, self._max_retries, last_exc)
        return {"error": f"Exception during remote tool execution after {self._max_retries} attempts: {last_exc}"}

    async def is_session_healthy(self, timeout: float = 3.0) -> bool:
        """Checks if the current MCP session responds to a lightweight heartbeat."""
        if self._session is None:
            return False
        try:
            await asyncio.wait_for(self._session.list_tools(), timeout=timeout)
            return True
        except Exception:
            logger.warning("MCP health check failed: session is not responding.")
            return False

    async def close(self):
        if self._session_cm:
            logger.info("Closing MCP session...")
            try:
                await self._session_cm.__aexit__(None, None, None)
            except Exception:
                pass
            self._session_cm = None
            self._session = None
        if self._transport_cm:
            try:
                await self._transport_cm.__aexit__(None, None, None)
            except Exception:
                pass
            self._transport_cm = None

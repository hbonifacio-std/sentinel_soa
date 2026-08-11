"""MCP client for the Core Orchestrator.

Uses the MCP Python SDK over native SSE so the core can talk to the
`mcp_server` container without relying on streamable HTTP keep-alive.
"""

import asyncio
from datetime import timedelta
import logging
import os
from types import CoroutineType
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

    This class provides functionality for initializing and managing connections to an MCP server
    using the SSE (Server-Sent Events) transport. It includes support for advanced features like
    concurrency limits, automated reconnection, retries for transient errors, session health checks,
    and MCP tool invocation.

    Methods:
        start_server_session:
            Establishes a new connection to the MCP server using the configured settings.
        call_tool:
            Calls a remote MCP tool with concurrency control and retry/backoff mechanisms.
        is_session_healthy:
            Checks if the current MCP session is responsive using a lightweight heartbeat.
        close:
            Safely closes the current session and transport connections.
    """

    def __init__(self, max_retries: int = 3):
        """
        Initializes an instance of the class with configurable retry behavior.

        Parameters:
            max_retries: int
                Maximum number of retries allowed for operations. Defaults to 3.
        """
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
        """
        Builds the SSE (Server-Sent Events) URL based on the base server URL.

        Returns:
            str: The complete SSE URL.

        Raises:
            MCPConfigurationError: If the base server URL is not defined or is empty.
        """
        if not self._url:
            raise MCPConfigurationError(
                setting_name="MCP_SERVER_URL",
                message="Environment variable is empty or not defined."
            )
        return f"{self._url}{_MCP_SERVER_SSE_PATH}"

    async def _open_sse_session(self, url: str) -> ClientSession:
        """
        Establishes and manages an asynchronous Server-Sent Events (SSE) session.

        This method is responsible for initiating an SSE connection to the given URL using
        a provided authentication token. The method handles connection setup, including
        setting required headers and initializing transport and session contexts. On
        successful connection, it returns an initialized `ClientSession` object.

        Raises:
            MCPConfigurationError: Raised if the authentication token is missing or invalid.
            MCPConnectionError: Raised if there is a failure in establishing the connection
            or initializing the session.

        Parameters:
            url (str): The URL to establish the SSE connection to.

        Returns:
            ClientSession: An initialized session object for interacting with the connected
            SSE transport.
        """
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
            self._session_cm = ClientSession(
                read_stream,
                write_stream,
                read_timeout_seconds=timedelta(seconds=_MCP_SSE_READ_TIMEOUT_SECONDS),
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
            raise MCPConnectionError(url=url, original_error=exc) from exc


    async def start_server_session(self) -> ClientSession:
        """
        Starts a server session for the MCP client.

        This method initializes a server-side event (SSE) session for the MCP client
        based on the transport mode specified in the environment. It supports only the
        "SSE" transport mode at the moment. The connection to the server is attempted
        with a timeout, and appropriate errors are raised in case of failure.

        Raises:
            MCPConfigurationError: If the transport mode specified in the environment
            is not "sse".
            MCPTimeoutError: If the operation exceeds the allowed timeout value.
            MCPClientError: If there is an error specific to the MCP client.
            MCPConnectionError: If a critical failure occurs while connecting to the
            MCP server.

        Returns:
            ClientSession: An active server-side event (SSE) session.
        """
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
            raise MCPTimeoutError(operation="start_server_session", timeout_seconds=_MCP_START_SERVER_SESSION_TIMEOUT_SECONDS) from exc
        except MCPClientError:
            raise
        except Exception as exc:
            logger.critical("Fatal error connecting to MCP server: %s", exc, exc_info=True)
            raise MCPConnectionError(url=url, original_error=exc) from exc


    async def _ensure_active_session(self) -> ClientSession:
        """
        Ensures there is an active MCP server session.

        If a session exists, checks its heartbeat by invoking a method on the
        current session to determine if it is still active. If the check fails,
        the session is closed, and a new connection to the server is established.
        If no session exists, a new connection is automatically created.

        Raises:
            Exception: Raised if any error occurs during the heartbeat check of
            the existing session.

        Returns:
            ClientSession: An active and valid MCP server session.
        """
        if self._session:
            try:
                await asyncio.wait_for(
                    self._session.list_tools(),
                    timeout=_MCP_SESSION_HEARTBEAT_TIMEOUT_SECONDS,
                )
                return self._session
            except Exception as e:
                logger.exception("Existing MCP session heartbeat failed (Timeout/Disconnect): %s", e)
                logger.warning(
                    "Existing MCP session heartbeat failed (Timeout/Disconnect). Cleaning up before reconnect...")
                await self.close()

        logger.info("Automatically reconnecting to the MCP server...")
        return await self.start_server_session()

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]):
        """
        Executes an asynchronous call to a specified tool with retries upon failure.

        This method is used to call tools reliably over multiple attempts, handling session
        reconnection when necessary. It ensures that the active session is valid and retries
        the operation according to the configured maximum retries, logging failures at each
        attempt. If all retries fail, an appropriate error is raised.

        Parameters:
        tool_name : str
            The name of the tool to be called.
        arguments : Dict[str, Any]
            The arguments to be passed to the tool.

        Raises:
        MCPConnectionError
            If restoring the active session fails before attempting any retries.
        MCPToolExecutionError
            If all retry attempts fail, with details of the tool, number of attempts,
            and the last encountered exception.
        """

        try:
            await self._ensure_active_session()
        except Exception as reconnection_error:
            logger.error("Failed to restore MCP session before tool execution.")
            raise MCPConnectionError(url=None, original_error=reconnection_error) from reconnection_error

        last_exc: Optional[Exception] = None
        for attempt in range(1, self._max_retries + 1):
            try:
                async with self._call_semaphore:
                    session = await self._ensure_active_session()
                    logger.info("Calling MCP tool '%s' (attempt %d/%d)", tool_name, attempt, self._max_retries)
                    return await session.call_tool(tool_name, arguments)
            except Exception as exc:
                    last_exc = exc
                    logger.exception(
                        "MCP call '%s' failed (attempt %d/%d): %s",
                        tool_name, attempt, self._max_retries, exc,
                    )
                    self._session = None
                    await asyncio.sleep(min(2 ** attempt, 8))

        raise MCPToolExecutionError(
            tool_name=tool_name,
            attempts=self._max_retries,
            last_error=last_exc
        )
    async def get_tool_list(self) -> ListToolsResult:
        if self._session:
            return await self._session.list_tools()
        else:
            return ListToolsResult(tools=[])

    async def is_session_healthy(self) -> bool:
        """
        Checks the health status of the session.

        This asynchronous function determines if the current session is
        healthy and responsive by attempting to list available tools within
        a predefined timeout period. If the session is absent or unresponsive,
        it is flagged as unhealthy.

        Returns:
            bool: True if the session is healthy, False otherwise.
        """
        if self._session is None:
            return False
        try:
            await asyncio.wait_for(self._session.list_tools(), timeout=_MCP_SESSION_HEARTBEAT_TIMEOUT_SECONDS)
            return True
        except Exception as e:
            logger.exception("MCP health check failed: session is not responding: %s", e)
            return False

    async def close(self):
        """
        Closes the current session and transport context managers safely.

        This method ensures the proper cleanup of both the session and transport
        context managers. If any exception occurs during the cleanup process,
        it will be logged appropriately. After execution, the session and transport
        managers will be set to None.

        Raises:
            Exception: If an error occurs during the exit of the session or transport
            context manager, the exception will be logged but not re-raised.
        """
        if self._session_cm:
            logger.info("Closing MCP session...")
            try:
                await self._session_cm.__aexit__(None, None, None)
            except Exception as e:
                logger.exception("Error exiting session context manager: %s", e)
            self._session_cm = None
            self._session = None
        if self._transport_cm:
            try:
                await self._transport_cm.__aexit__(None, None, None)
            except Exception as e:
                logger.exception("Error exiting transport context manager: %s", e)
            self._transport_cm = None

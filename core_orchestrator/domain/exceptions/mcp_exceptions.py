from typing import Optional

from core_orchestrator.domain.exceptions.domain_exceptions import DomainException


class MCPClientError(DomainException):
    """Base exception for all MCP Client errors."""
    pass


class MCPConfigurationError(MCPClientError):
    """Raised when configuration, environment variables, or transport parameters are missing/invalid."""
    def __init__(self, setting_name: str, message: str):
        self.setting_name = setting_name
        super().__init__(f"[MCP Config Error] '{setting_name}': {message}")


class MCPConnectionError(MCPClientError):
    """Raised when establishing an SSE transport or initializing a session fails."""
    def __init__(self, url: Optional[str], original_error: Optional[Exception] = None):
        self.url = url
        self.original_error = original_error
        target = f" at target '{url}'" if url else ""
        msg = f"[MCP Connection Error] Failed to establish or maintain SSE session{target}."
        if original_error:
            msg += f" Details: {original_error}"
        super().__init__(msg)


class MCPTimeoutError(MCPConnectionError):
    """Raised when an operation times out (connection, initialization, or tool execution)."""
    def __init__(self, operation: str, timeout_seconds: float):
        self.operation = operation
        self.timeout_seconds = timeout_seconds
        super().__init__(
            url=None,
            original_error=None
        )
        # Override message with clear timeout details
        self.args = (f"[MCP Timeout Error] Operation '{operation}' timed out after {timeout_seconds}s.",)


class MCPToolExecutionError(MCPClientError):
    """Raised when a remote MCP tool call fails after all configured retry attempts."""
    def __init__(self, tool_name: str, attempts: int, last_error: Optional[Exception]):
        self.tool_name = tool_name
        self.attempts = attempts
        self.last_error = last_error
        super().__init__(
            f"[MCP Tool Execution Error] Tool '{tool_name}' failed to execute after {attempts} attempts. "
            f"Last recorded error: {last_error}"
        )
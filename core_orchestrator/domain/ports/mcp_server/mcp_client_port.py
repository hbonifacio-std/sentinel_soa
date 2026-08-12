# domain/ports/mcp_port.py
from abc import ABC, abstractmethod
from typing import Any, Dict

from mcp import ListToolsResult


class MCPClientPort(ABC):
    """Port (Outbound Interface) for interacting with MCP tools and sessions."""

    @abstractmethod
    async def start_server_session(self) -> Any:
        pass

    @abstractmethod
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> dict[str, Any]:
        pass

    @abstractmethod
    async def get_tool_list(self) -> ListToolsResult:
        pass

    @abstractmethod
    async def is_session_healthy(self) -> bool:
        pass

    @abstractmethod
    async def close(self) -> None:
        pass
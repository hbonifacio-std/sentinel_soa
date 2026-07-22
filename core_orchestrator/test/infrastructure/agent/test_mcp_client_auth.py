import pytest

from core_orchestrator.infrastructure.agent.mcp_client import MCPClientManager


@pytest.mark.asyncio
async def test_open_sse_session_requires_internal_client_token(monkeypatch):
    monkeypatch.delenv("MCP_INTERNAL_CLIENT_TOKEN", raising=False)
    monkeypatch.delenv("MCP_INTERNAL_TOKEN", raising=False)
    manager = MCPClientManager()

    with pytest.raises(RuntimeError, match="MCP_INTERNAL_CLIENT_TOKEN"):
        await manager._open_sse_session("http://mcp_server:8080/sse")

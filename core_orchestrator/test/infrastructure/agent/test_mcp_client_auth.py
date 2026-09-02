import pytest

from core_orchestrator.infrastructure.adapters.mpc_server.mcp_client_adapter import MCPClientManagerAdapter


@pytest.mark.asyncio
async def test_open_sse_session_requires_internal_client_token(monkeypatch):
    monkeypatch.delenv("MCP_INTERNAL_CLIENT_TOKEN", raising=False)
    monkeypatch.delenv("MCP_INTERNAL_TOKEN", raising=False)
    manager = MCPClientManagerAdapter()

    with pytest.raises(RuntimeError, match="MCP_INTERNAL_CLIENT_TOKEN"):
        await manager._open_sse_session("http://mcp_server:8080/sse")

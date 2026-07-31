"""
Extended tests for MCPClientManager covering lines NOT yet hit:
  - start_server_session with non-http transport (raises RuntimeError)
  - start_server_session TimeoutError path
  - start_server_session generic exception path
  - _ensure_active_session when session exists and is alive
  - _ensure_active_session when session fails and reconnects
  - call_tool when reconnection fails
  - call_tool when session.call_tool raises exception
  - close with no session_cm / transport_cm (noop)
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_manager():
    from core_orchestrator.infrastructure.adapters.mpc_server.mcp_client_adapter import MCPClientManagerAdapter
    return MCPClientManagerAdapter()


# ---------------------------------------------------------------------------
# start_server_session
# ---------------------------------------------------------------------------
class TestStartServerSession:
    @pytest.mark.asyncio
    async def test_non_sse_transport_raises(self, monkeypatch):
        monkeypatch.setenv("MCP_TRANSPORT", "stdio")
        manager = _make_manager()
        with pytest.raises(RuntimeError, match="Only SSE transport"):
            await manager.start_server_session()

    @pytest.mark.asyncio
    async def test_timeout_raises_runtime_error(self, monkeypatch):
        monkeypatch.setenv("MCP_TRANSPORT", "sse")
        manager = _make_manager()

        async def _slow(*args, **kwargs):
            await asyncio.sleep(100)

        with patch.object(manager, "_open_sse_session", side_effect=_slow):
            with pytest.raises(RuntimeError, match="Timeout"):
                await manager.start_server_session(timeout=0.001)

    @pytest.mark.asyncio
    async def test_generic_exception_wraps_runtime_error(self, monkeypatch):
        monkeypatch.setenv("MCP_TRANSPORT", "sse")
        manager = _make_manager()

        with patch.object(manager, "_open_sse_session", side_effect=ConnectionRefusedError("refused")):
            with pytest.raises(RuntimeError, match="Could not initialize MCP session"):
                await manager.start_server_session()

    @pytest.mark.asyncio
    async def test_sse_client_uses_long_read_timeout(self, monkeypatch):
        monkeypatch.setenv("MCP_TRANSPORT", "sse")
        monkeypatch.setenv("MCP_SERVER_HOST", "localhost")
        manager = _make_manager()

        mock_transport = AsyncMock()
        mock_transport.__aenter__.return_value = (AsyncMock(), AsyncMock())
        mock_session = AsyncMock()
        mock_session.__aenter__.return_value = mock_session

        with patch("core_orchestrator.infrastructure.agent.mcp_client._sse_client", return_value=mock_transport) as mock_streamable:
            with patch("core_orchestrator.infrastructure.agent.mcp_client.ClientSession", return_value=mock_session):
                await manager.start_server_session()

        assert mock_streamable.call_args.kwargs["timeout"] == 600.0
        assert mock_streamable.call_args.kwargs["sse_read_timeout"] == 600.0
        assert mock_streamable.call_args.args[0] == "http://localhost:8080/sse"
        assert mock_session.initialize.await_count == 1


# ---------------------------------------------------------------------------
# _ensure_active_session
# ---------------------------------------------------------------------------
class TestEnsureActiveSession:
    @pytest.mark.asyncio
    async def test_session_alive_returns_existing(self):
        manager = _make_manager()
        mock_session = AsyncMock()
        mock_session.list_tools = AsyncMock(return_value=[])
        manager._session = mock_session

        result = await manager._ensure_active_session()
        assert result is mock_session
        mock_session.list_tools.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_session_unresponsive_reconnects(self):
        manager = _make_manager()
        mock_session = AsyncMock()
        mock_session.list_tools = AsyncMock(side_effect=asyncio.TimeoutError())
        manager._session = mock_session

        new_session = AsyncMock()
        with patch.object(manager, "close", AsyncMock()) as mock_close:
            with patch.object(manager, "start_server_session", AsyncMock(return_value=new_session)):
                result = await manager._ensure_active_session()
        assert result is new_session

    @pytest.mark.asyncio
    async def test_no_session_calls_start(self):
        manager = _make_manager()
        manager._session = None
        new_session = AsyncMock()
        with patch.object(manager, "start_server_session", AsyncMock(return_value=new_session)):
            result = await manager._ensure_active_session()
        assert result is new_session


# ---------------------------------------------------------------------------
# call_tool
# ---------------------------------------------------------------------------
class TestCallTool:
    @pytest.mark.asyncio
    async def test_call_tool_success(self):
        manager = _make_manager()
        mock_session = AsyncMock()
        mock_session.call_tool = AsyncMock(return_value={"status": "ok"})
        with patch.object(manager, "_ensure_active_session", AsyncMock(return_value=mock_session)):
            result = await manager.call_tool("do_thing", {"arg": 1})
        assert result == {"status": "ok"}

    @pytest.mark.asyncio
    async def test_call_tool_session_tool_exception_returns_error_dict(self):
        manager = _make_manager()
        mock_session = AsyncMock()
        mock_session.call_tool = AsyncMock(side_effect=RuntimeError("mcp down"))
        with patch.object(manager, "_ensure_active_session", AsyncMock(return_value=mock_session)):
            result = await manager.call_tool("bad_tool", {})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_call_tool_reconnection_failure_raises(self):
        manager = _make_manager()
        with patch.object(
            manager,
            "_ensure_active_session",
            AsyncMock(side_effect=RuntimeError("cannot reconnect")),
        ):
            with pytest.raises(RuntimeError, match="MCP client session is not active"):
                await manager.call_tool("tool", {})


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------
class TestClose:
    @pytest.mark.asyncio
    async def test_close_with_no_clients_is_safe(self):
        manager = _make_manager()
        # Neither session_cm nor transport_cm set — should not raise
        await manager.close()
        assert manager._session_cm is None
        assert manager._transport_cm is None

    @pytest.mark.asyncio
    async def test_close_clears_session_and_transport(self):
        manager = _make_manager()
        mock_session_cm = AsyncMock()
        mock_transport_cm = AsyncMock()
        manager._session_cm = mock_session_cm
        manager._transport_cm = mock_transport_cm
        manager._session = AsyncMock()

        await manager.close()

        mock_session_cm.__aexit__.assert_awaited_once()
        mock_transport_cm.__aexit__.assert_awaited_once()
        assert manager._session_cm is None
        assert manager._transport_cm is None
        assert manager._session is None

    @pytest.mark.asyncio
    async def test_close_suppresses_exceptions(self):
        manager = _make_manager()
        bad_cm = AsyncMock()
        bad_cm.__aexit__ = AsyncMock(side_effect=Exception("boom"))
        manager._session_cm = bad_cm
        manager._transport_cm = bad_cm
        manager._session = AsyncMock()
        # Should not raise
        await manager.close()

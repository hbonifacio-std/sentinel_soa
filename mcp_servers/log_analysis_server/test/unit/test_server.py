"""Unit tests for Mongo-backed MCP tool handlers in server.py."""

import os
from unittest.mock import AsyncMock, patch

import pytest

import mcp_servers.log_analysis_server.server as srv
from mcp_servers.log_analysis_server.security import set_user_role


@pytest.fixture(autouse=True)
def _authenticated_role():
    set_user_role("analyst")
    try:
        yield
    finally:
        set_user_role(None)


@pytest.mark.asyncio
async def test_get_mongo_access_scope_returns_scope() -> None:
    result = await srv.get_mongo_access_scope()
    assert result["database"] == "sentinel_soa"
    assert "raw_telemetry" in result["authorized_collections"]
    assert "reports" in result["authorized_collections"]


@pytest.mark.asyncio
async def test_get_raw_telemetry_events_calls_executor() -> None:
    mock_result = {"collection": "raw_telemetry", "total_returned": 1, "rows": [{"source_ip": "10.0.0.1"}]}
    with patch(
        "mcp_servers.log_analysis_server.server.execute_get_raw_telemetry_events",
        new=AsyncMock(return_value=mock_result),
    ) as mock_exec:
        result = await srv.get_raw_telemetry_events(source_ip="10.0.0.1", limit=50)

    assert result["collection"] == "raw_telemetry"
    assert mock_exec.await_count == 1
    assert mock_exec.await_args.args[0]["source_ip"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_analyze_potential_threat_calls_executor() -> None:
    mock_result = {"threat_detected": True, "threat_level": "HIGH", "threat_score": 82}
    with patch(
        "mcp_servers.log_analysis_server.server.execute_analyze_potential_threat",
        new=AsyncMock(return_value=mock_result),
    ) as mock_exec:
        result = await srv.analyze_potential_threat(source_ip="10.0.0.1", limit_raw_events=99999)

    assert result["threat_detected"] is True
    assert mock_exec.await_count == 1
    assert mock_exec.await_args.args[0]["limit_raw_events"] == srv.server_settings.max_query_limit


@pytest.mark.asyncio
async def test_main_starts_sse_transport() -> None:
    with patch.dict(
        os.environ,
        {"MCP_TRANSPORT": "sse", "MCP_SERVER_HOST": "0.0.0.0", "MCP_SERVER_PORT": "8080"},
    ):
        with patch("mcp_servers.log_analysis_server.server.get_internal_token", return_value="token"):
            with patch("mcp_servers.log_analysis_server.server.mongo_db_manager.connect", new=AsyncMock()):
                with patch("mcp_servers.log_analysis_server.server.mongo_db_manager.disconnect", new=AsyncMock()):
                    with patch("mcp_servers.log_analysis_server.server.server.run_http_async", new=AsyncMock()) as mock_run:
                        await srv.main()

    mock_run.assert_awaited_once()
    assert mock_run.await_args.kwargs["transport"] == "sse"

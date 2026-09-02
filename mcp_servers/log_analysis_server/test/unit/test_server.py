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
async def test_get_graph_access_scope_returns_scope() -> None:
    result = await srv.get_graph_access_scope()
    assert result["database"]
    assert "LogEvent" in result["labels"]
    assert result["access_mode"] == "read_only"


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
async def test_get_threat_reports_compact_mapping_calls_executor() -> None:
    mock_result = {"collection": "reports", "total_returned": 2, "rows": []}
    with patch(
        "mcp_servers.log_analysis_server.server.execute_get_threat_reports",
        new=AsyncMock(return_value=mock_result),
    ) as mock_exec:
        result = await srv.get_threat_reports(
            source_ip="10.0.0.1",
            severity="HIGH",
            only_open=True,
            only_unreviewed=True,
            lookback_hours=12,
            limit=99999,
        )

    assert result["collection"] == "reports"
    assert mock_exec.await_count == 1
    args = mock_exec.await_args.args[0]
    assert args["source_ip"] == "10.0.0.1"
    assert args["threat_level"] == "HIGH"
    assert args["min_threat_score"] == 60
    assert args["resolved"] is False
    assert args["reviewed"] is False
    assert args["limit"] == srv.server_settings.max_query_limit
    assert args["from_utc"] is not None
    assert args["to_utc"] is not None


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
async def test_get_graph_threat_landscape_calls_executor() -> None:
    mock_result = {"context_type": "graph_threat_landscape", "summary": {"total_reports": 12}}
    with patch(
        "mcp_servers.log_analysis_server.server.execute_get_graph_threat_landscape",
        new=AsyncMock(return_value=mock_result),
    ) as mock_exec:
        result = await srv.get_graph_threat_landscape(limit_entities=99999)

    assert result["context_type"] == "graph_threat_landscape"
    assert mock_exec.await_count == 1
    assert mock_exec.await_args.args[0]["limit_entities"] == srv.server_settings.max_query_limit


@pytest.mark.asyncio
async def test_get_graph_lateral_movement_paths_calls_executor() -> None:
    mock_result = {"context_type": "graph_lateral_movement_paths", "summary": {"candidate_paths": 3}}
    with patch(
        "mcp_servers.log_analysis_server.server.execute_get_graph_lateral_movement_paths",
        new=AsyncMock(return_value=mock_result),
    ) as mock_exec:
        result = await srv.get_graph_lateral_movement_paths(source_ip="10.0.0.1", limit_paths=99999)

    assert result["context_type"] == "graph_lateral_movement_paths"
    assert mock_exec.await_count == 1
    assert mock_exec.await_args.args[0]["limit_paths"] == srv.server_settings.max_query_limit


@pytest.mark.asyncio
async def test_get_graph_mitre_context_calls_executor() -> None:
    mock_result = {"context_type": "graph_mitre_context", "mitre_activity": []}
    with patch(
        "mcp_servers.log_analysis_server.server.execute_get_graph_mitre_context",
        new=AsyncMock(return_value=mock_result),
    ) as mock_exec:
        result = await srv.get_graph_mitre_context(limit_items=99999)

    assert result["context_type"] == "graph_mitre_context"
    assert mock_exec.await_count == 1
    assert mock_exec.await_args.args[0]["limit_items"] == srv.server_settings.max_query_limit


@pytest.mark.asyncio
async def test_get_unified_forensic_context_calls_executor() -> None:
    mock_result = {"context_type": "unified_forensic_context", "verdict": {"threat_level": "HIGH"}}
    with patch(
        "mcp_servers.log_analysis_server.server.execute_get_unified_forensic_context",
        new=AsyncMock(return_value=mock_result),
    ) as mock_exec:
        result = await srv.get_unified_forensic_context(source_ip="10.0.0.1", limit_raw_events=99999)

    assert result["context_type"] == "unified_forensic_context"
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
                with patch("mcp_servers.log_analysis_server.server.neo4j_db_manager.connect", new=AsyncMock()):
                    with patch("mcp_servers.log_analysis_server.server.mongo_db_manager.disconnect", new=AsyncMock()):
                        with patch("mcp_servers.log_analysis_server.server.neo4j_db_manager.disconnect", new=AsyncMock()):
                            with patch("mcp_servers.log_analysis_server.server.server.run_http_async", new=AsyncMock()) as mock_run:
                                await srv.main()

    mock_run.assert_awaited_once()
    assert mock_run.await_args.kwargs["transport"] == "sse"

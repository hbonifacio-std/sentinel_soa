"""Unit tests for MCP tool error response builders."""

from mcp_servers.log_analysis_server.tools.error_responses import (
    build_analyze_web_activity_error,
    build_threat_context_error,
)


def test_build_analyze_web_activity_error_shape():
    result = build_analyze_web_activity_error(
        window_id="win-1",
        source_id="src-1",
        source_ip="10.0.0.5",
        unique_uris_requested=["/admin", "/login"],
        error="boom",
    )
    assert result["threat_detected"] is False
    assert result["threat_level"] == "NONE"
    assert result["error"] == "boom"
    assert "/admin" in result["targeted_asset"]
    assert result["indicators_found"] == ["analysis_execution_error"]


def test_build_threat_context_error_shape():
    result = build_threat_context_error(source_ip="10.0.0.5", error="store down")
    assert result["source_ip"] == "10.0.0.5"
    assert result["history"] == []
    assert result["alerts_found"] == 0
    assert result["error"] == "store down"

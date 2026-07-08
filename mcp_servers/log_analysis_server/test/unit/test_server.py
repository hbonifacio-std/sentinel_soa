"""
Unit tests for server.py — FastMCP tool handlers.
Each tool function is tested by mocking its underlying implementation function,
so no LLM, Mongo, or Redis connections are needed.
"""
import asyncio
import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from unittest.mock import AsyncMock, patch, MagicMock

import mcp_servers.log_analysis_server.server as srv


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_analyze_payload(**overrides):
    now = datetime.now(timezone.utc)
    defaults = dict(
        window_id=str(uuid4()),
        source_id="victim-app-01",
        source_ip="10.0.0.1",
        window_start_utc=now.isoformat(),
        window_end_utc=(now + timedelta(seconds=60)).isoformat(),
        total_requests=10,
        unique_uris_requested=["/api/products"],
        user_agents_observed=["Mozilla/5.0"],
        requests_per_second_avg=0.2,
    )
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# get_available_models
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_available_models_returns_dict():
    result = await srv.get_available_models()
    assert "default_model_id" in result
    assert "available_models" in result
    assert isinstance(result["available_models"], dict)
    assert len(result["available_models"]) > 0


@pytest.mark.asyncio
async def test_get_available_models_model_has_required_fields():
    result = await srv.get_available_models()
    for model_id, model_info in result["available_models"].items():
        assert "provider" in model_info
        assert "model_name" in model_info


# ---------------------------------------------------------------------------
# analyze_web_activity
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_analyze_web_activity_calls_execute():
    mock_result = {
        "window_id": "test",
        "threat_detected": False,
        "threat_level": "NONE",
        "threat_score": 0,
        "indicators_found": [],
        "reasoning_summary": "Clean",
        "recommendation": "None",
        "targeted_asset": "victim-app",
        "mitre_tactic": None,
        "mitre_tactic_id": None,
        "mitre_technique": None,
        "mitre_technique_id": None,
        "mitre_sub_technique": None,
        "mitre_sub_technique_id": None,
        "suggested_mitigations": [],
    }

    with patch(
        "mcp_servers.log_analysis_server.server.execute_analyze_web_activity",
        new=AsyncMock(return_value=mock_result),
    ):
        payload = _base_analyze_payload()
        result = await srv.analyze_web_activity(**payload)

    assert result["threat_detected"] is False
    assert result["threat_level"] == "NONE"


@pytest.mark.asyncio
async def test_analyze_web_activity_returns_error_dict_on_exception():
    with patch(
        "mcp_servers.log_analysis_server.server.execute_analyze_web_activity",
        new=AsyncMock(side_effect=RuntimeError("unexpected error")),
    ):
        payload = _base_analyze_payload()
        result = await srv.analyze_web_activity(**payload)

    assert "error" in result
    assert result["threat_detected"] is False
    assert result["threat_level"] == "NONE"


# ---------------------------------------------------------------------------
# generate_mongo_query_from_nl
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_generate_mongo_query_from_nl_returns_filter():
    mock_result = {
        "mongo_filter": {"source_ip": "10.0.0.1"},
        "detected_ips": ["10.0.0.1"],
        "detected_status_codes": [],
        "detected_terms": [],
    }
    with patch(
        "mcp_servers.log_analysis_server.server.build_forensic_mongo_query",
        new=AsyncMock(return_value=mock_result),
    ):
        result = await srv.generate_mongo_query_from_nl(
            query="show logs from 10.0.0.1", source_id="victim-app"
        )

    assert "mongo_filter" in result


# ---------------------------------------------------------------------------
# generate_forensic_report_from_logs
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_generate_forensic_report_calls_generate():
    mock_result = {
        "markdown_report": "# Forensic Report",
        "highlights": ["highlight"],
    }
    log_rows = [{"source_ip": "10.0.0.1", "response_code": 404}] * 5

    with patch(
        "mcp_servers.log_analysis_server.server.generate_forensic_report",
        new=AsyncMock(return_value=mock_result),
    ):
        result = await srv.generate_forensic_report_from_logs(
            query="find attack attempts",
            total_matches=5,
            rows=log_rows,
            source_id="victim-app",
        )

    assert result["markdown_report"] == "# Forensic Report"
    assert "highlights" in result


# ---------------------------------------------------------------------------
# get_threat_context
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_threat_context_returns_history():
    mock_result = {
        "source_ip": "10.0.0.1",
        "history": [],
        "alerts_found": 0,
    }
    with patch(
        "mcp_servers.log_analysis_server.server.execute_get_threat_context",
        new=AsyncMock(return_value=mock_result),
    ):
        result = await srv.get_threat_context(source_ip="10.0.0.1", limit=5)

    assert result["source_ip"] == "10.0.0.1"
    assert "history" in result


@pytest.mark.asyncio
async def test_get_threat_context_returns_error_dict_on_exception():
    with patch(
        "mcp_servers.log_analysis_server.server.execute_get_threat_context",
        new=AsyncMock(side_effect=RuntimeError("redis down")),
    ):
        result = await srv.get_threat_context(source_ip="10.0.0.1")

    assert "error" in result
    assert result["source_ip"] == "10.0.0.1"
    assert result["history"] == []
    assert result["alerts_found"] == 0

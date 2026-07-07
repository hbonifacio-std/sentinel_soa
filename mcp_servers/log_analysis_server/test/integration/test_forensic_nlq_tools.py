"""Tests for deterministic forensic NLQ MCP tooling."""
import asyncio
from unittest.mock import patch, MagicMock

from mcp_servers.log_analysis_server.tools.forensic_nlq import (
    build_forensic_mongo_query,
    generate_forensic_report,
    _LOW_VOLUME_LOG_THRESHOLD,
    _SAMPLED_LOG_COUNT,
)


def test_build_forensic_mongo_query_extracts_ip_status_and_source_scope() -> None:
    # This test is not directly affected by the refactor, but we ensure it still passes.
    result = asyncio.run(
        build_forensic_mongo_query(
            {
                "query": "buscar 404 de 10.0.0.7 en /admin",
                "source_id": "victim-app",
            }
        )
    )

    mongo_filter = result.get("mongo_filter", {})
    assert "$and" in mongo_filter
    assert result.get("detected_ips") == ["10.0.0.7"]
    assert 404 in result.get("detected_status_codes", [])


@patch("mcp_servers.log_analysis_server.tools.forensic_nlq._generate_llm_forensic_report")
def test_generate_forensic_report_low_volume(mock_llm_report: MagicMock) -> None:
    """Verify direct analysis for low log volumes."""
    mock_llm_report.return_value = {
        "markdown_report": "# Test Report",
        "highlights": ["highlight 1"],
    }
    
    log_rows = [{"source_ip": f"10.0.0.{i}"} for i in range(50)]
    
    result = asyncio.run(
        generate_forensic_report(
            {
                "query": "analiza actividad normal",
                "source_id": "test-app",
                "total_matches": len(log_rows),
                "rows": log_rows,
                "model_id": "gemini-3.5-flash",
            }
        )
    )

    assert result["markdown_report"] == "# Test Report"
    mock_llm_report.assert_called_once()
    
    # Check that all rows were passed and no context note was added
    call_args = mock_llm_report.call_args[0]
    assert len(call_args[1]) == len(log_rows)
    assert call_args[2] is None  # system_context_note should be None


@patch("mcp_servers.log_analysis_server.tools.forensic_nlq._generate_llm_forensic_report")
def test_generate_forensic_report_uses_intelligent_sampling_for_high_volume(mock_llm_report: MagicMock) -> None:
    """Verify intelligent sampling is triggered for high log volumes."""
    mock_llm_report.return_value = {
        "markdown_report": "# Sampled Report",
        "highlights": ["sampled highlight"],
    }

    # Generate a high volume of logs
    log_rows = [{"source_ip": f"10.0.0.{i}"} for i in range(_LOW_VOLUME_LOG_THRESHOLD + 100)]
    
    result = asyncio.run(
        generate_forensic_report(
            {
                "query": "analiza una gran cantidad de logs con algo de ruido",
                "source_id": "test-app-large",
                "total_matches": len(log_rows),
                "rows": log_rows,
                "model_id": "gemini-3.5-flash",
            }
        )
    )

    assert result["markdown_report"] == "# Sampled Report"
    mock_llm_report.assert_called_once()
    
    # Verify that the LLM was called with a *sampled* number of rows and a context note
    call_args = mock_llm_report.call_args[0]
    passed_rows = call_args[1]
    system_note = call_args[2]

    assert len(passed_rows) <= _SAMPLED_LOG_COUNT
    assert isinstance(system_note, str)
    assert "intelligent sample" in system_note
    assert str(len(log_rows)) in system_note


def test_build_forensic_mongo_query_does_not_extract_http_status_from_ip_octets() -> None:
    # This test is not directly affected by the refactor, but we ensure it still passes.
    result = asyncio.run(
        build_forensic_mongo_query(
            {
                "query": "analiza la actividad de las ultimas 24 horas de la IP 172.18.0.2",
                "source_id": "victim-app-01",
            }
        )
    )

    assert result.get("detected_ips") == ["172.18.0.2"]
    assert result.get("detected_status_codes") == []

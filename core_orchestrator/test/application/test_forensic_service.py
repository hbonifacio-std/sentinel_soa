from unittest.mock import AsyncMock

import pytest

from core_orchestrator.application.modules.forensic.forensic_service import ForensicService
from core_orchestrator.infrastructure.dto.telemetry.forensic_analysis_dto import (
    ChatForensicQuestionDTO,
    ForensicChatSessionDTO,
    ForensicHistoryQueryDTO,
)


@pytest.mark.asyncio
async def test_analyze_activity_uses_mcp_query_plan_and_persists_report() -> None:
    repository = AsyncMock()
    repository.query_telemetry.return_value = (
        [
            {
                "source_ip": "10.0.0.7",
                "response_code": 401,
                "request_uri": "/login",
                "timestamp": "2026-07-02T10:00:00Z",
                "http_method": "POST",
            }
        ],
        1,
    )
    repository.save_analysis.return_value = "analysis-1"

    intelligence_port = AsyncMock()
    intelligence_port.generate_mongo_query_from_nl.return_value = {
        "mongo_filter": {"source_ip": "10.0.0.7"}
    }
    intelligence_port.generate_forensic_report_from_logs.return_value = {
        "markdown_report": "# Reporte Forense Inteligente\n\n- Riesgo: ALTO",
        "highlights": ["IP dominante: 10.0.0.7"],
    }

    service = ForensicService(
        forensic_repository=repository,
        forensic_intelligence_port=intelligence_port,
    )
    result = await service.analyze_activity(ChatForensicQuestionDTO(query="login", source_id="victim-app"))

    assert result.analysis_id == "analysis-1"
    assert result.total_matches == 1
    assert result.markdown_report.startswith("# Reporte Forense Inteligente")
    assert result.highlights == ["IP dominante: 10.0.0.7"]

    repository.query_telemetry.assert_awaited_once()
    query_filter = repository.query_telemetry.await_args.kwargs["query_filter"]
    assert query_filter == {"source_ip": "10.0.0.7"}


@pytest.mark.asyncio
async def test_analyze_activity_falls_back_when_mcp_report_is_empty() -> None:
    repository = AsyncMock()
    repository.query_telemetry.return_value = (
        [
            {
                "source_ip": "10.0.0.9",
                "response_code": 404,
                "request_uri": "/admin",
                "timestamp": "2026-07-02T10:01:00Z",
                "http_method": "GET",
            }
        ],
        1,
    )
    repository.save_analysis.return_value = "analysis-2"

    intelligence_port = AsyncMock()
    intelligence_port.generate_mongo_query_from_nl.return_value = {"mongo_filter": {}}
    intelligence_port.generate_forensic_report_from_logs.return_value = {}

    service = ForensicService(
        forensic_repository=repository,
        forensic_intelligence_port=intelligence_port,
    )
    result = await service.analyze_activity(ChatForensicQuestionDTO(query="admin", source_id="victim-app"))

    assert "Reporte Forense" in result.markdown_report
    assert result.highlights


@pytest.mark.asyncio
async def test_analyze_activity_falls_back_when_mcp_query_plan_is_invalid() -> None:
    repository = AsyncMock()
    repository.query_telemetry.return_value = ([], 0)
    repository.save_analysis.return_value = "analysis-3"

    intelligence_port = AsyncMock()
    intelligence_port.generate_mongo_query_from_nl.return_value = {"error": "mcp-timeout"}
    intelligence_port.generate_forensic_report_from_logs.return_value = {}

    service = ForensicService(
        forensic_repository=repository,
        forensic_intelligence_port=intelligence_port,
    )
    await service.analyze_activity(ChatForensicQuestionDTO(query="login", source_id="victim-app"))

    query_filter = repository.query_telemetry.await_args.kwargs["query_filter"]
    assert query_filter == {}


@pytest.mark.asyncio
async def test_get_analysis_history_wraps_repository_payload() -> None:
    repository = AsyncMock()
    query = ForensicHistoryQueryDTO(source_id="victim-app", page=1, limit=10)
    record = ForensicChatSessionDTO(
        analysis_id="analysis-1",
        query="admin",
        source_id="victim-app",
        total_matches=2,
        highlights=["h1"],
        markdown_report="# Reporte",
        sample_results=[],
    )
    repository.get_history.return_value = {
        "info": {"total_records": 1, "page": 1, "limit": 10, "next_page": None, "prev_page": None},
        "results": [record],
    }

    intelligence_port = AsyncMock()
    service = ForensicService(
        forensic_repository=repository,
        forensic_intelligence_port=intelligence_port,
    )
    result = await service.get_analysis_history(query)

    assert result.info["total_records"] == 1
    assert result.results[0].analysis_id == "analysis-1"

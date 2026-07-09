from unittest.mock import AsyncMock

import pytest

from core_orchestrator.application.modules.analysis_reports.services.analysis_service import AnalysisService
from core_orchestrator.domain.models.rule_engine.rules import RulesBundle


@pytest.mark.asyncio
async def test_analysis_service_adds_rules_bundle_and_normalizes_result() -> None:
    llm_analysis_port = AsyncMock()
    rules_engine_service = AsyncMock()

    rules_bundle = RulesBundle(
        malicious_ua_keywords={"sqlmap": 95},
        version_hash="v-test-1",
    )
    rules_engine_service.get_active_rules.return_value = rules_bundle
    llm_analysis_port.analyze_web_activity.return_value = {
        "threat_score": "82",
        "threat_detected": False,
        "indicators_found": [],
        "source_id": "N/A",
    }

    service = AnalysisService(llm_analysis_port=llm_analysis_port, rules_engine_service=rules_engine_service)

    telemetry_payload = {
        "window_id": 123,
        "source_id": "victim-app",
        "client_id": "tenant-42",
        "source_ip": "10.0.0.1",
        "window_start_utc": "2026-01-01T00:00:00Z",
        "window_end_utc": "2026-01-01T00:01:00Z",
        "unique_uris_requested": ["/.env"],
        "requests_per_second_avg": 10,
        "unexpected_field": "must-not-forward",
    }

    result = await service.analyze_activity(telemetry_payload)

    forwarded = llm_analysis_port.analyze_web_activity.await_args.args[0]

    assert forwarded["window_id"] == "123"
    assert "unexpected_field" not in forwarded
    assert forwarded["rules_bundle"]["version_hash"] == "v-test-1"

    assert result["source_ip"] == "10.0.0.1"
    assert result["source_id"] == "victim-app"
    assert result["client_id"] == "tenant-42"
    assert result["threat_score"] == 82
    assert result["threat_detected"] is True
    assert isinstance(result["indicators_found"], list)
    assert result["indicators_found"]

"""Integration test for historical_alerts_context population across consecutive analyses."""

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from mcp_servers.log_analysis_server.models.analysis_input import WebActivityWindowInput, SecurityStateFeatures
from mcp_servers.log_analysis_server.models.analysis_output import ThreatAssessment
from mcp_servers.log_analysis_server.services.prompt_builder import AnalysisPromptBuilder
from mcp_servers.log_analysis_server.store.alert_store import alert_store


@pytest.fixture(autouse=True)
def isolated_alert_store():
    """Ensure store isolation to avoid cross-test pollution."""
    alert_store.clear_all()
    yield
    alert_store.clear_all()


def _build_window(window_id: str, source_ip: str) -> WebActivityWindowInput:
    now = datetime.now(timezone.utc)
    return WebActivityWindowInput(
        window_id=window_id,
        source_id="victim-app-01",
        source_ip=source_ip,
        window_start_utc=now,
        window_end_utc=now + timedelta(seconds=60),
        total_requests=12,
        unique_uris_requested=["/auth/login", "/api/products"],
        http_methods_distribution={"GET": 8, "POST": 4},
        response_codes_distribution={"200": 7, "401": 3, "404": 2},
        user_agents_observed=["Mozilla/5.0", "python-requests/2.31.0"],
        requests_per_second_avg=0.2,
        attempted_usernames=["admin"],
        invalid_token_requests_count=1,
        max_response_size_bytes=512,
        suspicious_samples=[],
        critical_payload_features=["login retries"],
        infra_context={"environment": "simulation"},
        security_state_features=SecurityStateFeatures(
            compromised_accounts=["admin"],
            successful_logins_count=1,
            post_auth_internal_requests=4,
        ),
    )


def _extract_input_payload(prompt: str) -> dict:
    start = "\n\nINPUT_PAYLOAD:\n"
    end = "\n\nREQUIRED_OUTPUT_SCHEMA:\n"
    payload_text = prompt.split(start, 1)[1].split(end, 1)[0]
    return json.loads(payload_text)


def test_second_window_includes_previous_alert_in_historical_alerts_context():
    source_ip = "172.18.0.99"
    first_window_id = str(uuid4())
    second_window_id = str(uuid4())

    first_assessment = ThreatAssessment(
        window_id=first_window_id,
        source_id="victim-app-01",
        source_ip=source_ip,
        threat_detected=True,
        targeted_asset="victim-app [simulation_dmz] paths: [/auth/login]",
        threat_level="HIGH",
        threat_score=82,
        kill_chain_phase="Reconnaissance",
        mitre_tactic="Reconnaissance",
        mitre_tactic_id="TA0043",
        mitre_technique="Active Scanning",
        mitre_technique_id="T1595",
        mitre_sub_technique="Scanning IP Blocks",
        mitre_sub_technique_id="T1595.001",
        indicators_found=["AUTOMATED_SCANNER_FINGERPRINT"],
        reasoning_summary="Repeated scanner-like requests with elevated 404 ratio.",
        recommendation="Temporarily block source IP and increase monitoring.",
        suggested_mitigations=[],
    )

    alert_store.add_assessment(source_ip, first_assessment)

    second_window = _build_window(second_window_id, source_ip)
    history = alert_store.get_history_by_ip(source_ip, limit=10)
    prompt = AnalysisPromptBuilder.build_optimized_json_prompt(second_window, history)
    input_payload = _extract_input_payload(prompt)

    assert input_payload["target_window_id"] == second_window_id
    assert input_payload["historical_alerts_context"] != "No previous alerts registered for this IP."
    assert first_window_id in input_payload["historical_alerts_context"]
    assert input_payload["security_state_features"]["successful_logins_count"] == 1


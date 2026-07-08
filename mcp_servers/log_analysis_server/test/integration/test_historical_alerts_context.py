"""Integration test for historical_alerts_context population across consecutive analyses."""

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from mcp_servers.log_analysis_server.models.analysis_input import WebActivityWindowInput, SecurityStateFeatures
from mcp_servers.log_analysis_server.models.analysis_output import ThreatAssessment
from mcp_servers.log_analysis_server.services.prompt_factory import build_web_activity_prompt
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
    """Extract INPUT_PAYLOAD JSON from either FULL or OPTIMIZED prompt template."""
    # Handle both FULL_PROMPT_TEMPLATE and OPTIMIZED_PROMPT_TEMPLATE formats
    if "INPUT_PAYLOAD:" not in prompt:
        return {}
    
    # Split on INPUT_PAYLOAD: to get the JSON part
    parts = prompt.split("INPUT_PAYLOAD:", 1)
    if len(parts) < 2:
        return {}
    
    payload_section = parts[1].strip()
    
    # For FULL template, JSON ends at "\n\nRespond ONLY"
    if "\n\nRespond ONLY" in payload_section:
        payload_json = payload_section.split("\n\nRespond ONLY")[0].strip()
    # For OPTIMIZED template, JSON might be followed by "\n\nREQUIRED_OUTPUT_SCHEMA" or similar
    elif "\n\nREQUIRED_OUTPUT_SCHEMA" in payload_section:
        payload_json = payload_section.split("\n\nREQUIRED_OUTPUT_SCHEMA")[0].strip()
    else:
        # Try to extract JSON directly
        payload_json = payload_section.strip()
    
    try:
        return json.loads(payload_json)
    except json.JSONDecodeError:
        return {}


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
    
    # Use new prompt_factory API instead of deprecated AnalysisPromptBuilder
    prompt = build_web_activity_prompt(second_window, history, provider_name="ollama")
    input_payload = _extract_input_payload(prompt)

    assert input_payload.get("target_window_id") == second_window_id or input_payload.get("window_id") == second_window_id
    assert input_payload.get("history") != "No previous alerts registered for this IP."
    assert first_window_id in input_payload.get("history", "")
    assert input_payload["security_state_features"]["successful_logins_count"] == 1


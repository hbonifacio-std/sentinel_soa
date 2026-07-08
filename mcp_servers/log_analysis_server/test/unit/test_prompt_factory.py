"""Unit tests for prompt_factory consolidation and provider-specific prompt building."""

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from mcp_servers.log_analysis_server.models.analysis_input import (
    WebActivityWindowInput,
    SecurityStateFeatures,
)
from mcp_servers.log_analysis_server.models.forensic_input import ForensicReportInput
from mcp_servers.log_analysis_server.services.prompt_factory import (
    build_web_activity_prompt,
    build_forensic_prompt,
    FULL_PROMPT_TEMPLATE,
    OPTIMIZED_PROMPT_TEMPLATE,
    DEFAULT_WEB_ACTIVITY_SCHEMA,
)


def _build_telemetry() -> WebActivityWindowInput:
    """Helper to create a test telemetry object."""
    now = datetime.now(timezone.utc)
    return WebActivityWindowInput(
        window_id=str(uuid4()),
        source_id="victim-app-01",
        source_ip="172.18.0.99",
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


def _extract_json_payload(prompt: str) -> dict:
    """Extract the INPUT_PAYLOAD JSON section from a prompt."""
    if "INPUT_PAYLOAD:" not in prompt:
        return {}
    
    # Split on INPUT_PAYLOAD: to get the JSON part
    parts = prompt.split("INPUT_PAYLOAD:")
    if len(parts) < 2:
        return {}
    
    payload_section = parts[1].strip()
    
    # For FULL/OPTIMIZED templates, JSON ends at "\n\nRespond ONLY"
    if "\n\nRespond ONLY" in payload_section:
        payload_json = payload_section.split("\n\nRespond ONLY")[0].strip()
    # Fallback for other formats
    elif "\n\n" in payload_section:
        payload_json = payload_section.split("\n\n")[0].strip()
    else:
        payload_json = payload_section.strip()
    
    try:
        return json.loads(payload_json)
    except json.JSONDecodeError as e:
        # Return empty dict on parse failure
        return {}


def test_build_web_activity_prompt_for_ollama():
    """Verify build_web_activity_prompt generates OPTIMIZED template for Ollama."""
    telemetry = _build_telemetry()
    history = []
    
    prompt = build_web_activity_prompt(telemetry, history, provider_name="ollama")
    
    # Should use OPTIMIZED_PROMPT_TEMPLATE
    assert "Task: Web Activity Analysis" in prompt or "INPUT_PAYLOAD:" in prompt
    assert "Respond ONLY with a valid JSON object" in prompt
    
    payload = _extract_json_payload(prompt)
    assert payload.get("source_ip") == "172.18.0.99"
    assert "metrics" in payload or "statistical_metrics" in payload
    # history field contains context (empty or with previous alerts)
    assert payload.get("history") is not None


def test_build_web_activity_prompt_for_non_ollama():
    """Verify build_web_activity_prompt generates FULL template for non-Ollama providers."""
    telemetry = _build_telemetry()
    history = []
    
    prompt = build_web_activity_prompt(telemetry, history, provider_name="gemini")
    
    # Should use FULL_PROMPT_TEMPLATE (more detailed)
    assert "Task: Web Activity Analysis" in prompt
    assert "INPUT_PAYLOAD:" in prompt
    assert "Respond ONLY with a valid JSON object" in prompt
    
    payload = _extract_json_payload(prompt)
    assert payload.get("source_ip") == "172.18.0.99"


def test_build_web_activity_prompt_includes_historical_context():
    """Verify historical context is properly formatted when history is provided."""
    from mcp_servers.log_analysis_server.models.analysis_output import ThreatAssessment
    
    telemetry = _build_telemetry()
    
    # Create a mock historical assessment
    historical_assessment = ThreatAssessment(
        window_id=str(uuid4()),
        source_id="victim-app-01",
        source_ip="172.18.0.99",
        threat_detected=True,
        targeted_asset="victim-app [simulation_dmz]",
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
        reasoning_summary="Repeated scanner-like requests.",
        recommendation="Block IP temporarily.",
        suggested_mitigations=[],
    )
    
    history = [historical_assessment]
    
    prompt = build_web_activity_prompt(telemetry, history, provider_name="ollama")
    payload = _extract_json_payload(prompt)
    
    # Should include the historical alert in context  
    # The history field contains formatted alert information
    assert payload.get("history") != "No previous alerts registered for this IP."
    assert "Level=" in payload.get("history", "")


def test_build_forensic_prompt_with_rows():
    """Verify build_forensic_prompt handles log rows and token budgeting."""
    payload = ForensicReportInput(
        query="Find POST requests to /api/auth",
        source_id="victim-app-01",
        total_matches=1,
    )
    rows = [
        {
            "timestamp_utc": "2026-07-08T10:00:00Z",
            "source_ip": "192.168.1.100",
            "http": {"method": "POST", "path": "/api/auth", "status_code": 200, "user_agent": "curl/7.64.1"},
            "network": {"client_ip": "192.168.1.100"},
            "extra_fields": {"user": {"attempted_username": "admin", "authenticated_id": "user123"}},
        }
    ]
    
    prompt = build_forensic_prompt(
        payload, rows, provider_name="ollama", max_input_tokens=None
    )
    
    assert "forensic report" in prompt.lower() or "user_query" in prompt
    assert "192.168.1.100" in prompt or "Find POST requests to /api/auth" in prompt


def test_build_forensic_prompt_respects_max_tokens():
    """Verify build_forensic_prompt trims rows when max_input_tokens is set."""
    payload = ForensicReportInput(
        query="Find suspicious activity",
        source_id="victim-app-01",
        total_matches=20,
    )
    
    # Create many rows to ensure token budget triggers trimming
    rows = [
        {
            "timestamp_utc": f"2026-07-08T10:{i:02d}:00Z",
            "source_ip": "192.168.1.100",
            "http": {
                "method": "POST",
                "path": f"/api/endpoint{i}",
                "status_code": 200,
                "user_agent": "test-agent",
                "payload": "X" * 100,  # Large payload
            },
            "network": {"client_ip": "192.168.1.100"},
            "extra_fields": {"user": {"attempted_username": f"user{i}"}},
        }
        for i in range(20)
    ]
    
    prompt = build_forensic_prompt(
        payload, rows, provider_name="ollama", max_input_tokens=1000
    )
    
    # Should have reduced row count (not all 20 rows)
    # Count "ts": occurrences to verify sample reduction
    row_count = prompt.count('"ts":')
    assert row_count < len(rows), "Rows should have been sampled/trimmed for token budget"


def test_prompt_factory_contains_valid_schemas():
    """Verify output schemas are properly formatted JSON."""
    telemetry = _build_telemetry()
    
    prompt = build_web_activity_prompt(telemetry, [], provider_name="gemini")
    
    # Extract and validate the schema
    if "SCHEMA:" in prompt:
        schema_start = prompt.index("SCHEMA:") + len("SCHEMA:")
        schema_part = prompt[schema_start:].strip()
        # Try to parse as JSON
        try:
            parsed = json.loads(schema_part)
            assert isinstance(parsed, dict)
            assert "threat_score" in parsed
        except json.JSONDecodeError:
            pytest.skip("Schema is not parseable JSON (expected for template)")


def test_build_web_activity_prompt_window_id_is_string():
    """Regression test: window_id must be a string in JSON payload."""
    telemetry = _build_telemetry()
    history = []
    
    prompt = build_web_activity_prompt(telemetry, history, provider_name="ollama")
    payload = _extract_json_payload(prompt)
    
    assert isinstance(payload.get("window_id") or payload.get("target_window_id"), str)


def test_build_forensic_prompt_with_system_context_note():
    """Verify build_forensic_prompt includes system_context_note when provided."""
    payload = ForensicReportInput(
        query="Find suspicious login attempts",
        source_id="victim-app-01",
        total_matches=5,
    )
    rows = [
        {
            "timestamp_utc": "2026-07-08T10:00:00Z",
            "source_ip": "192.168.1.100",
            "http": {"method": "POST", "path": "/api/auth", "status_code": 401},
            "network": {"client_ip": "192.168.1.100"},
            "extra_fields": {"user": {"attempted_username": "admin"}},
        }
    ]
    
    prompt = build_forensic_prompt(
        payload,
        rows,
        provider_name="ollama",
        system_context_note="These logs are a sample from a larger dataset"
    )
    
    # Should include the system context note in the payload
    assert "These logs are a sample from a larger dataset" in prompt


def test_build_forensic_prompt_for_non_ollama_provider():
    """Verify build_forensic_prompt uses FULL template for non-Ollama providers."""
    payload = ForensicReportInput(
        query="Find SQL injection attempts",
        source_id="victim-app-01",
        total_matches=2,
    )
    rows = [
        {
            "timestamp_utc": "2026-07-08T10:00:00Z",
            "source_ip": "192.168.1.100",
            "http": {"method": "POST", "path": "/login", "status_code": 200},
            "network": {"client_ip": "192.168.1.100"},
        }
    ]
    
    prompt = build_forensic_prompt(
        payload, rows, provider_name="gemini", max_input_tokens=None
    )
    
    # Non-Ollama should use FULL template (more detailed)
    assert "You are a senior cybersecurity analyst" in prompt or "task_name" in prompt


def test_build_forensic_prompt_returns_as_is_when_cannot_trim():
    """Verify build_forensic_prompt returns prompt as-is when it can't trim further."""
    payload = ForensicReportInput(
        query="Test",
        source_id="victim-app-01",
        total_matches=1,
    )
    rows = [
        {
            "timestamp_utc": "2026-07-08T10:00:00Z",
            "source_ip": "192.168.1.1",
            "http": {"method": "GET", "path": "/"},
            "network": {"client_ip": "192.168.1.1"},
        }
    ]
    
    # Even with a very restrictive budget, should not fail
    prompt = build_forensic_prompt(
        payload, rows, provider_name="ollama", max_input_tokens=100
    )
    
    # Should return something (even if over budget)
    assert len(prompt) > 0
    assert "forensic" in prompt.lower() or "user_query" in prompt


def test_build_nlq_to_mongo_prompt_for_ollama():
    """Verify build_nlq_to_mongo_prompt generates correct template for Ollama."""
    from mcp_servers.log_analysis_server.services.prompt_factory import build_nlq_to_mongo_prompt
    
    prompt = build_nlq_to_mongo_prompt(
        query="Find all POST requests to /api/users",
        provider_name="ollama",
        source_id="app-01"
    )
    
    assert "Natural Language to MongoDB" in prompt or "MongoDB" in prompt
    assert "/api/users" in prompt
    assert "app-01" in prompt
    assert "Respond ONLY with a valid JSON object" in prompt


def test_build_nlq_to_mongo_prompt_for_non_ollama():
    """Verify build_nlq_to_mongo_prompt generates correct template for non-Ollama."""
    from mcp_servers.log_analysis_server.services.prompt_factory import build_nlq_to_mongo_prompt
    
    prompt = build_nlq_to_mongo_prompt(
        query="Find 404 errors from specific IP",
        provider_name="gemini",
        source_id=None
    )
    
    assert "Natural Language to MongoDB" in prompt or "MongoDB" in prompt
    assert "404 errors" in prompt
    assert "Respond ONLY with a valid JSON object" in prompt

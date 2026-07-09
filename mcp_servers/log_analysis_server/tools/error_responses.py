"""Typed builders for MCP tool error payloads."""

from __future__ import annotations

from typing import Any


def build_analyze_web_activity_error(
    *,
    source_ip: str,
    unique_uris_requested: list[str],
    error: str,
) -> dict[str, Any]:
    """Build a safe fallback verdict when analyze_web_activity fails."""
    uri_sample = unique_uris_requested[:5]
    return {
        "source_ip": source_ip,
        "threat_detected": False,
        "threat_level": "NONE",
        "threat_score": 0,
        "indicators_found": ["analysis_execution_error"],
        "reasoning_summary": "MCP tool execution failed before producing a valid analytical verdict.",
        "recommendation": "Review MCP server logs, validate telemetry window payload, and rerun analysis.",
        "targeted_asset": f"victim-app [simulation_dmz] paths: {uri_sample}",
        "mitre_tactic": None,
        "mitre_tactic_id": None,
        "mitre_technique": None,
        "mitre_technique_id": None,
        "mitre_sub_technique": None,
        "mitre_sub_technique_id": None,
        "suggested_mitigations": [],
        "error": error,
    }


def build_threat_context_error(*, source_ip: str, error: str) -> dict[str, Any]:
    """Build a safe fallback payload when get_threat_context fails."""
    return {
        "source_ip": source_ip,
        "history": [],
        "alerts_found": 0,
        "error": error,
    }

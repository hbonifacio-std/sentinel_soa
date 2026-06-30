"""
Service responsible for analyzing telemetry data.
"""
import json
import logging
from typing import Any, Dict, List

from core_orchestrator.agent.mcp_client import MCPClientManager
from core_orchestrator.application.services.rules_engine_service import RulesEngineService
from core_orchestrator.domain.ports.analysis_service_port import AnalysisServicePort

logger = logging.getLogger(__name__)


def _normalize_score(value: Any, default: int = 0) -> int:
    """Coerces a score-like value into an integer [0, 100]."""
    try:
        score = int(round(float(value)))
    except (TypeError, ValueError):
        score = default
    return max(0, min(100, score))


def _minimal_indicators(telemetry_payload: Dict[str, Any]) -> List[str]:
    """Builds a deterministic fallback indicator list from telemetry payload."""
    indicators: List[str] = []

    uris = [str(uri).lower() for uri in telemetry_payload.get("unique_uris_requested", [])[:20] if isinstance(uri, str)]
    if any("../" in uri or "%2e%2e" in uri or "/etc/passwd" in uri or "/etc/shadow" in uri for uri in uris):
        indicators.append("PATH_TRAVERSAL_PROBE")
    if any(token in uri for uri in uris for token in ["/.env", "/.aws", "/.git", "/swagger", "/server-status", "/actuator"]):
        indicators.append("SENSITIVE_RESOURCE_ENUMERATION")

    rps = telemetry_payload.get("requests_per_second_avg", 0)
    try:
        if float(rps) > 5:
            indicators.append("ANOMALOUS_REQUEST_RATE")
    except (TypeError, ValueError):
        pass

    if not indicators:
        indicators.append("insufficient_llm_output")
    return indicators


def _build_safe_analysis_result(analysis_result: Dict[str, Any], telemetry_payload: Dict[str, Any], source_ip: str) -> Dict[str, Any]:
    """Ensures a minimum persistence contract even when MCP/LLM returns partial outputs."""
    safe = dict(analysis_result or {})

    if safe.get("error"):
        logger.warning("MCP analysis returned an error for %s: %s", source_ip, safe.get("error"))

    safe["source_ip"] = source_ip
    safe["source_id"] = safe.get("source_id") or telemetry_payload.get("source_id", "unknown")
    safe["window_id"] = str(safe.get("window_id") or telemetry_payload.get("window_id", "unknown"))

    score = _normalize_score(safe.get("threat_score"), 0)
    safe["threat_score"] = score

    detected = bool(safe.get("threat_detected", False))
    if score >= 40:
        detected = True
    elif score < 20:
        detected = False
    safe["threat_detected"] = detected

    if score >= 90:
        safe.setdefault("threat_level", "CRITICAL")
    elif score >= 70:
        safe.setdefault("threat_level", "HIGH")
    elif score >= 40:
        safe.setdefault("threat_level", "MEDIUM")
    elif score >= 20:
        safe.setdefault("threat_level", "LOW")
    else:
        safe.setdefault("threat_level", "NONE")

    indicators = safe.get("indicators_found")
    if not isinstance(indicators, list) or not indicators:
        safe["indicators_found"] = _minimal_indicators(telemetry_payload)

    safe.setdefault("targeted_asset", f"victim-app [simulation_dmz] paths: {telemetry_payload.get('unique_uris_requested', [])[:5]}")
    safe.setdefault("reasoning_summary", "Structured fallback generated due to partial MCP/LLM output.")
    safe.setdefault("recommendation", "Review telemetry window, enable stricter rate limiting, and investigate suspicious paths.")

    # Minimal MITRE alignment for detected activity if provider omitted these fields.
    if safe.get("threat_detected") and not (safe.get("mitre_tactic_id") and safe.get("mitre_technique_id")):
        safe["mitre_tactic"] = safe.get("mitre_tactic") or "Reconnaissance"
        safe["mitre_tactic_id"] = safe.get("mitre_tactic_id") or "TA0043"
        safe["mitre_technique"] = safe.get("mitre_technique") or "Active Scanning"
        safe["mitre_technique_id"] = safe.get("mitre_technique_id") or "T1595"
        safe["mitre_sub_technique"] = safe.get("mitre_sub_technique") or "Vulnerability Scanning"
        safe["mitre_sub_technique_id"] = safe.get("mitre_sub_technique_id") or "T1595.002"

    return safe


class AnalysisService(AnalysisServicePort):
    def __init__(self, mcp_manager: MCPClientManager, rules_engine_service: RulesEngineService):
        self.mcp_manager = mcp_manager
        self.rules_engine_service = rules_engine_service

    async def analyze_activity(self, telemetry_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Calls the MCP to analyze web activity and returns a sanitized result."""
        source_ip = telemetry_payload.get("source_ip", "UNKNOWN")
        logger.info(f"Requesting web activity analysis for {source_ip}")

        # Ensure types are string for the MCP tool
        telemetry_payload['window_id'] = str(telemetry_payload.get('window_id'))
        telemetry_payload['window_start_utc'] = str(telemetry_payload.get('window_start_utc'))
        telemetry_payload['window_end_utc'] = str(telemetry_payload.get('window_end_utc'))

        _ANALYZE_TOOL_FIELDS = {
            "window_id", "source_id", "source_ip",
            "window_start_utc", "window_end_utc",
            "total_requests", "unique_uris_requested",
            "http_methods_distribution", "response_codes_distribution",
            "user_agents_observed", "requests_per_second_avg",
            "attempted_usernames",
            "invalid_token_requests_count",
            "max_response_size_bytes",
            "suspicious_samples",
            "critical_payload_features",
            "infra_context",
            "security_state_features",
        }
        tool_arguments = {k: v for k, v in telemetry_payload.items() if k in _ANALYZE_TOOL_FIELDS}

        rules_bundle = await self.rules_engine_service.get_active_rules()
        tool_arguments["rules_bundle"] = rules_bundle.to_cache_dict()
        logger.info(
            "Forwarding telemetry window %s to MCP with rules bundle version=%s",
            telemetry_payload.get("window_id"), rules_bundle.version_hash,
        )

        raw_analysis_result = await self.mcp_manager.call_tool(
            tool_name="analyze_web_activity", arguments=tool_arguments
        )

        analysis_result: Dict[str, Any] = {}
        if hasattr(raw_analysis_result, "content") and raw_analysis_result.content:
            try:
                analysis_result = json.loads(raw_analysis_result.content[0].text)
            except (json.JSONDecodeError, IndexError, AttributeError):
                logger.error("Could not parse JSON from analyze_web_activity. Using empty fallback.")
                analysis_result = {"threat_detected": False, "threat_score": 0}
        else:
            analysis_result = raw_analysis_result if isinstance(raw_analysis_result, dict) else {}
        
        if "source_ip" not in analysis_result:
            analysis_result["source_ip"] = source_ip

        safe_result = _build_safe_analysis_result(analysis_result, telemetry_payload, source_ip)
        logger.info(
            f"Analysis completed for {source_ip}: threat_detected={safe_result.get('threat_detected')}, "
            f"score={safe_result.get('threat_score', 'N/A')}%"
        )
        return safe_result

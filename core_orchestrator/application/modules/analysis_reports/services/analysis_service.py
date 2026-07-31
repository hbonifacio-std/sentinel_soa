"""Service responsible for analyzing telemetry data."""

import logging
from typing import Any, Dict, List

from core_orchestrator.application.modules.analysis_reports.services.rules_engine_service import RulesEngineService
from core_orchestrator.domain.entities.agent.agents import LLMResponseAnalyzer
from core_orchestrator.domain.ports import AiAnalysisPort, LlmAnalysisPort
from core_orchestrator.infrastructure.security.rules_bundle_signer import sign_rules_bundle

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

    try:
        if float(telemetry_payload.get("requests_per_second_avg", 0)) > 5:
            indicators.append("ANOMALOUS_REQUEST_RATE")
    except (TypeError, ValueError):
        pass

    return indicators or ["insufficient_llm_output"]


def _apply_threat_level_defaults(safe: Dict[str, Any], score: int) -> None:
    """Populate threat classification defaults based on the normalized score."""
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


def _ensure_mitre_defaults(safe: Dict[str, Any]) -> None:
    """Ensure MITRE ATT&CK metadata exists for detected threats."""
    if safe.get("threat_detected") and not (safe.get("mitre_tactic_id") and safe.get("mitre_technique_id")):
        safe["mitre_tactic"] = safe.get("mitre_tactic") or "Reconnaissance"
        safe["mitre_tactic_id"] = safe.get("mitre_tactic_id") or "TA0043"
        safe["mitre_technique"] = safe.get("mitre_technique") or "Active Scanning"
        safe["mitre_technique_id"] = safe.get("mitre_technique_id") or "T1595"
        safe["mitre_sub_technique"] = safe.get("mitre_sub_technique") or "Vulnerability Scanning"
        safe["mitre_sub_technique_id"] = safe.get("mitre_sub_technique_id") or "T1595.002"


def _build_safe_analysis_result(
    analysis_result: Dict[str, Any],
    telemetry_payload: Dict[str, Any],
    source_ip: str,
) -> Dict[str, Any]:
    """Ensures a minimum persistence contract even when MCP/LLM returns partial outputs."""
    safe = dict(analysis_result or {})

    if safe.get("error"):
        logger.warning("MCP analysis returned an error for %s: %s", source_ip, safe.get("error"))

    safe["source_ip"] = source_ip
    source_id = safe.get("source_id")
    if not source_id or str(source_id).strip().lower() in {"n/a", "unknown", "unknown-service", "none"}:
        source_id = telemetry_payload.get("source_id", "unknown")
    safe["source_id"] = source_id
    safe["client_id"] = safe.get("client_id") or telemetry_payload.get("client_id")
    safe["window_id"] = str(safe.get("window_id") or telemetry_payload.get("window_id", "unknown"))

    score = _normalize_score(safe.get("threat_score"), 0)
    safe["threat_score"] = score

    detected = bool(safe.get("threat_detected", False))
    if score >= 40:
        detected = True
    elif score < 20:
        detected = False
    safe["threat_detected"] = detected

    _apply_threat_level_defaults(safe, score)

    if not isinstance(safe.get("indicators_found"), list) or not safe.get("indicators_found"):
        safe["indicators_found"] = _minimal_indicators(telemetry_payload)

    safe.setdefault("targeted_asset", f"victim-app [simulation_dmz] paths: {telemetry_payload.get('unique_uris_requested', [])[:5]}")
    safe.setdefault("reasoning_summary", "Structured fallback generated due to partial MCP/LLM output.")
    safe.setdefault("recommendation", "Review telemetry window, enable stricter rate limiting, and investigate suspicious paths.")

    _ensure_mitre_defaults(safe)

    return safe


class AiAnalysis(AiAnalysisPort):

    async def format_response(self, response: str) -> LLMResponseAnalyzer:
        pass

    def __init__(
        self,
        llm_analysis_port: LlmAnalysisPort,
        rules_engine_service: RulesEngineService,
        tenant_provider_service: Any = None,
    ):
        self.llm_analysis_port = llm_analysis_port
        self.rules_engine_service = rules_engine_service
        self.tenant_provider_service = tenant_provider_service

    async def analyze_activity(self, telemetry_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Calls the MCP to analyze web activity and returns a sanitized result."""
        source_ip = telemetry_payload.get("source_ip", "UNKNOWN")
        logger.info("Requesting web activity analysis for %s", source_ip)

        telemetry_payload = dict(telemetry_payload)
        telemetry_payload["window_id"] = str(telemetry_payload.get("window_id"))
        telemetry_payload["window_start_utc"] = str(telemetry_payload.get("window_start_utc"))
        telemetry_payload["window_end_utc"] = str(telemetry_payload.get("window_end_utc"))

        allowed_fields = {
            "window_id",
            "source_ip",
            "window_start_utc",
            "window_end_utc",
            "total_requests",
            "unique_uris_requested",
            "http_methods_distribution",
            "response_codes_distribution",
            "user_agents_observed",
            "requests_per_second_avg",
            "attempted_usernames",
            "invalid_token_requests_count",
            "max_response_size_bytes",
            "suspicious_samples",
            "critical_payload_features",
            "infra_context",
            "security_state_features",
        }
        tool_arguments = {k: v for k, v in telemetry_payload.items() if k in allowed_fields}

        client_id = telemetry_payload.get("client_id")
        if client_id and self.tenant_provider_service:
            try:
                provider_override = await self.tenant_provider_service.get_default_provider_config(client_id)
                if provider_override:
                    tool_arguments["provider_override"] = provider_override
            except Exception as e:
                logger.warning(f"Could not resolve default provider_override for client_id {client_id}: {e}")

        rules_bundle = await self.rules_engine_service.get_active_rules(
            client_id=telemetry_payload.get("client_id")
        )
        signed_bundle = self._sign_rules_bundle(rules_bundle.to_cache_dict())
        tool_arguments["rules_bundle"] = signed_bundle
        logger.info(
            "Forwarding telemetry window %s to MCP with rules bundle version=%s (signed)",
            telemetry_payload.get("window_id"),
            rules_bundle.version_hash,
        )

        analysis_result = await self.llm_analysis_port.analyze_web_activity(tool_arguments)
        logger.info("MCP analysis completed for %s", source_ip)
        return _build_safe_analysis_result(analysis_result, telemetry_payload, source_ip)

    @staticmethod
    def _sign_rules_bundle(rules_bundle: Dict[str, Any]) -> Dict[str, Any]:
        """Sign rules_bundle with HMAC to ensure integrity and authenticity."""
        return sign_rules_bundle(rules_bundle)

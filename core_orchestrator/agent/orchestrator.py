"""Core orchestrator agent module.

Manages the AI reasoning loop, translating security requirements into
MCP tool calls and consolidating the final verdict.
"""

import logging
import json
from datetime import datetime, timezone
from typing import Dict, Any, List

from core_orchestrator.services.database import db
from core_orchestrator.services.rules_engine import get_rules_engine
from core_orchestrator.agent.mcp_client import MCPClientManager

logger = logging.getLogger("core_orchestrator.agent.orchestrator")


def ensure_created_at_utc(val: Any) -> datetime:
    """Normalizes any datetime or string input to timezone-aware UTC datetime."""
    if not val:
        return datetime.now(timezone.utc)
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)
    if isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)


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


class OrchestratorAgent:
    """
    Controller responsible for orchestration and tool
    invocation under the MCP protocol.
    """

    def __init__(self, mcp_manager: MCPClientManager):
        """
        Initializes the agent and the associated MCP client.
        """
        self.mcp_manager = mcp_manager


    async def get_redis_lock(self, lock_key: str, timeout: int = 10):
        """
        Acquires a distributed lock using Redis.
        """
        return db.redis_client.lock(lock_key, timeout=timeout)

    async def process_telemetry_window(self, telemetry_payload: Dict[str, Any]) -> str:
        """
        Initiates the analytical reasoning cycle for a telemetry time window.
        """
        source_ip = telemetry_payload.get("source_ip", "UNKNOWN")
        logger.info(
            f"Orchestrator Agent activated to analyze IP: {source_ip}")

        try:
            # --- STEP 0: Check Redis cache ---
            cache_key = f"cache:analysis:{json.dumps(telemetry_payload, sort_keys=True, default=str)}"
            cached_result = await db.redis_client.get(cache_key)
            if cached_result:
                logger.info(
                    f"Analysis result found in cache for {source_ip}.")
                return cached_result.decode('utf-8')

            # --- STEP 1: Mandatory execution of the first analytical tool ---
            logger.info(
                f"Step 1: Requesting web activity analysis for {source_ip}")

            # Ensure types are string for the MCP tool
            telemetry_payload['window_id'] = str(telemetry_payload.get('window_id'))
            telemetry_payload['window_start_utc'] = str(telemetry_payload.get('window_start_utc'))
            telemetry_payload['window_end_utc'] = str(telemetry_payload.get('window_end_utc'))

            # Whitelist: only forward fields declared in the MCP tool signature.
            # This prevents future TelemetryWindow fields from breaking the call
            # if FastMCP rejects unknown parameters.
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

            # Filtramos de manera segura basándonos en la lista blanca
            tool_arguments = {
                k: v for k, v in telemetry_payload.items()
                if k in _ANALYZE_TOOL_FIELDS
            }

            rules_bundle = await get_rules_engine().get_active_rules()
            tool_arguments["rules_bundle"] = rules_bundle.to_cache_dict()
            logger.info(
                "Forwarding telemetry window %s to MCP with rules bundle version=%s",
                telemetry_payload.get("window_id"),
                rules_bundle.version_hash,
            )

            raw_analysis_result = await self.mcp_manager.call_tool(
                tool_name="analyze_web_activity",
                arguments=tool_arguments
            )

            analysis_result: Dict[str, Any] = {}
            if hasattr(raw_analysis_result, "content") and raw_analysis_result.content:
                try:
                    analysis_result = json.loads(
                        raw_analysis_result.content[0].text)
                except (json.JSONDecodeError, IndexError, AttributeError):
                    logger.error(
                        "Could not parse JSON from analyze_web_activity. Using empty fallback.")
                    analysis_result = {
                        "threat_detected": False, "threat_score": 0}
            else:
                analysis_result = raw_analysis_result if isinstance(
                    raw_analysis_result, dict) else {}

            if "source_ip" not in analysis_result:
                analysis_result["source_ip"] = source_ip

            analysis_result = _build_safe_analysis_result(analysis_result, telemetry_payload, source_ip)

            logger.info(
                f"Analysis completed for {source_ip}: threat_detected={analysis_result.get('threat_detected')}, "
                f"score={analysis_result.get('threat_score', 'N/A')}%")

            # --- STEP 2: If threat detected, get historical context ---
            if analysis_result.get("threat_detected", False):
                logger.info(
                    f"Step 2: Threat detected. Requesting historical context for {source_ip}")

                raw_context_result = await self.mcp_manager.call_tool(
                    tool_name="get_threat_context",
                    arguments={"source_ip": source_ip, "limit": 5}
                )

                context_result: Dict[str, Any] = {}
                if hasattr(raw_context_result, "content") and raw_context_result.content:
                    try:
                        context_result = json.loads(
                            raw_context_result.content[0].text)
                    except (json.JSONDecodeError, IndexError, AttributeError):
                        context_result = {"history": []}
                else:
                    context_result = raw_context_result if isinstance(
                        raw_context_result, dict) else {}

                analysis_result["threat_history"] = context_result.get(
                    "history", [])
                logger.info(
                    f"Historical context added: {len(context_result.get('history', []))} previous alerts")

            # --- STEP 3: Save the result to MongoDB and cache it in Redis ---
            final_report_json = json.dumps(
                analysis_result, indent=2, ensure_ascii=False, default=str)

            # Save to MongoDB — add audit/triage default fields
            analysis_result.setdefault("reviewed", False)
            analysis_result.setdefault("actions", [])
            analysis_result.setdefault("resolved", False)
            analysis_result.setdefault("created_at_utc", datetime.now(timezone.utc))
            await db.get_app_db().analysis_reports.insert_one(analysis_result)

            # Save to Redis cache (5 minutes)
            await db.redis_client.set(cache_key, final_report_json, ex=300)

            logger.debug(
                f"Returning analysis and saving to the database for {source_ip}")
            return final_report_json

        except Exception as exc:
            logger.error(
                f"Failure during the Orchestrator Agent's reasoning cycle: {str(exc)}", exc_info=True)
            return json.dumps({
                "status": "error",
                "error": str(exc),
                "source_ip": source_ip,
                "threat_detected": False,
                "threat_level": "NONE"
            }, ensure_ascii=False)

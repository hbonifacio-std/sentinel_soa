"""
MCP tool module for advanced web activity analysis.

This file contains the implementation of the 'analyze_web_activity' tool,
which processes aggregated HTTP telemetry windows using artificial intelligence
to identify early phases of the Cyber Kill Chain model.

Supports multiple LLM providers (Gemini, Ollama, etc.) via factory pattern.
"""

import logging
import json
import re
from typing import Dict, Any, List, Optional

from mcp_servers.log_analysis_server.config import server_settings as settings
from mcp_servers.log_analysis_server.models.analysis_input import WebActivityWindowInput as AnalysisInput
from mcp_servers.log_analysis_server.models.analysis_output import ThreatAssessment as AnalysisOutput
from mcp_servers.log_analysis_server.models.rules_bundle import RulesBundle

from mcp_servers.log_analysis_server.services.heuristics_engine import ThreatHeuristics
from mcp_servers.log_analysis_server.store.alert_store import alert_store
from mcp_servers.log_analysis_server.llm_providers import create_llm_provider

# Local logger configuration
logger = logging.getLogger(__name__)

_INDICATOR_GENERIC_TOKENS = {
    "abnormal_rps",
    "suspicious_user_agents",
    "scanner_activity",
    "recon_activity",
}

_SENSITIVE_URI_TOKENS = [
    "/.env", "/.aws", "/etc/", "/server-status", "/swagger", "/.git", "/admin", "/actuator", "/wp-",
]

_ENCODED_TRAVERSAL_TOKEN = "%2e%2e"

# ---------------------------------------------------------------------------
# MITRE ATT&CK Governance Matrix — determinista y desacoplada del LLM.
# Orden de prioridad: SQLi (100) > Path Traversal (90) > Auth (80) > Scanner (70) > Enumeration (60)
# ---------------------------------------------------------------------------
MITRE_MATRIX: Dict[str, Dict[str, Any]] = {
    "SQL_INJECTION_PROBE": {
        "mitre_tactic": "Initial Access",
        "mitre_tactic_id": "TA0001",
        "mitre_technique": "Exploit Public-Facing Application",
        "mitre_technique_id": "T1190",
        "mitre_sub_technique": "SQL Injection",
        "mitre_sub_technique_id": "T1190.002",
        "kill_chain_phase": "Exploitation",
        "suggested_actions": [
            {
                "action": "block_ip",
                "reason": "SQL injection probe detected against public-facing endpoints.",
                "severity": "critical",
                "automation_ready": True,
            },
            {
                "action": "rate_limit_ip",
                "reason": "Reduce repeated payload attempts while incident triage runs.",
                "severity": "high",
                "automation_ready": True,
            },
        ],
        "_priority": 100,
    },
    "PATH_TRAVERSAL_PROBE": {
        "mitre_tactic": "Initial Access",
        "mitre_tactic_id": "TA0001",
        "mitre_technique": "Exploit Public-Facing Application",
        "mitre_technique_id": "T1190",
        "mitre_sub_technique": "Path Traversal",
        "mitre_sub_technique_id": "T1190.005",
        "kill_chain_phase": "Exploitation",
        "suggested_actions": [
            {
                "action": "block_ip",
                "reason": "Path traversal attempt against sensitive filesystem paths.",
                "severity": "high",
                "automation_ready": True,
            }
        ],
        "_priority": 90,
    },
    "AUTHENTICATION_OR_AUTHORIZATION_PROBING": {
        "mitre_tactic": "Credential Access",
        "mitre_tactic_id": "TA0006",
        "mitre_technique": "Brute Force",
        "mitre_technique_id": "T1110",
        "mitre_sub_technique": "Password Spraying",
        "mitre_sub_technique_id": "T1110.003",
        "kill_chain_phase": "Exploitation",
        "suggested_actions": [
            {
                "action": "rate_limit_ip",
                "reason": "Authentication probing pattern indicates brute-force behavior.",
                "severity": "high",
                "automation_ready": True,
            }
        ],
        "_priority": 80,
    },
    "AUTOMATED_SCANNER_FINGERPRINT": {
        "mitre_tactic": "Reconnaissance",
        "mitre_tactic_id": "TA0043",
        "mitre_technique": "Active Scanning",
        "mitre_technique_id": "T1595",
        "mitre_sub_technique": "Scanning IP Blocks",
        "mitre_sub_technique_id": "T1595.001",
        "kill_chain_phase": "Reconnaissance",
        "suggested_actions": [
            {
                "action": "rate_limit_ip",
                "reason": "Automated scanner signature detected in telemetry.",
                "severity": "medium",
                "automation_ready": True,
            }
        ],
        "_priority": 70,
    },
    "SENSITIVE_RESOURCE_ENUMERATION": {
        "mitre_tactic": "Reconnaissance",
        "mitre_tactic_id": "TA0043",
        "mitre_technique": "Active Scanning",
        "mitre_technique_id": "T1595",
        "mitre_sub_technique": "Wordlist Scanning",
        "mitre_sub_technique_id": "T1595.003",
        "kill_chain_phase": "Reconnaissance",
        "suggested_actions": [
            {
                "action": "rate_limit_ip",
                "reason": "Sensitive path enumeration detected through repetitive probing.",
                "severity": "medium",
                "automation_ready": True,
            }
        ],
        "_priority": 60,
    },
}

_MITRE_FALLBACK: Dict[str, Any] = {
    "mitre_tactic": "Reconnaissance",
    "mitre_tactic_id": "TA0043",
    "mitre_technique": "Active Scanning",
    "mitre_technique_id": "T1595",
    "mitre_sub_technique": "Vulnerability Scanning",
    "mitre_sub_technique_id": "T1595.002",
    "kill_chain_phase": "Reconnaissance",
    "suggested_actions": [
        {
            "action": "rate_limit_ip",
            "reason": "Unmapped suspicious activity treated as generic vulnerability scanning.",
            "severity": "medium",
            "automation_ready": True,
        }
    ],
}

_MITRE_FIELDS: List[str] = [
    "mitre_tactic",
    "mitre_tactic_id",
    "mitre_technique",
    "mitre_technique_id",
    "mitre_sub_technique",
    "mitre_sub_technique_id",
]

_LLM_DECISION_FIELDS = ("threat_score", "reasoning_summary", "recommendation")


def _llm_signature_suffix(provider_name: str, model_name: str) -> str:
    """Builds a normalized suffix signature for LLM-authored text fields."""
    provider = str(provider_name or "").strip().lower()
    model = str(model_name or "").strip().lower()
    if not provider or not model:
        return ""
    return f"({provider}-{model})"


def _append_llm_signature(text: Any, provider_name: str, model_name: str) -> str:
    """Appends `(provider-model)` once, preserving the original text contract."""
    content = str(text or "").strip()
    suffix = _llm_signature_suffix(provider_name, model_name)
    if not content or not suffix:
        return content
    if content.lower().endswith(suffix.lower()):
        return content
    return f"{content} {suffix}"


def _extract_rules_bundle(arguments: Dict[str, Any]) -> Optional[RulesBundle]:
    raw_bundle = arguments.get("rules_bundle")
    if raw_bundle is None:
        return None
    if not isinstance(raw_bundle, dict):
        logger.warning("Discarding invalid injected rules bundle: expected dict, got %s", type(raw_bundle).__name__)
        return None

    try:
        return RulesBundle.from_cache_dict(raw_bundle)
    except Exception as exc:
        logger.warning("Failed to parse injected rules bundle: %s", exc)
        return None


def _extract_llm_decision_fields(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Keep only the cognitive fields produced by the LLM provider."""
    if not isinstance(raw, dict):
        return {}
    return {k: raw.get(k) for k in _LLM_DECISION_FIELDS if k in raw}


def _normalize_score(value: Any, default: int) -> int:
    """Normalizes any score-like value to an integer in the range [0, 100]."""
    try:
        score = int(round(float(value)))
    except (TypeError, ValueError):
        return int(max(0, min(100, default)))
    return int(max(0, min(100, score)))


def _clean_indicator_text(indicator: Any) -> str:
    """Removes noisy prefixes/emojis to keep stable indicator labels for persistence."""
    text = str(indicator or "").strip()
    text = re.sub(r"^[^A-Za-z0-9/\\.]+", "", text)
    return text


def _is_raw_path_indicator(text: str) -> bool:
    """Returns True when an indicator looks like a literal URI/path sample."""
    stripped = text.strip().lower()
    return bool(stripped.startswith("/") or stripped.startswith("../") or _ENCODED_TRAVERSAL_TOKEN in stripped)


def _normalize_indicator_label(indicator: Any) -> str:
    """Maps free-text indicators to stable SOC taxonomy labels (no raw routes)."""
    text = _clean_indicator_text(indicator)
    if not text:
        return ""

    lower = text.lower()

    if _is_raw_path_indicator(text):
        if "../" in lower or _ENCODED_TRAVERSAL_TOKEN in lower or "etc/passwd" in lower or "etc/shadow" in lower:
            return "PATH_TRAVERSAL_PROBE"
        if any(token in lower for token in ["/.env", "/.aws", "/.git", "/server-status", "/swagger", "/actuator"]):
            return "SENSITIVE_RESOURCE_ENUMERATION"
        return "SUSPICIOUS_PATH_PROBING"

    if "path traversal" in lower:
        return "PATH_TRAVERSAL_PROBE"
    if "sql injection" in lower or "union select" in lower or "sqlmap" in lower:
        return "SQL_INJECTION_PROBE"
    if "scanner" in lower or "nikto" in lower or "nmap" in lower or "masscan" in lower or "dirbuster" in lower:
        return "AUTOMATED_SCANNER_FINGERPRINT"
    if "suspicious user-agent" in lower:
        return "SUSPICIOUS_USER_AGENT_PATTERN"
    if "high 404" in lower or "404 error ratio" in lower or "moderate 404" in lower:
        return "HIGH_404_ENUMERATION_RATIO"
    if "403" in lower or "access denied" in lower or "auth" in lower or "brute" in lower or "password" in lower:
        return "AUTHENTICATION_OR_AUTHORIZATION_PROBING"
    if "high rps" in lower or "moderately high rps" in lower or "abnormal_rps" in lower:
        return "ANOMALOUS_REQUEST_RATE"
    if "burst" in lower:
        return "REQUEST_BURST_PATTERN"
    if "http method" in lower or "delete" in lower or "trace" in lower or "connect" in lower:
        return "UNUSUAL_HTTP_METHOD_USAGE"
    if "sensitive path" in lower or "request to sensitive path" in lower:
        return "SENSITIVE_RESOURCE_ENUMERATION"

    return text


def _build_deterministic_indicators(analysis_input: AnalysisInput, heuristic_indicators: list) -> list:
    """Builds a deterministic indicator baseline using SOC-style labels."""
    indicators = []

    uris_lower = [str(uri).lower() for uri in analysis_input.unique_uris_requested]
    if any("../" in uri or _ENCODED_TRAVERSAL_TOKEN in uri or "/etc/passwd" in uri or "/etc/shadow" in uri for uri in uris_lower):
        indicators.append("PATH_TRAVERSAL_PROBE")
    if any(any(token in uri for token in _SENSITIVE_URI_TOKENS) for uri in uris_lower):
        indicators.append("SENSITIVE_RESOURCE_ENUMERATION")

    if analysis_input.requests_per_second_avg > 5:
        indicators.append("ANOMALOUS_REQUEST_RATE")

    total_requests = max(analysis_input.total_requests, 1)
    count_404 = analysis_input.response_codes_distribution.get("404", 0)
    if (count_404 / total_requests) > 0.4:
        indicators.append("HIGH_404_ENUMERATION_RATIO")

    suspicious_ua = any(
        any(token in str(ua).lower() for token in ["nikto", "nmap", "sqlmap", "scanner", "masscan", "httpx", "burp"])
        for ua in analysis_input.user_agents_observed
    )
    if suspicious_ua:
        indicators.append("AUTOMATED_SCANNER_FINGERPRINT")

    for h in heuristic_indicators:
        normalized = _normalize_indicator_label(h)
        if normalized:
            indicators.append(normalized)

    # Deduplicate preserving order
    deduped = []
    seen = set()
    for ind in indicators:
        key = ind.lower()
        if key not in seen:
            deduped.append(ind)
            seen.add(key)
    return deduped


def _derive_threat_level(score: int) -> str:
    """Derives deterministic threat level from numeric score."""
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "NONE"


def _build_targeted_asset(analysis_input: AnalysisInput) -> str:
    """Builds deterministic targeted asset description from the first three URIs."""
    uri_sample = [str(uri).strip() for uri in analysis_input.unique_uris_requested if str(uri).strip()][:3]
    paths = ", ".join(uri_sample) if uri_sample else "N/A"
    return f"victim-app [simulation_dmz] paths: [{paths}]"


def _generate_recommendation(threat_level: str, source_ip: str, indicators: list) -> str:
    """Generates a mitigation recommendation based on the threat level and specific indicators."""

    # Analyze specific indicators for more descriptive recommendations
    has_sql_injection = any("SQL" in ind for ind in indicators)
    has_path_traversal = any("path traversal" in ind.lower() for ind in indicators)
    has_scanner = any("Scanner" in ind or "scanning" in ind.lower() for ind in indicators)
    has_admin_access = any("admin" in ind.lower() for ind in indicators)
    has_shell = any("shell" in ind.lower() or "webshell" in ind.lower() for ind in indicators)

    if threat_level == "CRITICAL":
        recommendation = (
            f"🔴 **CRITICAL LEVEL - IMMEDIATE ACTION REQUIRED**\n"
            f"Source IP: {source_ip}\n\n"
            f"**Level 1 (Immediately - 0-5 minutes):**\n"
        )
        if has_shell:
            recommendation += f"• BLOCK IMMEDIATELY in WAF/Firewall. Evidence of webshell attempt detected.\n"
        elif has_sql_injection:
            recommendation += f"• BLOCK IMMEDIATELY in WAF/Firewall. SQL injection attack in progress.\n"
        elif has_path_traversal:
            recommendation += f"• BLOCK IMMEDIATELY in WAF/Firewall. Attempt to access sensitive system files.\n"
        else:
            recommendation += f"• BLOCK IMMEDIATELY IP {source_ip} at all entry points (WAF/Firewall).\n"

        recommendation += (
            f"• Verify if the attack was successful (check 200/500 response codes).\n"
            f"• Prepare incident response team.\n\n"
            f"**Level 2 (In parallel - 5-30 minutes):**\n"
            f"• Run forensic analysis: review access logs from the last 24 hours.\n"
            f"• Correlate with other suspicious IPs or similar patterns.\n"
            f"• Verify server file integrity (web.config, .env, etc.).\n"
            f"• Review file modification events in ACLs.\n\n"
            f"**Level 3 (Escalation - 30+ minutes):**\n"
            f"• Escalate to cybersecurity team and IT leadership.\n"
            f"• Consider server snapshot for malware analysis.\n"
            f"• Begin potential compromise investigation.\n"
        )
    elif threat_level == "HIGH":
        recommendation = (
            f"🟠 **HIGH LEVEL - URGENT ACTION RECOMMENDED**\n"
            f"Source IP: {source_ip}\n\n"
            f"**Level 1 (Immediately):**\n"
            f"• Temporarily block IP {source_ip} in WAF/Firewall for 24 hours.\n"
        )
        if has_scanner:
            recommendation += f"• Implement more aggressive rate-limiting. Enumeration/scanning pattern detected.\n"
        if has_admin_access:
            recommendation += f"• Urgently review access to administrative panels.\n"
        recommendation += (
            f"\n**Level 2 (Next 2 hours):**\n"
            f"• Audit all resources requested by this IP.\n"
            f"• Review logs from the last 24 hours for this source.\n"
            f"• Verify that administrative endpoints are protected (authentication + 2FA).\n"
            f"• Confirm that WAF rules are active for SQL injection/XSS.\n\n"
            f"**Level 3 (Ongoing monitoring):**\n"
            f"• Monitor future behavior of this IP for the next 7 days.\n"
            f"• Consider permanent block if attempts persist.\n"
        )
    elif threat_level == "MEDIUM":
        recommendation = (
            f"🟡 **MEDIUM LEVEL - MONITORING RECOMMENDED**\n"
            f"Source IP: {source_ip}\n\n"
            f"**Recommended Actions:**\n"
            f"• Increase monitoring of IP {source_ip}. Suspicious behavior detected.\n"
            f"• Implement rate-limiting on web endpoints.\n"
            f"• Review recent logs (last 6 hours).\n"
            f"• Consider temporary 24-48 hour block if pattern repeats.\n"
            f"• Verify that WAF/IDS is capturing events and alerting correctly.\n"
        )
    else:
        recommendation = (
            f"🟢 **LOW/BENIGN LEVEL**\n"
            f"Traffic classified as benign or very low suspicion. "
            f"Continue with standard routine monitoring.\n"
            f"No immediate action required.\n"
        )

    return recommendation


def _enrich_with_mitre_dictionary(assessment: Dict[str, Any]) -> Dict[str, Any]:
    """Applies deterministic MITRE mapping and mitigation templating with collision priority."""
    if not assessment.get("threat_detected", False):
        for field in _MITRE_FIELDS:
            assessment[field] = None
        assessment["kill_chain_phase"] = None
        assessment["suggested_mitigations"] = []
        return assessment

    raw_indicators = assessment.get("indicators_found", [])
    if not isinstance(raw_indicators, list):
        raw_indicators = [raw_indicators] if raw_indicators else []

    normalized_indicators = [str(ind).strip().upper() for ind in raw_indicators if str(ind).strip()]

    highest_priority_key: Optional[str] = None
    highest_priority = -1
    for indicator in normalized_indicators:
        signature = MITRE_MATRIX.get(indicator)
        if not signature:
            continue
        current_priority = int(signature.get("_priority", 0))
        if current_priority > highest_priority:
            highest_priority = current_priority
            highest_priority_key = indicator

    selected_signature: Dict[str, Any] = MITRE_MATRIX.get(highest_priority_key, _MITRE_FALLBACK)
    sub_technique = str(selected_signature.get("mitre_sub_technique", "Vulnerability Scanning"))
    sub_technique_id = str(selected_signature.get("mitre_sub_technique_id", "T1595.002"))

    if highest_priority_key is None:
        secondary_text = " ".join(normalized_indicators).lower()
        if "scanner" in secondary_text or "scanning" in secondary_text:
            sub_technique = "Scanning IP Blocks"
            sub_technique_id = "T1595.001"
        elif "enumeration" in secondary_text or "wordlist" in secondary_text:
            sub_technique = "Wordlist Scanning"
            sub_technique_id = "T1595.003"

    assessment["mitre_tactic"] = selected_signature.get("mitre_tactic")
    assessment["mitre_tactic_id"] = selected_signature.get("mitre_tactic_id")
    assessment["mitre_technique"] = selected_signature.get("mitre_technique")
    assessment["mitre_technique_id"] = selected_signature.get("mitre_technique_id")
    assessment["mitre_sub_technique"] = sub_technique
    assessment["mitre_sub_technique_id"] = sub_technique_id
    assessment["kill_chain_phase"] = selected_signature.get("kill_chain_phase")

    source_ip = str(assessment.get("source_ip") or "UNKNOWN")
    mitigations: List[Dict[str, Any]] = []
    for action_template in selected_signature.get("suggested_actions", []):
        if not isinstance(action_template, dict):
            continue
        mitigations.append(
            {
                "action": str(action_template.get("action", "rate_limit_ip")),
                "target": source_ip,
                "reason": str(action_template.get("reason", "Deterministic SOC mitigation.")),
                "severity": str(action_template.get("severity", "medium")),
                "automation_ready": bool(action_template.get("automation_ready", False)),
            }
        )

    assessment["suggested_mitigations"] = mitigations
    return assessment

class LLMAnalyzer:
    """
    Encapsulates the LLM provider invocation logic.

    Supports multiple providers (Gemini, Ollama, etc.) based on configuration.
    Provides an agnostic analysis method that works with any provider.
    """

    _provider = None

    @classmethod
    def _get_provider(cls):
        """Get or create the configured LLM provider."""
        if cls._provider is None:
            config = settings.get_provider_config()
            cls._provider = create_llm_provider(settings.llm_provider, config)
            logger.info(f"LLM provider initialized: {settings.llm_provider}")
        return cls._provider

    @classmethod
    async def analyze_with_context(cls, telemetry: Any, history: list) -> Dict[str, Any]:
        """
        Performs the analysis by requesting the specific prompt from the active provider
        and calling the model.
        """
        try:
            provider = cls._get_provider()
            logger.debug(f"Sending analysis to provider: {provider.provider_name}")

            # KEY CHANGE: The provider generates its own situational prompt polymorphically
            prompt = provider.build_analysis_prompt(telemetry, history)
            print(prompt)
            # Invoke the provider with the generated prompt
            response_text = await provider.call_model(prompt)
            print(response_text)
            # Validate response
            validated_response = await provider.validate_response(response_text)

            # Enforce the cross-provider contract before returning to orchestration logic.
            decision = _extract_llm_decision_fields(validated_response.model_dump())
            decision["reasoning_summary"] = _append_llm_signature(
                decision.get("reasoning_summary"),
                provider.provider_name,
                provider.model_name,
            )
            decision["recommendation"] = _append_llm_signature(
                decision.get("recommendation"),
                provider.provider_name,
                provider.model_name,
            )
            return decision

        except Exception as exc:
            logger.error(f"Error in LLMAnalyzer.analyze_with_context: {str(exc)}", exc_info=True)
            raise


async def execute_analyze_web_activity(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes heuristic and AI analysis on a suspicious web activity window.
    """
    try:
        rules_bundle = _extract_rules_bundle(arguments)
        sanitized_arguments = {k: v for k, v in arguments.items() if k != "rules_bundle"}

        # 1. Strict static validation via the Pydantic v2 model
        analysis_input = AnalysisInput(**sanitized_arguments)

        source_ip = analysis_input.source_ip
        source_id = analysis_input.source_id
        window_id = analysis_input.window_id
        logger.info(f"Starting 'analyze_web_activity' tool for IP: {source_ip} (Window: {window_id})")

        # ========================================================================
        # 2. DETERMINISTIC HEURISTIC ANALYSIS (Confidence baseline)
        # ========================================================================
        logger.debug(f"[HEURISTICS] Running deterministic engine for {source_ip}...")
        heuristic_score, heuristic_indicators, heuristic_reasoning = ThreatHeuristics.analyze(
            analysis_input,
            rules_bundle=rules_bundle,
        )
        if rules_bundle is not None:
            logger.info("[HEURISTICS] Using injected rules bundle version=%s", rules_bundle.version_hash)
        logger.info(f"[HEURISTICS] Score: {heuristic_score}/100 | Indicators: {len(heuristic_indicators)}")

        # ========================================================================
        # 3. TEMPORAL CONTEXT ENRICHMENT: history of previous alerts
        # ========================================================================
        threat_history = alert_store.get_history_by_ip(source_ip, limit=10)
        logger.debug(f"Previous alert history for {source_ip}: {len(threat_history)} records")

        # ========================================================================
        # 4. DIRECT DATA SUBMISSION TO LLM PROVIDER (Internal logic delegated)
        # ========================================================================
        logger.debug(f"Sending telemetry payload from {source_ip} to {settings.llm_provider} API.")

        # Try LLM analysis, fallback to pure heuristics if it fails
        raw_assessment = None
        try:
            # KEY CHANGE: We no longer build the prompt here. We delegate the telemetry and
            # history directly to LLMAnalyzer so the provider decides how to package it.
            raw_assessment = await LLMAnalyzer.analyze_with_context(
                telemetry=analysis_input,
                history=threat_history
            )
            logger.debug(
                f"LLM response received: {json.dumps(raw_assessment, indent=2, ensure_ascii=False)[:300]}...")
        except Exception as llm_err:
            logger.warning(f"LLM analysis failed, using heuristics fallback: {str(llm_err)}")
            raw_assessment = None

        # ========================================================================
        # 5. HYBRID VERDICT CONSTRUCTION (HEURISTICS + OPTIONAL LLM)
        # ========================================================================

        if raw_assessment is None:
            logger.info(f"Using purely heuristic analysis for {source_ip}")
            raw_assessment = {}
        else:
            raw_assessment = _extract_llm_decision_fields(raw_assessment)

        # LLM only returns cognitive fields; the backend owns deterministic structure and scoring policy.
        for field in _MITRE_FIELDS:
            raw_assessment.pop(field, None)

        deterministic_indicators = _build_deterministic_indicators(analysis_input, heuristic_indicators)
        llm_indicators = raw_assessment.get("indicators_found")
        if not isinstance(llm_indicators, list):
            llm_indicators = [llm_indicators] if llm_indicators else []

        merged_indicators = []
        seen = set()
        for indicator in deterministic_indicators + [_normalize_indicator_label(i) for i in llm_indicators]:
            if not indicator:
                continue
            key = indicator.lower()
            if key not in seen:
                merged_indicators.append(indicator)
                seen.add(key)

        if not merged_indicators:
            logger.debug("No valid indicators after merge; using heuristic fallback")
            merged_indicators = deterministic_indicators[:10]

        if merged_indicators and all(ind.lower() in _INDICATOR_GENERIC_TOKENS for ind in merged_indicators):
            merged_indicators = deterministic_indicators[:10] or merged_indicators

        raw_assessment["window_id"] = str(window_id)
        raw_assessment["source_id"] = source_id
        raw_assessment["source_ip"] = source_ip
        raw_assessment["indicators_found"] = merged_indicators[:15]

        threat_score = _normalize_score(raw_assessment.get("threat_score"), heuristic_score)
        raw_assessment["threat_score"] = threat_score
        raw_assessment["threat_detected"] = threat_score >= 20
        raw_assessment["threat_level"] = _derive_threat_level(threat_score)
        raw_assessment["targeted_asset"] = _build_targeted_asset(analysis_input)

        if not raw_assessment.get("reasoning_summary"):
            raw_assessment["reasoning_summary"] = heuristic_reasoning[:500]

        if not raw_assessment.get("recommendation"):
            raw_assessment["recommendation"] = _generate_recommendation(
                raw_assessment["threat_level"], source_ip, merged_indicators
            )

        # Blindar el veredicto con gobernanza MITRE determinista antes de instanciar el modelo
        raw_assessment = _enrich_with_mitre_dictionary(raw_assessment)

        # Validation and instantiation of the output model
        analysis_output = AnalysisOutput(**raw_assessment)

        # ========================================================================
        # 6. ASSESSMENT PERSISTENCE (for temporal context)
        # ========================================================================
        alert_store.add_assessment(source_ip, analysis_output)

        if analysis_output.threat_detected:
            logger.warning(
                f"[⚠ ALERT GENERATED] Threat detected from {source_ip}. "
                f"Level: {analysis_output.threat_level} | Score: {analysis_output.threat_score}% | "
                f"Phase: {analysis_output.kill_chain_phase}"
            )
        else:
            logger.info(
                f"[✓ CLEAN] No threats detected for {source_ip} (score: {analysis_output.threat_score}%)")

        # Return the validated primitive dictionary required by the MCP protocol
        result = analysis_output.model_dump()
        logger.debug(
            f"Final result for {source_ip}: threat_detected={result.get('threat_detected')}, score={result.get('threat_score')}%")

        return result

    except ValueError as val_err:
        logger.error(f"Schema validation error in 'analyze_web_activity': {str(val_err)}")
        raise ValueError(f"Invalid arguments for the tool: {str(val_err)}") from val_err

    except Exception as exc:
        logger.critical(f"Unexpected critical failure in the analytical tool: {str(exc)}", exc_info=True)
        raise Exception(f"Internal error in analytical tool execution: {str(exc)}") from exc

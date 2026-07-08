"""Indicator normalization and deterministic indicator building.

Handles the extraction, normalization and deduplication of threat indicators
from heuristic and LLM sources.
"""

import re
from typing import Any, List

from mcp_servers.log_analysis_server.models.analysis_input import WebActivityWindowInput as AnalysisInput

# Heuristic indicator tokens for generic classification
INDICATOR_GENERIC_TOKENS = {
    "abnormal_rps",
    "suspicious_user_agents",
    "scanner_activity",
    "recon_activity",
}

# Sensitive paths tokens for detection
SENSITIVE_URI_TOKENS = [
    "/.env", "/.aws", "/etc/", "/server-status", "/swagger", "/.git", "/admin", "/actuator", "/wp-",
]

# Encoded path traversal indicator
ENCODED_TRAVERSAL_TOKEN = "%2e%2e"


def _clean_indicator_text(indicator: Any) -> str:
    """Removes noisy prefixes/emojis to keep stable indicator labels for persistence."""
    text = str(indicator or "").strip()
    text = re.sub(r"^[^A-Za-z0-9/\\.]+", "", text)
    return text


def _is_raw_path_indicator(text: str) -> bool:
    """Returns True when an indicator looks like a literal URI/path sample."""
    stripped = text.strip().lower()
    return bool(stripped.startswith("/") or stripped.startswith("../") or ENCODED_TRAVERSAL_TOKEN in stripped)


def normalize_indicator_label(indicator: Any) -> str:
    """Maps free-text indicators to stable SOC taxonomy labels (no raw routes).

    Args:
        indicator: Raw indicator text from heuristics or LLM.

    Returns:
        Normalized SOC-style indicator label.
    """
    text = _clean_indicator_text(indicator)
    if not text:
        return ""

    lower = text.lower()

    if _is_raw_path_indicator(text):
        if "../" in lower or ENCODED_TRAVERSAL_TOKEN in lower or "etc/passwd" in lower or "etc/shadow" in lower:
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


def build_deterministic_indicators(analysis_input: AnalysisInput, heuristic_indicators: list) -> list:
    """Builds a deterministic indicator baseline using SOC-style labels.

    Args:
        analysis_input: The input telemetry window.
        heuristic_indicators: Raw indicators from the heuristics engine.

    Returns:
        Deduplicated list of normalized SOC-style indicators.
    """
    indicators = []

    uris_lower = [str(uri).lower() for uri in analysis_input.unique_uris_requested]
    if any("../" in uri or ENCODED_TRAVERSAL_TOKEN in uri or "/etc/passwd" in uri or "/etc/shadow" in uri for uri in uris_lower):
        indicators.append("PATH_TRAVERSAL_PROBE")
    if any(any(token in uri for token in SENSITIVE_URI_TOKENS) for uri in uris_lower):
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
        normalized = normalize_indicator_label(h)
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

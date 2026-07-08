"""Shared normalization for canonical LLM decision fields."""

from __future__ import annotations

from typing import Any

from mcp_servers.log_analysis_server.services.json_utils import extract_json_object

_LLM_DECISION_ALIASES = {
    "score": "threat_score",
    "risk_score": "threat_score",
    "analysis_summary": "reasoning_summary",
    "summary": "reasoning_summary",
    "justification": "reasoning_summary",
    "recommended_action": "recommendation",
    "mitigation": "recommendation",
}

_DEFAULT_REASONING = (
    "Partial LLM output received; reasoning completed using deterministic security heuristics."
)
_DEFAULT_RECOMMENDATION = (
    "Strengthen layered detection controls and harden exposed application attack surfaces."
)


def normalize_llm_decision(
    parsed: dict[str, Any],
    *,
    use_fallback_defaults: bool = False,
) -> dict[str, Any]:
    """Map provider-specific aliases to the 3 canonical LLM decision fields."""
    raw = dict(parsed)
    for source_key, target_key in _LLM_DECISION_ALIASES.items():
        if target_key not in raw and source_key in raw:
            raw[target_key] = raw[source_key]

    empty_reasoning = _DEFAULT_REASONING if use_fallback_defaults else ""
    empty_recommendation = _DEFAULT_RECOMMENDATION if use_fallback_defaults else ""

    return {
        "threat_score": raw.get("threat_score", 0),
        "reasoning_summary": raw.get("reasoning_summary", empty_reasoning),
        "recommendation": raw.get("recommendation", empty_recommendation),
    }


def parse_llm_decision_response(
    response: str,
    *,
    use_fallback_defaults: bool = False,
) -> dict[str, Any]:
    """Extract and normalize a raw LLM response string into decision fields."""
    parsed = extract_json_object(response, strict=True)
    return normalize_llm_decision(parsed, use_fallback_defaults=use_fallback_defaults)


__all__ = [
    "normalize_llm_decision",
    "parse_llm_decision_response",
]

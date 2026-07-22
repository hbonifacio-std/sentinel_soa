"""Main orchestration logic for web activity analysis.

Coordinates heuristic analysis, LLM invocation, and verdict construction.
Supports lightweight dependency injection for testability.
"""

import json
import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol

from mcp_servers.log_analysis_server.models.analysis_input import WebActivityWindowInput as AnalysisInput
from mcp_servers.log_analysis_server.models.analysis_output import ThreatAssessment as AnalysisOutput
from mcp_servers.log_analysis_server.models.rules_bundle import RulesBundle

from mcp_servers.log_analysis_server.services.heuristics_engine import ThreatHeuristics
from mcp_servers.log_analysis_server.store.alert_store import alert_store

from .llm_analyzer import LLMAnalyzer, _extract_llm_decision_fields
from .mitre_mapper import enrich_with_mitre_dictionary, _MITRE_FIELDS
from .indicators import build_deterministic_indicators, normalize_indicator_label, INDICATOR_GENERIC_TOKENS
from .recommendations import generate_recommendation

logger = logging.getLogger(__name__)
_LLM_ANALYSIS_TIMEOUT_S = 900.0


# ============================================================================
# Protocol & Dataclass for Dependency Injection
# ============================================================================

class AlertStoreProtocol(Protocol):
    """Protocol for alert store implementations (in-memory, Redis, Mongo, etc.)."""

    def get_history_by_ip(self, source_ip: str, limit: int = 10) -> List[Any]:
        """Retrieves alert history for an IP (for backward compatibility with InMemoryAlertStore)."""
        ...

    def add_assessment(self, source_ip: str, assessment: AnalysisOutput) -> None:
        """Persists an assessment for temporal context (for backward compatibility with InMemoryAlertStore)."""
        ...


@dataclass
class AnalysisDependencies:
    """Lightweight dependency container for analyze_web_activity.
    
    Allows tests to inject mock implementations without monkeypatching.
    Defaults point to singletons for backward compatibility.
    """

    alert_store: AlertStoreProtocol
    threat_heuristics_class: type = ThreatHeuristics

    @classmethod
    def default(cls) -> "AnalysisDependencies":
        """Returns dependencies with singletons (production default)."""
        return cls(
            alert_store=alert_store,
            threat_heuristics_class=ThreatHeuristics,
        )


# Default instance for the MCP tool entry point
DEFAULT_DEPS = AnalysisDependencies.default()


def _normalize_score(value: Any, default: int) -> int:
    """Normalizes any score-like value to an integer in the range [0, 100]."""
    try:
        score = int(round(float(value)))
    except (TypeError, ValueError):
        return int(max(0, min(100, default)))
    return int(max(0, min(100, score)))


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


def _extract_rules_bundle(arguments: Dict[str, Any]) -> Optional[RulesBundle]:
    """Safely extracts and validates rules bundle from arguments."""
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


async def execute_analyze_web_activity(
    arguments: Dict[str, Any],
    deps: AnalysisDependencies = None,
) -> Dict[str, Any]:
    """Executes heuristic and AI analysis on a suspicious web activity window.

    Args:
        arguments: MCP tool arguments including the WebActivityWindowInput payload.
        deps: Dependency injection container. Defaults to DEFAULT_DEPS (production singletons).

    Returns:
        ThreatAssessment dictionary with threat score, indicators, MITRE mapping, etc.

    Raises:
        ValueError: If the input schema is invalid.
        Exception: On unexpected runtime errors.
    """
    if deps is None:
        deps = DEFAULT_DEPS

    try:
        model_id = arguments.pop("model_id", None)
        provider_override = arguments.pop("provider_override", None)
        
        # Extract metadata that should NOT be sent to LLM analysis
        window_id = arguments.pop("window_id", None)
        source_id = arguments.pop("source_id", None)
        client_id = arguments.pop("client_id", None)
        
        rules_bundle = _extract_rules_bundle(arguments)
        sanitized_arguments = {k: v for k, v in arguments.items() if k != "rules_bundle"}

        # 1. Strict static validation via the Pydantic v2 model
        analysis_input = AnalysisInput(**sanitized_arguments)

        source_ip = analysis_input.source_ip
        logger.info(f"Starting 'analyze_web_activity' tool for IP: {source_ip} (Window: {window_id})")

        # ========================================================================
        # 2. DETERMINISTIC HEURISTIC ANALYSIS (Confidence baseline)
        # ========================================================================
        logger.debug(f"[HEURISTICS] Running deterministic engine for {source_ip}...")
        heuristic_score, heuristic_indicators, heuristic_reasoning = deps.threat_heuristics_class.analyze(
            analysis_input,
            rules_bundle=rules_bundle,
        )
        if rules_bundle is not None:
            logger.info("[HEURISTICS] Using injected rules bundle version=%s", rules_bundle.version_hash)
        logger.info(f"[HEURISTICS] Score: {heuristic_score}/100 | Indicators: {len(heuristic_indicators)}")

        # ========================================================================
        # 3. TEMPORAL CONTEXT ENRICHMENT: history of previous alerts
        # ========================================================================
        threat_history = deps.alert_store.get_history_by_ip(source_ip, limit=10)
        logger.debug(f"Previous alert history for {source_ip}: {len(threat_history)} records")

        # ========================================================================
        # 4. DIRECT DATA SUBMISSION TO LLM PROVIDER (Internal logic delegated)
        # ========================================================================
        
        # Try LLM analysis, fallback to pure heuristics if it fails
        raw_assessment = None
        try:
            # Instantiate the analyzer with the selected model or provider_override
            analyzer = LLMAnalyzer(model_id=model_id, provider_override=provider_override)
            logger.debug(f"Sending telemetry payload from {source_ip} to analyzer.")

            # We delegate telemetry and history directly to LLMAnalyzer
            # so the provider decides how to package it.
            raw_assessment = await asyncio.wait_for(
                analyzer.analyze_with_context(
                    telemetry=analysis_input,
                    history=threat_history
                ),
                timeout=_LLM_ANALYSIS_TIMEOUT_S,
            )
            logger.debug(
                f"LLM response received: {json.dumps(raw_assessment, indent=2, ensure_ascii=False)[:300]}...")
        except asyncio.TimeoutError:
            logger.warning(
                "LLM analysis timed out after %ss for %s. Falling back to heuristics.",
                _LLM_ANALYSIS_TIMEOUT_S,
                source_ip,
            )
            raw_assessment = None
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

        deterministic_indicators = build_deterministic_indicators(analysis_input, heuristic_indicators)
        llm_indicators = raw_assessment.get("indicators_found")
        if not isinstance(llm_indicators, list):
            llm_indicators = [llm_indicators] if llm_indicators else []

        merged_indicators = []
        seen = set()
        for indicator in deterministic_indicators + [normalize_indicator_label(i) for i in llm_indicators]:
            if not indicator:
                continue
            key = indicator.lower()
            if key not in seen:
                merged_indicators.append(indicator)
                seen.add(key)

        if not merged_indicators:
            logger.debug("No valid indicators after merge; using heuristic fallback")
            merged_indicators = deterministic_indicators[:10]

        if merged_indicators and all(ind.lower() in INDICATOR_GENERIC_TOKENS for ind in merged_indicators):
            merged_indicators = deterministic_indicators[:10] or merged_indicators

        raw_assessment["window_id"] = str(window_id) if window_id else "N/A"
        raw_assessment["source_id"] = source_id or "N/A"
        raw_assessment["client_id"] = client_id
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
            raw_assessment["recommendation"] = generate_recommendation(
                raw_assessment["threat_level"], source_ip, merged_indicators
            )

        # Apply deterministic MITRE governance before instantiating the output model
        raw_assessment = enrich_with_mitre_dictionary(raw_assessment)

        # Validation and instantiation of the output model
        analysis_output = AnalysisOutput(**raw_assessment)

        # ========================================================================
        # 6. ASSESSMENT PERSISTENCE (for temporal context)
        # ========================================================================
        deps.alert_store.add_assessment(source_ip, analysis_output)

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

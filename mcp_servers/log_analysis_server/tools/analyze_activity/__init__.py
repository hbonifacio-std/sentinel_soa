"""Web activity analysis package — SRP-decomposed modules for threat assessment.

Provides the main `execute_analyze_web_activity` tool along with specialized
modules for MITRE mapping, indicator normalization, recommendations, and LLM integration.

Maintains backward compatibility with the original import path:
    from mcp_servers.log_analysis_server.tools.analyze_activity import execute_analyze_web_activity
"""

from .orchestrator import (
    execute_analyze_web_activity,
    _normalize_score,
    _derive_threat_level,
    _build_targeted_asset,
    _extract_rules_bundle,
)
from .llm_analyzer import (
    LLMAnalyzer,
    _append_llm_signature,
    _extract_llm_decision_fields,
)
from .llm_analyzer import _llm_signature_suffix  # Private helper for tests
from .mitre_mapper import enrich_with_mitre_dictionary, MITRE_MATRIX, _MITRE_FIELDS
from .indicators import (
    build_deterministic_indicators,
    normalize_indicator_label,
    _clean_indicator_text,
    _is_raw_path_indicator,
)
from .recommendations import generate_recommendation

# For backward compatibility, expose private functions used in tests
_enrich_with_mitre_dictionary = enrich_with_mitre_dictionary
_normalize_indicator_label = normalize_indicator_label

__all__ = [
    # Main execution
    "execute_analyze_web_activity",
    # LLM integration
    "LLMAnalyzer",
    "_append_llm_signature",
    "_extract_llm_decision_fields",
    "_llm_signature_suffix",
    # MITRE mapping
    "enrich_with_mitre_dictionary",
    "MITRE_MATRIX",
    "_enrich_with_mitre_dictionary",  # Backward compat alias
    # Indicators
    "build_deterministic_indicators",
    "normalize_indicator_label",
    "_normalize_indicator_label",  # Backward compat alias
    "_clean_indicator_text",
    "_is_raw_path_indicator",
    # Recommendations
    "generate_recommendation",
    # Orchestration helpers
    "_normalize_score",
    "_derive_threat_level",
    "_build_targeted_asset",
    "_extract_rules_bundle",
]

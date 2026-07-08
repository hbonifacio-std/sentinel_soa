"""MITRE ATT&CK mapping and enrichment for threat assessments.

Handles deterministic mapping of indicators to MITRE framework and applies
mitigation templating based on indicator-driven priority.
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

def get_mitre_matrix() -> Dict[str, Dict[str, Any]]:
    """Load MITRE matrix from config or use default hardcoded version."""
    from mcp_servers.log_analysis_server.config import server_settings
    
    mitre_matrix: Dict[str, Dict[str, Any]] = {
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
    
    # Override with external JSON if configured
    if hasattr(server_settings, 'mitre_matrix_json_path') and server_settings.mitre_matrix_json_path:
        external_matrix = server_settings._load_mitre_matrix_from_json(server_settings.mitre_matrix_json_path)
        if external_matrix:
            mitre_matrix.update(external_matrix)
    
    return mitre_matrix

# MITRE ATT&CK Governance Matrix — determinista y desacoplada del LLM.
# Lazily loaded to support external configuration
MITRE_MATRIX: Dict[str, Dict[str, Any]] = {}

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


def enrich_with_mitre_dictionary(assessment: Dict[str, Any]) -> Dict[str, Any]:
    """Applies deterministic MITRE mapping and mitigation templating with collision priority.

    Args:
        assessment: The threat assessment dictionary to enrich.

    Returns:
        The enriched assessment with MITRE fields and suggested mitigations.
    """
    global MITRE_MATRIX
    
    # Load MITRE matrix on first use (lazy initialization)
    if not MITRE_MATRIX:
        MITRE_MATRIX = get_mitre_matrix()
    
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

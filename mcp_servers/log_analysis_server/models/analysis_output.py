"""Output model definition module for the MCP Agent verdict.

This module contains the strict Pydantic schema that maps the cybersecurity
threat evaluation, aligned with the Cyber Kill Chain model.
"""

from enum import Enum
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class ThreatLevelEnum(str, Enum):
    """Enumeration of severity levels for detected threats."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class KillChainPhaseEnum(str, Enum):
    """Enumeration of Cyber Kill Chain phases applicable to web telemetry."""
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    EXPLOITATION = "Exploitation"
    ACTION_ON_OBJETIVES = "Actions on Objectives"


class SuggestedMitigation(BaseModel):
    action: str = Field(..., description="Type of mitigation action (e.g., 'block_ip', 'rate_limit_user', 'isolate_host')")
    target: str = Field(..., description="The entity to which the action applies (e.g., IP address, username, host ID)")
    reason: str = Field(..., description="Brief explanation for the suggested mitigation")
    severity: Optional[str] = Field("medium", description="Severity of the suggested action (low, medium, high, critical)")
    automation_ready: bool = Field(False, description="Indicates if the action is ready for automated execution by a SOAR platform")


class ThreatAssessment(BaseModel):
    """Pydantic model encapsulating the analysis and indicators dictated by the LLM.
    
    This object represents the source of truth that the MCP tool returns to the
    Core Orchestrator after heuristic processing of the log window.
    """

    window_id: UUID = Field(
        ...,
        description="Universal unique identifier (UUID v4) matching the analyzed window."
    )
    source_id: str = Field(
        ...,
        description="Unique identifier of the server or application that originates the log."
    )
    source_ip: str = Field(
        ...,
        description="Source IP address of the analyzed traffic."
    )
    threat_detected: bool = Field(
        ...,
        description="Boolean flag indicating whether the behavior constitutes an anomaly or attack."
    )
    targeted_asset: str = Field(
        ...,
        description=(
            "Lista consolidada y única de activos, endpoints o componentes bajo amenaza detectados en "
            "la ventana de logs. Se adapta dinámicamente según la capa (ej. URLs para Web, servicios "
            "para OS, o nombres de bases de datos para DB)."
        )
    )
    threat_level: ThreatLevelEnum = Field(
        ...,
        description="Qualitative severity assigned to the observed activity."
    )
    threat_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Numeric risk score from 0 to 100 quantifying the probability of a threat."
    )
    kill_chain_phase: Optional[KillChainPhaseEnum] = Field(
        default=None,
        description="Identified Cyber Kill Chain phase. Null if threat_detected is false."
    )
    # MITRE ATT&CK Framework Alignment
    mitre_tactic: Optional[str] = Field(None, description="MITRE ATT&CK Tactic name (e.g., 'Initial Access')")
    mitre_tactic_id: Optional[str] = Field(None, description="MITRE ATT&CK Tactic ID (e.g., 'TA0001')")
    mitre_technique: Optional[str] = Field(None, description="MITRE ATT&CK Technique name (e.g., 'Exploit Public-Facing Application')")
    mitre_technique_id: Optional[str] = Field(None, description="MITRE ATT&CK Technique ID (e.g., 'T1190')")
    mitre_sub_technique: Optional[str] = Field(None, description="MITRE ATT&CK Sub-Technique name (e.g., 'SQL Injection')")
    mitre_sub_technique_id: Optional[str] = Field(None, description="MITRE ATT&CK Sub-Technique ID (e.g., 'T1190.002')")
    
    indicators_found: List[str] = Field(
        default_factory=list,
        description="Concise list of specific patterns found (e.g., 'SQL Injection detected')."
    )
    reasoning_summary: str = Field(
        ...,
        max_length=5000,
        description="Synthesis of the AI agent's heuristic reasoning in a maximum of 100 words."
    )
    recommendation: str = Field(
        ...,
        description="Explicit, prioritized mitigating action suggested for system administrators."
    )

    # NIST CSF Alignment for Response
    suggested_mitigations: List[SuggestedMitigation] = Field(
        default_factory=list,
        description="Structured list of suggested mitigation actions for automation (SOAR)."
    )

    # Additional fields for human workflow / Orchestration
    reviewed: bool = Field(
        default=False,
        description="Flag indicating whether a human analyst has reviewed the report. Default False."
    )
    actions: List[str] = Field(
        default_factory=list,
        description="List of actions taken or suggested (strings)." 
    )
    resolved: bool = Field(
        default=False,
        description="Flag indicating whether the incident/report was marked as resolved. Default False."
    )

    @field_validator('suggested_mitigations', mode='before')
    @classmethod
    def prevent_null_mitigations(cls, v):
        if v is None:
            return []
        return v
    model_config = {
        "use_enum_values": True,  # Facilitates direct serialization to native JSON strings
        "json_schema_extra": {
            "example": {
                "window_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
                "source_id": "some-server-123",
                "source_ip": "10.0.0.66",
                "threat_detected": True,
                "threat_level": "HIGH",
                "threat_score": 87,
                "kill_chain_phase": "Reconnaissance",
                "mitre_tactic": "Reconnaissance",
                "mitre_tactic_id": "TA0043",
                "mitre_technique": "Active Scanning",
                "mitre_technique_id": "T1595",
                "mitre_sub_technique": "Scanning IP Blocks",
                "mitre_sub_technique_id": "T1595.001",
                "indicators_found": [
                    "Automated User-Agent Nikto-Scanner/2.1 detected",
                    "404 response ratio 88% (8 of 9 requests)",
                    "Systematic request pattern to sensitive paths: /etc/passwd, /admin, /.git/config",
                    "RPS of 0.15 from a single IP within a 60-second window"
                ],
                "reasoning_summary": "IP 10.0.0.66 is executing an active reconnaissance campaign following typical scanning tool patterns (Nikto). Multiple indicators converge: known User-Agent, sensitive URI targets, anomalous error rate. Heuristic confidence 87%.",
                "recommendation": "Level 1: Block IP 10.0.0.66 in the WAF/Perimeter Firewall immediately. Level 2: Audit historical logs from the last 24h to identify correlated patterns. Level 3: Verify that administrative endpoints are protected with authentication and rate-limiting.",
                "suggested_mitigations": [
                    {
                        "action": "block_ip",
                        "target": "10.0.0.66",
                        "reason": "Source of automated scanning activity.",
                        "severity": "high",
                        "automation_ready": True
                    }
                ],
                "reviewed": False,
                "actions": [],
                "resolved": False
            }
        }
    }
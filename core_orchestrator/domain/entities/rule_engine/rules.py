"""
Domain entities for heuristic rules stored in MongoDB and cached in Redis.

Only pure domain types live here as dataclasses. Validation and request/response
shapes live in infrastructure DTOs (Pydantic BaseModel).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from shared.rules_seed import build_bundle_payload_from_rules, build_seed_bundle_payload


RuleType = Literal["keyword_mapping", "pattern_list", "threshold"]
RuleCategory = Literal["user_agent", "uri", "injection", "threshold"]
MatchStrategy = Literal["substring_case_insensitive", "exact", "regex"]
AuditAction = Literal["CREATE", "UPDATE", "DELETE", "ACTIVATE", "ROLLBACK"]


@dataclass
class RulesStatistics:
    total_active_rules: int
    version_hash: str
    cached: bool
    last_updated: Optional[datetime]


@dataclass
class HealthStatus:
    status: str
    cached: bool
    version_hash: str
    last_updated: Optional[datetime]
    source: str

@dataclass
class RuleContent:
    type: RuleType
    data: Dict[str, Any]
    match_strategy: MatchStrategy = "substring_case_insensitive"


@dataclass
class RuleMetadata:
    source: str
    changed_by: str
    change_reason: str
    compatibility_version: str = "1.0.0"


@dataclass
class ValidationRules:
    min_score: int = 0
    max_score: int = 100
    required_fields: List[str] = field(default_factory=lambda: ["rule_id", "category"])


@dataclass
class HeuristicRule:
    rule_id: str
    client_id: Optional[str] = None
    rule_type: RuleType = "keyword_mapping"
    category: RuleCategory = "user_agent"
    version: int = 1
    is_active: bool = True
    description: str = ""
    content: RuleContent = field(default_factory=lambda: RuleContent(type="keyword_mapping", data={}))
    metadata: RuleMetadata = field(default_factory=lambda: RuleMetadata(source="system", changed_by="system", change_reason="init"))
    validation_rules: ValidationRules = field(default_factory=ValidationRules)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class HeuristicRuleUpdate:
    rule_type: Optional[RuleType] = None
    category: Optional[RuleCategory] = None
    version: Optional[int] = None
    is_active: Optional[bool] = None
    description: Optional[str] = None
    content: Optional[RuleContent] = None
    metadata: Optional[RuleMetadata] = None


@dataclass
class RuleVersion:
    version_hash: str
    client_id: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = False
    rules_included: List[str] = field(default_factory=list)
    changelog: str = ""
    deployed_by: str = "system"
    deployment_timestamp: Optional[datetime] = None
    rollback_url: Optional[str] = None


@dataclass
class RuleAuditLog:
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    action: AuditAction = "CREATE"
    rule_id: str = ""
    user: str = "system"
    client_id: Optional[str] = None
    ip_address: str = "127.0.0.1"
    changes: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    status: str = "success"


@dataclass
class RulesBundle:
    """In-memory bundle of active rules for heuristic analysis."""

    malicious_ua_keywords: Dict[str, int] = field(default_factory=dict)
    sensitive_uris: Dict[str, int] = field(default_factory=dict)
    sql_injection_patterns: List[str] = field(default_factory=list)
    path_traversal_patterns: List[str] = field(default_factory=list)
    sql_injection_score: int = 30
    path_traversal_score: int = 40
    version_hash: str = "default"
    last_updated: Optional[datetime] = None

    def to_cache_dict(self) -> Dict[str, Any]:
        return {
            "malicious_ua_keywords": self.malicious_ua_keywords,
            "sensitive_uris": self.sensitive_uris,
            "sql_injection_patterns": self.sql_injection_patterns,
            "path_traversal_patterns": self.path_traversal_patterns,
            "sql_injection_score": self.sql_injection_score,
            "path_traversal_score": self.path_traversal_score,
            "version_hash": self.version_hash,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
        }

    @classmethod
    def from_cache_dict(cls, data: Dict[str, Any]) -> "RulesBundle":
        last_updated = data.get("last_updated")
        parsed_updated: Optional[datetime] = None
        if isinstance(last_updated, str):
            parsed_updated = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
        elif isinstance(last_updated, datetime):
            parsed_updated = last_updated

        return cls(
            malicious_ua_keywords=dict(data.get("malicious_ua_keywords", {})),
            sensitive_uris=dict(data.get("sensitive_uris", {})),
            sql_injection_patterns=list(data.get("sql_injection_patterns", [])),
            path_traversal_patterns=list(data.get("path_traversal_patterns", [])),
            sql_injection_score=int(data.get("sql_injection_score", 30)),
            path_traversal_score=int(data.get("path_traversal_score", 40)),
            version_hash=str(data.get("version_hash", "default")),
            last_updated=parsed_updated,
        )


def hash_version(rules: List[HeuristicRule]) -> str:
    """Deterministic version hash from active rule identities and versions."""
    payload = sorted((r.rule_id, r.version, r.category) for r in rules)
    digest = hashlib.sha256(json.dumps(payload).encode()).hexdigest()
    return f"v1_{digest[:16]}"


def build_default_rules_bundle() -> RulesBundle:
    """Fallback bundle derived from the persisted seed file."""
    return RulesBundle.from_cache_dict(build_seed_bundle_payload())


def rules_to_bundle(rules: List[HeuristicRule], version_hash: str = "default") -> RulesBundle:
    """Build a RulesBundle from a list of HeuristicRule documents."""
    # convert dataclass rule instances into serializable dicts expected by the shared builder
    rules_payload = [asdict(rule) if is_dataclass(rule) else rule for rule in rules]
    bundle_payload = build_bundle_payload_from_rules(rules_payload, version_hash=version_hash)
    return RulesBundle.from_cache_dict(bundle_payload)


@dataclass
class RuleValidationResult:
    """Represents the outcome of a rule validation check."""
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class RuleTestResult:
    """Represents the outcome of executing the known-payload test suite against a rule bundle."""
    passed: bool
    total: int
    passed_count: int
    failures: List[str] = field(default_factory=list)

@dataclass
class RuleMatch:
    """
    Represents a match found by applying detection rules.

    This class holds information about a single match resulting
    from the evaluation of detection rules. It is typically used
    to classify and score a specific detection, providing details
    such as the matched value, associated rule, and evidence
    collected.

    Attributes:
        category: Category of detection, such as user agents, URIs,
            or injections.
        match_value: Exact string or pattern detected that caused
            the match.
        score: Assigned score based on the rule or dictionary
            evaluation.
        evidence: Additional details or context about the match.
    """
    category: RuleCategory        # Ej: "user_agent", "uri", "injection"
    match_value: str     # Exact string or pattern detected (e.g., "sqlmap", "/.env")
    score: int           # Score assigned according to the dictionary/rule
    evidence: str
    mitre: Optional[MitreMapping] = None


    @staticmethod
    def extract_primary_mitre(rule_matches: List[RuleMatch]) -> Optional[MitreMapping]:
        """

        """
        matches_with_mitre = [m for m in rule_matches if m.mitre is not None]
        if not matches_with_mitre:
            return None

        best_match = max(matches_with_mitre, key=lambda m: m.score)
        return best_match.mitre

@dataclass(frozen=True)
class MitreMapping:
    tactic: str
    tactic_id: str
    technique: str
    technique_id: str
    sub_technique: Optional[str] = None
    sub_technique_id: Optional[str] = None

MITRE_CATALOG: Dict[str, MitreMapping] = {

    "user_agent": MitreMapping(
        tactic="Reconnaissance",
        tactic_id="TA0043",
        technique="Active Scanning",
        technique_id="T1595",
        sub_technique="Wordlist Scanning",
        sub_technique_id="T1595.003",
    ),
    "uri": MitreMapping(
        tactic="Reconnaissance",
        tactic_id="TA0043",
        technique="Active Scanning",
        technique_id="T1595",
        sub_technique="Vulnerability Scanning",
        sub_technique_id="T1595.002",
    ),
    "sql_injection": MitreMapping(
        tactic="Initial Access",
        tactic_id="TA0001",
        technique="Exploit Public-Facing Application",
        technique_id="T1190",
    ),
    "path_traversal": MitreMapping(
        tactic="Discovery",
        tactic_id="TA0007",
        technique="File and Directory Discovery",
        technique_id="T1083",
    ),
    "command_injection": MitreMapping(
        tactic="Execution",
        tactic_id="TA0002",
        technique="Command and Scripting Interpreter",
        technique_id="T1059",
        sub_technique="Unix Shell",
        sub_technique_id="T1059.004",
    ),
    "xss": MitreMapping(
        tactic="Initial Access",
        tactic_id="TA0001",
        technique="Exploit Public-Facing Application",
        technique_id="T1190",
    ),
    "ssrf": MitreMapping(
        tactic="Initial Access",
        tactic_id="TA0001",
        technique="Exploit Public-Facing Application",
        technique_id="T1190",
    ),
    "brute_force": MitreMapping(
        tactic="Credential Access",
        tactic_id="TA0006",
        technique="Brute Force",
        technique_id="T1110",
        sub_technique="Password Guessing",
        sub_technique_id="T1110.001",
    ),
    "dos": MitreMapping(
        tactic="Impact",
        tactic_id="TA0040",
        technique="Endpoint Denial of Service",
        technique_id="T1499",
        sub_technique="Application Exhaustion",
        sub_technique_id="T1499.003",
    ),
}
# Mapeo de Tácticas de MITRE a Fases del Cyber Kill Chain de Lockheed Martin
TACTIC_TO_KILL_CHAIN: Dict[str, str] = {
    "Reconnaissance": "Reconnaissance",
    "Resource Development": "Weaponization",
    "Initial Access": "Delivery",
    "Execution": "Exploitation",
    "Persistence": "Installation",
    "Privilege Escalation": "Privilege Escalation",
    "Defense Evasion": "Exploitation",
    "Credential Access": "Credential Access",
    "Discovery": "Reconnaissance",
    "Lateral Movement": "Lateral Movement",
    "Collection": "Actions on Objectives",
    "Command and Control": "Command & Control",
    "Exfiltration": "Actions on Objectives",
    "Impact": "Actions on Objectives",
}
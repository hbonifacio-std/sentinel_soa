"""
Pydantic models for heuristic rules stored in MongoDB and cached in Redis.

Defines the schema for rule documents, version bundles, and the in-memory
RulesBundle consumed by ThreatHeuristics during analysis.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import AliasChoices, BaseModel, Field, field_validator, model_validator

from shared.rules_seed import build_bundle_payload_from_rules, build_seed_bundle_payload


RuleType = Literal["keyword_mapping", "pattern_list", "threshold"]
RuleCategory = Literal["user_agent", "uri", "injection", "threshold"]
MatchStrategy = Literal["substring_case_insensitive", "exact", "regex"]
AuditAction = Literal["CREATE", "UPDATE", "DELETE", "ACTIVATE", "ROLLBACK"]


class RuleContent(BaseModel):
    type: RuleType
    data: Dict[str, Any]
    match_strategy: MatchStrategy = "substring_case_insensitive"

    @model_validator(mode="after")
    def validate_content_shape(self) -> "RuleContent":
        if self.type == "keyword_mapping":
            for key, score in self.data.items():
                if not isinstance(score, (int, float)):
                    raise ValueError(f"Keyword '{key}' score must be numeric")
                if not 0 <= int(score) <= 100:
                    raise ValueError(f"Keyword '{key}' score must be between 0 and 100")
        elif self.type == "pattern_list":
            patterns = self.data.get("patterns")
            if not isinstance(patterns, list) or not patterns:
                raise ValueError("pattern_list requires a non-empty 'patterns' list in data")
            score = self.data.get("score_per_match", 30)
            if not 0 <= int(score) <= 100:
                raise ValueError("score_per_match must be between 0 and 100")
        return self


class RuleMetadata(BaseModel):
    source: str
    changed_by: str
    change_reason: str
    compatibility_version: str = "1.0.0"


class ValidationRules(BaseModel):
    min_score: int = 0
    max_score: int = 100
    required_fields: List[str] = Field(default_factory=lambda: ["rule_id", "category"])


class HeuristicRule(BaseModel):
    rule_id: str
    client_id: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("client_id", "tenant_id"),
        serialization_alias="client_id",
        description="Client ID for tenant-specific rules (None for global rules)",
    )
    rule_type: RuleType
    category: RuleCategory
    version: int = Field(ge=1)
    is_active: bool = True
    description: str
    content: RuleContent
    metadata: RuleMetadata
    validation_rules: ValidationRules = Field(default_factory=ValidationRules)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("rule_id")
    @classmethod
    def rule_id_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("rule_id cannot be empty")
        return v.strip()


class HeuristicRuleUpdate(BaseModel):
    """Partial update payload for PATCH /rules/{rule_id}."""

    rule_type: Optional[RuleType] = None
    category: Optional[RuleCategory] = None
    version: Optional[int] = Field(default=None, ge=1)
    is_active: Optional[bool] = None
    description: Optional[str] = None
    content: Optional[RuleContent] = None
    metadata: Optional[RuleMetadata] = None


class RuleVersion(BaseModel):
    version_hash: str
    client_id: Optional[str] = Field(default=None, description="Client ID this version belongs to (None for global)")
    created_at: datetime
    is_active: bool = False
    rules_included: List[str]
    changelog: str = ""
    deployed_by: str = "system"
    deployment_timestamp: Optional[datetime] = None
    rollback_url: Optional[str] = None


class RuleAuditLog(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    action: AuditAction
    rule_id: str
    user: str
    ip_address: str = "127.0.0.1"
    changes: Dict[str, Any] = Field(default_factory=dict)
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
    bundle_payload = build_bundle_payload_from_rules(
        [rule.model_dump(mode="json") for rule in rules],
        version_hash=version_hash,
    )
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

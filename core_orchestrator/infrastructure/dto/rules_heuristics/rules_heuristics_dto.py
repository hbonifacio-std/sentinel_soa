from __future__ import annotations

from typing import Any, Dict, List, Optional, Literal
from datetime import datetime

from pydantic import BaseModel, Field

# --- DTOs used by the API for rules endpoints ---

RuleType = Literal["keyword_mapping", "pattern_list", "threshold"]
RuleCategory = Literal["user_agent", "uri", "injection", "threshold"]
MatchStrategy = Literal["substring_case_insensitive", "exact", "regex"]
AuditAction = Literal["CREATE", "UPDATE", "DELETE", "ACTIVATE", "ROLLBACK"]


class RuleContentDTO(BaseModel):
    type: RuleType
    data: Dict[str, Any]
    match_strategy: MatchStrategy = "substring_case_insensitive"


class RuleMetadataDTO(BaseModel):
    source: str
    changed_by: str
    change_reason: str
    compatibility_version: str = "1.0.0"


class ValidationRulesDTO(BaseModel):
    min_score: int = 0
    max_score: int = 100
    required_fields: List[str] = Field(default_factory=lambda: ["rule_id", "category"])


class RuleCreateDTO(BaseModel):
    rule_id: str
    client_id: Optional[str] = None
    rule_type: RuleType
    category: RuleCategory
    version: int = 1
    is_active: bool = True
    description: str
    content: RuleContentDTO
    metadata: RuleMetadataDTO
    validation_rules: Optional[ValidationRulesDTO] = None


class RuleResponseDTO(BaseModel):
    rule_id: str
    client_id: Optional[str] = None
    rule_type: RuleType
    category: RuleCategory
    version: int
    is_active: bool
    description: str
    content: RuleContentDTO
    metadata: RuleMetadataDTO
    validation_rules: ValidationRulesDTO
    created_at: datetime
    updated_at: datetime


class RuleUpdateDTO(BaseModel):
    rule_type: Optional[RuleType] = None
    category: Optional[RuleCategory] = None
    version: Optional[int] = None
    is_active: Optional[bool] = None
    description: Optional[str] = None
    content: Optional[RuleContentDTO] = None
    metadata: Optional[RuleMetadataDTO] = None


class RuleVersionDTO(BaseModel):
    version_hash: str
    client_id: Optional[str] = None
    created_at: datetime
    is_active: bool = False
    rules_included: List[str]
    changelog: str = ""
    deployed_by: str = "system"
    deployment_timestamp: Optional[datetime] = None
    rollback_url: Optional[str] = None


class RulesBundleDTO(BaseModel):
    malicious_ua_keywords: Dict[str, int]
    sensitive_uris: Dict[str, int]
    sql_injection_patterns: List[str]
    path_traversal_patterns: List[str]
    sql_injection_score: int
    path_traversal_score: int
    version_hash: str
    last_updated: Optional[datetime] = None


class RulesListResponseDTO(BaseModel):
    rules: List[RuleResponseDTO]
    version_hash: str
    total: int


class RuleCreateResponseDTO(BaseModel):
    rule_id: str
    message: str
    version_hash: str
    created_at: datetime


class RuleUpdateResponseDTO(BaseModel):
    message: str
    rule_id: str
    updated_at: datetime


class RuleDeleteResponseDTO(BaseModel):
    message: str
    rule_id: str


class ValidateRulesRequestDTO(BaseModel):
    rules: List[RuleCreateDTO]


class ValidateRulesResponseDTO(BaseModel):
    valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    tests_passed: Optional[int] = None
    tests_total: Optional[int] = None


class ActivateVersionResponseDTO(BaseModel):
    message: str
    active_version: str
    deployed_at: datetime
    rules_included: List[str]


class RulesHealthResponseDTO(BaseModel):
    status: str
    cached: bool
    version_hash: str
    last_updated: Optional[datetime] = None
    source: str
    total_active_rules: int


class CreateVersionRequestDTO(BaseModel):
    rules_included: List[str]
    changelog: str = ""
    deployed_by: str = "admin"

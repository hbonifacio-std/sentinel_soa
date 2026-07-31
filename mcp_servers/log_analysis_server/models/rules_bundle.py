"""
In-memory rules bundle for heuristic analysis (MCP server side).

Mirrors core_orchestrator.entities.rule_schema.RulesBundle so the MCP
process can consume injected rules without importing core_orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class RulesBundle:
    malicious_ua_keywords: Dict[str, int] = field(default_factory=dict)
    sensitive_uris: Dict[str, int] = field(default_factory=dict)
    sql_injection_patterns: List[str] = field(default_factory=list)
    path_traversal_patterns: List[str] = field(default_factory=list)
    sql_injection_score: int = 30
    path_traversal_score: int = 40
    version_hash: str = "default"
    last_updated: Optional[datetime] = None

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

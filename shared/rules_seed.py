from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_RULES_SEED_PATH = ROOT_DIR / "data" / "mongodb" / "heuristic_rules.json"


def load_rules_seed_payload(path: Optional[Path] = None) -> Dict[str, Any]:
    seed_path = Path(path) if path else DEFAULT_RULES_SEED_PATH
    with seed_path.open(encoding="utf-8") as seed_file:
        return json.load(seed_file)


def get_active_seed_rules(payload: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    seed = payload or load_rules_seed_payload()
    return [rule for rule in seed.get("heuristic_rules", []) if rule.get("is_active", True)]


def get_seed_version_hash(payload: Optional[Dict[str, Any]] = None) -> str:
    seed = payload or load_rules_seed_payload()
    active_version = next(
        (version for version in seed.get("rule_versions", []) if version.get("is_active")),
        None,
    )
    if active_version and active_version.get("version_hash"):
        return str(active_version["version_hash"])
    return "default"


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value.strip():
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return None


def _resolve_pattern_kind(rule: Dict[str, Any]) -> str:
    content = rule.get("content", {})
    data = content.get("data", {}) if isinstance(content, dict) else {}
    explicit_kind = str(data.get("pattern_kind", "")).strip().lower()
    if explicit_kind in {"sql_injection", "path_traversal"}:
        return explicit_kind

    lookup_text = " ".join(
        [
            str(rule.get("rule_id", "")).lower(),
            str(rule.get("description", "")).lower(),
        ]
    )
    if "sql" in lookup_text and "injection" in lookup_text:
        return "sql_injection"
    if "path" in lookup_text and "traversal" in lookup_text:
        return "path_traversal"
    if "traversal" in lookup_text:
        return "path_traversal"
    return ""


def build_bundle_payload_from_rules(
    rules: Iterable[Dict[str, Any]],
    version_hash: str = "default",
    last_updated: Optional[str] = None,
) -> Dict[str, Any]:
    bundle: Dict[str, Any] = {
        "malicious_ua_keywords": {},
        "sensitive_uris": {},
        "sql_injection_patterns": [],
        "path_traversal_patterns": [],
        "sql_injection_score": 30,
        "path_traversal_score": 40,
        "version_hash": version_hash,
        "last_updated": last_updated,
    }
    timestamps: List[datetime] = []

    for rule in rules:
        if not rule.get("is_active", True):
            continue

        created_at = _parse_timestamp(rule.get("updated_at")) or _parse_timestamp(rule.get("created_at"))
        if created_at:
            timestamps.append(created_at)

        content = rule.get("content", {})
        data = content.get("data", {}) if isinstance(content, dict) else {}
        rule_type = str(rule.get("rule_type", "")).lower()
        category = str(rule.get("category", "")).lower()

        if rule_type == "keyword_mapping" and category == "user_agent":
            bundle["malicious_ua_keywords"].update({k: int(v) for k, v in data.items()})
            continue

        if rule_type == "keyword_mapping" and category == "uri":
            bundle["sensitive_uris"].update({k: int(v) for k, v in data.items()})
            continue

        if rule_type == "pattern_list":
            pattern_kind = _resolve_pattern_kind(rule)
            patterns = [str(pattern) for pattern in data.get("patterns", [])]
            score_per_match = int(data.get("score_per_match", 30))
            if pattern_kind == "sql_injection":
                bundle["sql_injection_patterns"] = patterns
                bundle["sql_injection_score"] = score_per_match
            elif pattern_kind == "path_traversal":
                bundle["path_traversal_patterns"] = patterns
                bundle["path_traversal_score"] = score_per_match

    if bundle["last_updated"] is None:
        resolved_timestamp = max(timestamps) if timestamps else datetime.now(timezone.utc)
        bundle["last_updated"] = resolved_timestamp.isoformat()

    return bundle


def build_seed_bundle_payload(path: Optional[Path] = None) -> Dict[str, Any]:
    payload = load_rules_seed_payload(path)
    return build_bundle_payload_from_rules(
        get_active_seed_rules(payload),
        version_hash=get_seed_version_hash(payload),
    )


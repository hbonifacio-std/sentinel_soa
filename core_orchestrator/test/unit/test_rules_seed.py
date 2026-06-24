"""Unit tests for shared rules seed helpers."""

from __future__ import annotations

from datetime import datetime

from shared.rules_seed import (
    build_bundle_payload_from_rules,
    get_active_seed_rules,
    get_seed_version_hash,
    load_rules_seed_payload,
)


def test_load_rules_seed_payload_contains_expected_sections():
    payload = load_rules_seed_payload()

    assert "heuristic_rules" in payload
    assert "rule_versions" in payload
    assert "rule_audit_log" in payload


def test_get_active_seed_rules_filters_inactive():
    payload = {
        "heuristic_rules": [
            {"rule_id": "r1", "is_active": True},
            {"rule_id": "r2", "is_active": False},
            {"rule_id": "r3"},
        ]
    }

    active = get_active_seed_rules(payload)

    assert [rule["rule_id"] for rule in active] == ["r1", "r3"]


def test_get_seed_version_hash_returns_default_when_no_active_version():
    payload = {
        "rule_versions": [
            {"version_hash": "v_old", "is_active": False},
            {"version_hash": "v_old2", "is_active": False},
        ]
    }

    assert get_seed_version_hash(payload) == "default"


def test_build_bundle_payload_from_rules_maps_keyword_and_patterns_by_kind():
    rules = [
        {
            "rule_id": "ua_rule",
            "rule_type": "keyword_mapping",
            "category": "user_agent",
            "is_active": True,
            "updated_at": "2026-06-24T10:00:00Z",
            "content": {
                "data": {"nikto": 30},
            },
        },
        {
            "rule_id": "uri_rule",
            "rule_type": "keyword_mapping",
            "category": "uri",
            "is_active": True,
            "updated_at": "2026-06-24T10:05:00Z",
            "content": {
                "data": {"/.env": 40},
            },
        },
        {
            "rule_id": "sql_rule",
            "rule_type": "pattern_list",
            "category": "injection",
            "is_active": True,
            "updated_at": "2026-06-24T10:10:00Z",
            "content": {
                "data": {
                    "patterns": ["UNION SELECT"],
                    "pattern_kind": "sql_injection",
                    "score_per_match": 35,
                }
            },
        },
        {
            "rule_id": "trav_rule",
            "rule_type": "pattern_list",
            "category": "injection",
            "is_active": True,
            "updated_at": "2026-06-24T10:15:00Z",
            "description": "Path traversal detector",
            "content": {
                "data": {
                    "patterns": ["../"],
                    "score_per_match": 45,
                }
            },
        },
        {
            "rule_id": "inactive_rule",
            "rule_type": "keyword_mapping",
            "category": "user_agent",
            "is_active": False,
            "content": {"data": {"should_not_exist": 99}},
        },
    ]

    bundle = build_bundle_payload_from_rules(rules, version_hash="v_unit")

    assert bundle["version_hash"] == "v_unit"
    assert bundle["malicious_ua_keywords"]["nikto"] == 30
    assert bundle["sensitive_uris"]["/.env"] == 40
    assert bundle["sql_injection_patterns"] == ["UNION SELECT"]
    assert bundle["sql_injection_score"] == 35
    assert bundle["path_traversal_patterns"] == ["../"]
    assert bundle["path_traversal_score"] == 45
    assert "should_not_exist" not in bundle["malicious_ua_keywords"]


def test_build_bundle_payload_from_rules_sets_last_updated_when_missing_input():
    bundle = build_bundle_payload_from_rules(
        [
            {
                "rule_id": "minimal",
                "rule_type": "keyword_mapping",
                "category": "user_agent",
                "is_active": True,
                "content": {"data": {"scanner": 10}},
            }
        ],
        version_hash="v_last_updated",
    )

    assert isinstance(bundle["last_updated"], str)
    parsed = datetime.fromisoformat(bundle["last_updated"])
    assert parsed.tzinfo is not None



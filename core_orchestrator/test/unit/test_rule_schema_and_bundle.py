"""Unit tests for rule schema hashing and rules bundle transformations."""

from __future__ import annotations

from datetime import datetime, timezone

from core_orchestrator.models.rule_schema import (
    RulesBundle,
    build_default_rules_bundle,
    hash_version,
    rules_to_bundle,
)
from shared.rules_seed import build_seed_bundle_payload


def test_hash_version_is_stable_for_same_rules(seed_rules):
    assert hash_version(seed_rules) == hash_version(seed_rules)


def test_hash_version_changes_with_rule_identity_or_version(seed_rules):
    original = hash_version(seed_rules)

    mutated = [rule.model_copy(deep=True) for rule in seed_rules]
    mutated[0] = mutated[0].model_copy(update={"version": mutated[0].version + 1})

    assert hash_version(mutated) != original


def test_hash_version_does_not_change_with_metadata_only(seed_rules):
    original = hash_version(seed_rules)

    mutated = [rule.model_copy(deep=True) for rule in seed_rules]
    changed = mutated[0].model_copy(
        update={
            "metadata": mutated[0].metadata.model_copy(
                update={"change_reason": "Metadata-only change"}
            )
        }
    )
    mutated[0] = changed

    assert hash_version(mutated) == original


def test_rules_to_bundle_skips_inactive_rules(seed_rules):
    rules = [rule.model_copy(deep=True) for rule in seed_rules]
    rules[0] = rules[0].model_copy(update={"is_active": False})

    bundle = rules_to_bundle(rules, version_hash="inactive_test")

    assert "nikto" not in bundle.malicious_ua_keywords
    assert bundle.version_hash == "inactive_test"


def test_rules_bundle_from_cache_dict_parses_last_updated_iso_z():
    bundle = RulesBundle.from_cache_dict(
        {
            "malicious_ua_keywords": {"scanner": 20},
            "sensitive_uris": {},
            "sql_injection_patterns": [],
            "path_traversal_patterns": [],
            "version_hash": "v_test",
            "last_updated": "2026-06-24T12:00:00Z",
        }
    )

    assert bundle.version_hash == "v_test"
    assert bundle.last_updated is not None
    assert bundle.last_updated.tzinfo is not None


def test_build_default_rules_bundle_matches_seed_payload_summary():
    default_bundle = build_default_rules_bundle()
    seed_payload = build_seed_bundle_payload()

    assert len(default_bundle.malicious_ua_keywords) == len(seed_payload["malicious_ua_keywords"])
    assert len(default_bundle.sensitive_uris) == len(seed_payload["sensitive_uris"])
    assert len(default_bundle.sql_injection_patterns) == len(seed_payload["sql_injection_patterns"])
    assert len(default_bundle.path_traversal_patterns) == len(seed_payload["path_traversal_patterns"])


def test_rules_bundle_to_cache_dict_roundtrip_preserves_datetime(seed_rules):
    bundle = rules_to_bundle(seed_rules, version_hash="roundtrip_v1")
    bundle.last_updated = datetime.now(timezone.utc)

    restored = RulesBundle.from_cache_dict(bundle.to_cache_dict())

    assert restored.version_hash == "roundtrip_v1"
    assert restored.last_updated == bundle.last_updated



"""Unit tests for RuleValidator."""

from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from core_orchestrator.models.rule_schema import HeuristicRule, RuleContent, RuleMetadata
from core_orchestrator.services.rule_validator import RuleValidator
from core_orchestrator.test.conftest import load_seed_rules


def _make_rule(**overrides) -> HeuristicRule:
    base = load_seed_rules()[0].model_dump()
    base.update(overrides)
    return HeuristicRule(**base)


def test_validate_rule_accepts_valid_seed_rules(seed_rules):
    for rule in seed_rules:
        result = RuleValidator.validate_rule(rule)
        assert result.valid, result.errors


def test_validate_rule_rejects_score_out_of_range():
    with pytest.raises(ValidationError):
        HeuristicRule(
            **_make_rule(
                content={
                    "type": "keyword_mapping",
                    "data": {"evil": 150},
                    "match_strategy": "substring_case_insensitive",
                }
            ).model_dump()
        )


def test_validate_rule_rejects_duplicate_rule_id():
    rule = _make_rule(rule_id="dup_test")
    result = RuleValidator.validate_rule(rule, existing_rule_ids=["dup_test"])
    assert not result.valid
    assert any("Duplicate" in e for e in result.errors)


def test_validate_rule_rejects_mismatched_content_type():
    rule = _make_rule(rule_type="pattern_list")
    result = RuleValidator.validate_rule(rule)
    assert not result.valid


def test_validate_rule_rejects_empty_pattern_list():
    with pytest.raises(ValidationError):
        HeuristicRule(
            **_make_rule(
                rule_id="empty_patterns",
                rule_type="pattern_list",
                category="injection",
                content={
                    "type": "pattern_list",
                    "data": {"patterns": [], "score_per_match": 30},
                    "match_strategy": "substring_case_insensitive",
                },
            ).model_dump()
        )


def test_validate_rule_rejects_invalid_regex():
    rule = _make_rule(
        rule_id="bad_regex",
        rule_type="pattern_list",
        category="injection",
        content={
            "type": "pattern_list",
            "data": {"patterns": ["[invalid"], "score_per_match": 30},
            "match_strategy": "regex",
        },
    )
    result = RuleValidator.validate_rule(rule)
    assert not result.valid
    assert result.errors


def test_validate_rule_bundle_accepts_full_seed(seed_rules):
    result = RuleValidator.validate_rule_bundle(seed_rules)
    assert result.valid


def test_validate_rule_bundle_rejects_no_active_rules(seed_rules):
    inactive = [r.model_copy(update={"is_active": False}) for r in seed_rules]
    result = RuleValidator.validate_rule_bundle(inactive)
    assert not result.valid


def test_test_rules_with_patterns_passes_seed(seed_rules):
    result = RuleValidator.test_rules_with_patterns(seed_rules)
    assert result.passed
    assert result.passed_count == result.total == 4


def test_validate_rules_full_pipeline(seed_rules):
    result = RuleValidator.validate_rules(seed_rules)
    assert result.valid
    assert result.errors == []


def test_pattern_list_detects_sql_injection(seed_rules):
    bundle_rules = copy.deepcopy(seed_rules)
    result = RuleValidator.test_rules_with_patterns(bundle_rules)
    assert result.passed

    sql_rule = next(r for r in bundle_rules if r.rule_id.startswith("sql_injection"))
    sql_rule.content.data["patterns"] = ["totally_unique_pattern_xyz"]
    result = RuleValidator.test_rules_with_patterns(bundle_rules)
    assert not result.passed
    assert result.failures


def test_hash_version_is_deterministic(seed_rules):
    from core_orchestrator.models.rule_schema import hash_version

    assert hash_version(seed_rules) == hash_version(seed_rules)


def test_rule_content_keyword_mapping_requires_numeric_scores():
    with pytest.raises(ValidationError):
        RuleContent(type="keyword_mapping", data={"bad": "not_a_number"}, match_strategy="exact")

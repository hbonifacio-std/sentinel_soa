"""
Validation service for heuristic rules before persistence or activation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

from core_orchestrator.models.rule_schema import HeuristicRule, RulesBundle, rules_to_bundle


@dataclass
class ValidationResult:
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class TestResult:
    passed: bool
    total: int
    passed_count: int
    failures: List[str] = field(default_factory=list)


# Known test payloads used before activating a version
_TEST_CASES: List[Dict[str, Any]] = [
    {
        "name": "nikto_user_agent",
        "user_agent": "Nikto-Scanner/2.1",
        "uri": "/",
        "expect_match": "user_agent",
    },
    {
        "name": "sql_injection_uri",
        "user_agent": "Mozilla/5.0",
        "uri": "/search?q=' OR 1=1--",
        "expect_match": "sql_injection",
    },
    {
        "name": "path_traversal_uri",
        "user_agent": "Mozilla/5.0",
        "uri": "/files?path=../../etc/passwd",
        "expect_match": "path_traversal",
    },
    {
        "name": "sensitive_uri",
        "user_agent": "Mozilla/5.0",
        "uri": "/.env",
        "expect_match": "sensitive_uri",
    },
]


class RuleValidator:
    @staticmethod
    def validate_rule(rule: HeuristicRule, existing_rule_ids: List[str] | None = None) -> ValidationResult:
        errors: List[str] = []
        warnings: List[str] = []

        if existing_rule_ids and rule.rule_id in existing_rule_ids:
            errors.append(f"Duplicate rule_id: {rule.rule_id}")

        if rule.rule_type != rule.content.type:
            errors.append(
                f"rule_type '{rule.rule_type}' does not match content.type '{rule.content.type}'"
            )

        if rule.rule_type == "keyword_mapping":
            if not rule.content.data:
                errors.append("keyword_mapping requires at least one entry in content.data")
            keywords = list(rule.content.data.keys())
            if len(keywords) != len(set(keywords)):
                errors.append("Duplicate keywords detected in content.data")

        if rule.content.match_strategy == "regex":
            if rule.rule_type == "pattern_list":
                for pattern in rule.content.data.get("patterns", []):
                    try:
                        re.compile(str(pattern))
                    except re.error as exc:
                        errors.append(f"Invalid regex pattern '{pattern}': {exc}")
            elif rule.rule_type == "keyword_mapping":
                for keyword in rule.content.data:
                    try:
                        re.compile(str(keyword))
                    except re.error as exc:
                        errors.append(f"Invalid regex keyword '{keyword}': {exc}")

        for keyword in rule.content.data.keys() if rule.rule_type == "keyword_mapping" else []:
            if len(str(keyword)) > 256:
                warnings.append(f"Keyword '{keyword[:32]}...' exceeds 256 characters")

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)

    @staticmethod
    def validate_rule_bundle(rules: List[HeuristicRule]) -> ValidationResult:
        errors: List[str] = []
        warnings: List[str] = []
        seen_ids: set[str] = set()
        categories: Dict[str, str] = {}

        for rule in rules:
            result = RuleValidator.validate_rule(rule, list(seen_ids))
            errors.extend(result.errors)
            warnings.extend(result.warnings)
            seen_ids.add(rule.rule_id)

            if rule.category in categories and rule.rule_type == "keyword_mapping":
                if categories[rule.category] != rule.rule_id:
                    warnings.append(
                        f"Multiple keyword_mapping rules for category '{rule.category}'"
                    )
            categories[rule.category] = rule.rule_id

        active = [r for r in rules if r.is_active]
        if not active:
            errors.append("Bundle must contain at least one active rule")

        required_categories = {"user_agent", "uri", "injection"}
        present = {r.category for r in active}
        missing = required_categories - present
        if missing:
            warnings.append(f"Bundle missing categories: {', '.join(sorted(missing))}")

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)

    @staticmethod
    def test_rules_with_patterns(rules: List[HeuristicRule]) -> TestResult:
        bundle = rules_to_bundle(rules, version_hash="test")
        failures: List[str] = []
        passed_count = 0

        for case in _TEST_CASES:
            ua = case["user_agent"].lower()
            uri = case["uri"].lower()
            matched = False

            if case["expect_match"] == "user_agent":
                matched = any(kw in ua for kw in bundle.malicious_ua_keywords)
            elif case["expect_match"] == "sql_injection":
                matched = any(p.lower() in uri for p in bundle.sql_injection_patterns)
            elif case["expect_match"] == "path_traversal":
                matched = any(p.lower() in uri for p in bundle.path_traversal_patterns)
            elif case["expect_match"] == "sensitive_uri":
                matched = any(path in uri for path in bundle.sensitive_uris)

            if matched:
                passed_count += 1
            else:
                failures.append(f"Test '{case['name']}' did not match expected pattern")

        total = len(_TEST_CASES)
        return TestResult(
            passed=passed_count == total,
            total=total,
            passed_count=passed_count,
            failures=failures,
        )

    @staticmethod
    def validate_rules(rules: List[HeuristicRule]) -> ValidationResult:
        """Full validation: schema + bundle compatibility + pattern tests."""
        bundle_result = RuleValidator.validate_rule_bundle(rules)
        if not bundle_result.valid:
            return bundle_result

        test_result = RuleValidator.test_rules_with_patterns(rules)
        if not test_result.passed:
            return ValidationResult(
                valid=False,
                errors=[f"Pattern test failed: {f}" for f in test_result.failures],
                warnings=bundle_result.warnings,
            )

        return ValidationResult(
            valid=True,
            errors=[],
            warnings=bundle_result.warnings,
        )

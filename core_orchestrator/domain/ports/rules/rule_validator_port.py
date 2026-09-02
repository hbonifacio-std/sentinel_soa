# core_orchestrator/domain/ports/rule_validator_port.py
from abc import ABC, abstractmethod
from typing import List, Optional

from core_orchestrator.domain.entities.rule_engine.rules import (
    HeuristicRule,
    RuleTestResult,
    RuleValidationResult,
)


class RuleValidatorPort(ABC):
    """
    Port for rule validation logic.

    Pure domain contract: no FastAPI, persistence, or framework imports.
    Adapters (e.g. DefaultRuleValidator) implement this interface and are
    injected into services/endpoints through dependency inversion.
    """

    @abstractmethod
    def validate_rule(
        self,
        rule: HeuristicRule,
        existing_rule_ids: Optional[List[str]] = None,
    ) -> RuleValidationResult:
        """Validates a single heuristic rule (schema + semantic checks)."""
        raise NotImplementedError

    @abstractmethod
    def validate_rule_bundle(self, rules: List[HeuristicRule]) -> RuleValidationResult:
        """Validates a collection of rules as a coherent bundle."""
        raise NotImplementedError

    @abstractmethod
    def test_rules_with_patterns(self, rules: List[HeuristicRule]) -> RuleTestResult:
        """Runs the known-payload test suite against the rule bundle."""
        raise NotImplementedError

    @abstractmethod
    def validate_rules(self, rules: List[HeuristicRule]) -> RuleValidationResult:
        """Full validation: schema + bundle compatibility + pattern tests."""
        raise NotImplementedError

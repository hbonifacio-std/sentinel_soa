from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from core_orchestrator.domain.entities.rule_engine.rules import HeuristicRule, RuleVersion

class RuleRepositoryPort(ABC):
    @abstractmethod
    async def get_by_id(self, rule_id: str, client_id: Optional[str]) -> Optional[HeuristicRule]:
        raise NotImplementedError

    @abstractmethod
    async def get_all(self, include_inactive: bool = False, client_id: Optional[str] = None) -> List[HeuristicRule]:
        raise NotImplementedError

    @abstractmethod
    async def get_by_ids(self, rule_ids: List[str], client_id: Optional[str]) -> List[HeuristicRule]:
        raise NotImplementedError

    @abstractmethod
    async def get_rules_by_client(self, client_id: Optional[str], include_inactive: bool = False) -> List[HeuristicRule]:
        """Fetch rules for a specific client (or global rules if client_id is None)."""
        raise NotImplementedError

    @abstractmethod
    async def rule_exists(self, rule_id: str, client_id: Optional[str]) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def rule_exists_any(self, rule_id: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def update_rule(self, rule_id: str, client_id: Optional[str], updates: Dict[str, Any]) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def create_rule(self, rule: HeuristicRule) -> HeuristicRule:
        raise NotImplementedError

    @abstractmethod
    async def delete_rule(self, rule_id: str, client_id: Optional[str]) -> bool:
        raise NotImplementedError

    # Versioning methods
    @abstractmethod
    async def create_version(self, version: RuleVersion) -> RuleVersion:
        raise NotImplementedError

    @abstractmethod
    async def get_version(self, version_hash: str, client_id: Optional[str]) -> Optional[RuleVersion]:
        raise NotImplementedError

    @abstractmethod
    async def get_active_version(self, client_id: Optional[str]) -> Optional[RuleVersion]:
        raise NotImplementedError

    @abstractmethod
    async def list_versions(self, client_id: Optional[str], limit: int = 50) -> List[RuleVersion]:
        raise NotImplementedError

    @abstractmethod
    async def activate_version(self, version_hash: str, client_id: Optional[str]) -> bool:
        raise NotImplementedError

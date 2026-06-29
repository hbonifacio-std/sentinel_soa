from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from core_orchestrator.domain.models.rules import HeuristicRule, RuleVersion

class RuleRepository(ABC):
    @abstractmethod
    async def get_by_id(self, rule_id: str) -> Optional[HeuristicRule]:
        raise NotImplementedError

    @abstractmethod
    async def get_all(self, include_inactive: bool = False) -> List[HeuristicRule]:
        raise NotImplementedError

    @abstractmethod
    async def get_by_ids(self, rule_ids: List[str]) -> List[HeuristicRule]:
        raise NotImplementedError

    @abstractmethod
    async def rule_exists(self, rule_id: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def create_rule(self, rule: HeuristicRule) -> HeuristicRule:
        raise NotImplementedError

    @abstractmethod
    async def delete_rule(self, rule_id: str) -> bool:
        raise NotImplementedError

    # Versioning methods
    @abstractmethod
    async def create_version(self, version: RuleVersion) -> RuleVersion:
        raise NotImplementedError

    @abstractmethod
    async def get_version(self, version_hash: str) -> Optional[RuleVersion]:
        raise NotImplementedError

    @abstractmethod
    async def get_active_version(self) -> Optional[RuleVersion]:
        raise NotImplementedError

    @abstractmethod
    async def list_versions(self, limit: int = 50) -> List[RuleVersion]:
        raise NotImplementedError

    @abstractmethod
    async def activate_version(self, version_hash: str) -> bool:
        raise NotImplementedError

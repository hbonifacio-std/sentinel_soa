from abc import ABC, abstractmethod
from typing import List, Optional
from core_orchestrator.domain.models.rules import RuleVersion

class VersionRepository(ABC):
    @abstractmethod
    async def list_versions(self, limit: int) -> List[RuleVersion]:
        raise NotImplementedError

    @abstractmethod
    async def get_by_hash(self, version_hash: str) -> Optional[RuleVersion]:
        raise NotImplementedError

    @abstractmethod
    async def get_active(self) -> Optional[RuleVersion]:
        raise NotImplementedError

    @abstractmethod
    async def create_version(self, version: RuleVersion) -> RuleVersion:
        raise NotImplementedError
    
    @abstractmethod
    async def activate_version(self, version: RuleVersion) -> bool:
        raise NotImplementedError


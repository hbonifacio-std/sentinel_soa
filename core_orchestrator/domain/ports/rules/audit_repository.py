from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any

class AuditRulesRepositoryPort(ABC):
    @abstractmethod
    async def get_logs(
        self,
        client_id: Optional[str],
        rule_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    async def log_action(
        self,
        action: str,
        rule_id: str,
        user: str,
        changes: Dict[str, Any],
        reason: str,
        ip_address: str,
        client_id: Optional[str] = None,
    ):
        raise NotImplementedError

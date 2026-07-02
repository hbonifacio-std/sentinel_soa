from abc import ABC, abstractmethod
from typing import Any, Dict


class ThreatContextPort(ABC):
    @abstractmethod
    async def get_threat_context(self, source_ip: str, limit: int = 5) -> Dict[str, Any]:
        """Retrieves historical threat context for a source IP."""
        pass

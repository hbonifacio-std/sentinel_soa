from abc import ABC, abstractmethod
from typing import Dict, Any

class ThreatContextServicePort(ABC):
    @abstractmethod
    async def get_historical_context(self, source_ip: str) -> Dict[str, Any]:
        """
        Retrieves historical threat context for a given source IP.
        """
        pass

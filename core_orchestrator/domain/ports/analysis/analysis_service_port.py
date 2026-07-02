from abc import ABC, abstractmethod
from typing import Dict, Any

class AnalysisServicePort(ABC):
    @abstractmethod
    async def analyze_activity(self, telemetry_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes telemetry data and returns an analysis result.
        """
        pass

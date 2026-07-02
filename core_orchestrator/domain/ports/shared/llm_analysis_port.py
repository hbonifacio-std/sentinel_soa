from abc import ABC, abstractmethod
from typing import Any, Dict


class LlmAnalysisPort(ABC):
    @abstractmethod
    async def analyze_web_activity(self, telemetry_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Executes threat analysis for a telemetry window and returns structured data."""
        pass

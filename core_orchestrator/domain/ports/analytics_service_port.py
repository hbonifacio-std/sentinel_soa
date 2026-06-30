from abc import ABC, abstractmethod
from typing import Dict, Any

class AnalyticsServicePort(ABC):
    @abstractmethod
    async def create_analysis_report(self, report_data: Dict[str, Any]) -> str:
        """
        Creates a new analysis report in the database.
        """
        pass

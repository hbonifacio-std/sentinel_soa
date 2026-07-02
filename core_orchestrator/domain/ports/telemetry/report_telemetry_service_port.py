from abc import ABC, abstractmethod

from pydantic import BaseModel


class ReportTelemetryServicePort(ABC):
    @abstractmethod
    async def create_analysis_report(self, report_data: BaseModel) -> str:
        """
        Creates a new analysis report in the database.
        """
        pass

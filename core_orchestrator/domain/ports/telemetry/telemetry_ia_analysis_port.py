from abc import ABC, abstractmethod

from core_orchestrator.domain.entities.telemetry import TelemetryWindow
from core_orchestrator.domain.entities.telemetry.reports import AnalysisReport


class AiAnalysisPort(ABC):

    @abstractmethod
    async def analyze_activity(self, telemetry_window: TelemetryWindow) -> AnalysisReport:
        """
        Analyzes telemetry data and returns an analysis result.
        """
        pass
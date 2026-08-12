from abc import ABC, abstractmethod
from typing import Sequence, Optional

from core_orchestrator.domain.entities.telemetry.logs_event import LogEvent
from core_orchestrator.domain.entities.telemetry.reports import AnalysisReport


class TelemetryGraphRepositoryPort(ABC):
    @abstractmethod
    async def upsert_log_event(self, log_event: LogEvent, event_id: Optional[str] = None) -> None:
        raise NotImplementedError

    @abstractmethod
    async def upsert_bulk_log_events(self, log_events: Sequence[LogEvent]) -> None:
        raise NotImplementedError

    @abstractmethod
    async def upsert_analysis_report(self, report: AnalysisReport, report_id: Optional[str] = None) -> None:
        raise NotImplementedError

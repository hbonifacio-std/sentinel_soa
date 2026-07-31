from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any

from core_orchestrator.domain.entities.analysis import AnalysisReportResponse
from core_orchestrator.domain.entities.telemetry.log_event import LogEvent


class TelemetryRepository(ABC):
    @abstractmethod
    async def insert_log_event(self, log_event: LogEvent) -> str:
        ...

    @abstractmethod
    async def bulk_insert_log_events(self, log_events: List[LogEvent]) -> int:
        ...

    @abstractmethod
    async def get_logs_paginated(
        self, query: Optional[Dict[str, Any]] = None, page: int = 1, limit: int = 10
    ) -> Dict[str, Any]:
        ...

    @abstractmethod
    async def insert_analysis_report(self, report_model: AnalysisReportResponse) -> str:
        ...

    @abstractmethod
    async def get_analysis_reports_paginated(
        self, query: Optional[Dict[str, Any]] = None, page: int = 1, limit: int = 10
    ) -> list[AnalysisReportResponse]:
        ...

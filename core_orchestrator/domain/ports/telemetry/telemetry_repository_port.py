from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any

from core_orchestrator.domain.entities.telemetry.logs_event import LogEvent
from core_orchestrator.infrastructure.adapters.mongodb.responses import PaginatedResult
from core_orchestrator.infrastructure.dto.telemetry.analysis_report_dto import AnalysisReportResponseDTO
from core_orchestrator.infrastructure.dto.telemetry.log_event_dto import LogEventDTO


class TelemetryRepositoryPort(ABC):
    @abstractmethod
    async def insert_log_event(self, log_event: LogEvent) -> str:
        ...

    @abstractmethod
    async def bulk_insert_log_events(self, log_events: List[LogEvent]) -> int:
        ...

    @abstractmethod
    async def get_logs_paginated(
        self, query: Optional[Dict[str, Any]] = None, page: int = 1, limit: int = 10
    ) -> PaginatedResult[LogEvent]:
        ...

    @abstractmethod
    async def insert_analysis_report(self, report_model: AnalysisReportResponseDTO) -> str:
        ...

    @abstractmethod
    async def get_analysis_reports_paginated(
        self, query: Optional[Dict[str, Any]] = None, page: int = 1, limit: int = 10
    ) -> list[AnalysisReportResponseDTO]:
        ...

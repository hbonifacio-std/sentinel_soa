"""Repository port for forensic analysis persistence and search."""

from abc import ABC, abstractmethod
from typing import Any, Optional

from core_orchestrator.infrastructure.dto.telemetry.forensic_analysis_dto import (
    ForensicAnalyzeRequestDTO,
    ForensicAnalysisRecordDTO,
    ForensicHistoryQueryDTO,
)


class ForensicAnalysisRepositoryPort(ABC):
    """Persistence and search contract for forensic analysis workflows."""

    @abstractmethod
    async def query_telemetry(
        self,
        request: ForensicAnalyzeRequestDTO,
        query_filter: Optional[dict[str, Any]] = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Search telemetry logs using the forensic query contract or an intelligence-built filter."""
        raise NotImplementedError

    @abstractmethod
    async def save_analysis(self, record: ForensicAnalysisRecordDTO) -> str:
        """Persist a forensic report and return its identifier."""
        raise NotImplementedError

    @abstractmethod
    async def get_analysis_by_id(self, analysis_id: str, client_id: str) -> Optional[ForensicAnalysisRecordDTO]:
        """Load a previously generated forensic report by id."""
        raise NotImplementedError

    @abstractmethod
    async def get_history(self, query: ForensicHistoryQueryDTO) -> dict[str, Any]:
        """Return paginated forensic report history."""
        raise NotImplementedError

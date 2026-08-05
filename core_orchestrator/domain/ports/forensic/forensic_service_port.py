"""Application service port for forensic workflows."""

from abc import ABC, abstractmethod
from typing import Optional

from core_orchestrator.infrastructure.dto.telemetry.forensic_analysis_dto import (
    ForensicAnalyzeRequestDTO,
    ForensicAnalysisRecordDTO,
    ForensicHistoryQueryDTO,
    ForensicHistoryResponseDTO,
)


class ForensicServicePort(ABC):
    """Contract used by API layer to run and read forensic analyses."""

    @abstractmethod
    async def analyze_activity(self, request: ForensicAnalyzeRequestDTO) -> ForensicAnalysisRecordDTO:
        """Run a forensic query and generate a persisted report."""
        raise NotImplementedError

    @abstractmethod
    async def get_analysis_history(self, query: ForensicHistoryQueryDTO) -> ForensicHistoryResponseDTO:
        """Retrieve paginated forensic report history."""
        raise NotImplementedError

    @abstractmethod
    async def get_analysis_by_id(self, analysis_id: str, client_id: str) -> Optional[ForensicAnalysisRecordDTO]:
        """Retrieve one forensic report by identifier."""
        raise NotImplementedError

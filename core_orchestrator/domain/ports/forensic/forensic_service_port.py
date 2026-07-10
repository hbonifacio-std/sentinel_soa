"""Application service port for forensic workflows."""

from abc import ABC, abstractmethod
from typing import Optional

from core_orchestrator.domain.models.forensic.forensic_analysis import (
    ForensicAnalyzeRequest,
    ForensicAnalysisRecord,
    ForensicHistoryQuery,
    ForensicHistoryResponse,
)


class ForensicServicePort(ABC):
    """Contract used by API layer to run and read forensic analyses."""

    @abstractmethod
    async def analyze_activity(self, request: ForensicAnalyzeRequest) -> ForensicAnalysisRecord:
        """Run a forensic query and generate a persisted report."""
        raise NotImplementedError

    @abstractmethod
    async def get_analysis_history(self, query: ForensicHistoryQuery) -> ForensicHistoryResponse:
        """Retrieve paginated forensic report history."""
        raise NotImplementedError

    @abstractmethod
    async def get_analysis_by_id(self, analysis_id: str, client_id: str) -> Optional[ForensicAnalysisRecord]:
        """Retrieve one forensic report by identifier."""
        raise NotImplementedError

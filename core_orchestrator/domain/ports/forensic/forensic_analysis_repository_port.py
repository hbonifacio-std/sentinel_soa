"""Repository port for forensic analysis persistence and search."""

from abc import ABC, abstractmethod
from typing import Any, Optional, List

from core_orchestrator.domain.entities.telemetry.forensic import ForensicChatSession
from core_orchestrator.infrastructure.adapters.mongodb.responses import PaginatedResult
from core_orchestrator.infrastructure.dto.telemetry.forensic_analysis_dto import (
    ChatForensicQuestionDTO,
    ForensicChatSessionDTO,
    ForensicHistoryQueryDTO,
)


class ForensicAnalysisRepositoryPort(ABC):
    """Persistence and search contract for forensic analysis workflows."""

    @abstractmethod
    async def query_telemetry(
        self,
        request: ChatForensicQuestionDTO,
        query_filter: Optional[dict[str, Any]] = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Search telemetry logs using the forensic query contract or an intelligence-built filter."""
        raise NotImplementedError

    @abstractmethod
    async def save_analysis(self, record: ForensicChatSession) -> Optional[ForensicChatSession]:
        """Persist a forensic report and return its identifier."""
        raise NotImplementedError

    @abstractmethod
    async def get_by_id(self, session_id: str, client_id: str) -> Optional[ForensicChatSession]:
        """Load a previously generated forensic report by id."""
        raise NotImplementedError

    @abstractmethod
    async def get_history(self, query: ForensicHistoryQueryDTO) -> PaginatedResult[ForensicChatSession]:
        """Return paginated forensic report history."""
        raise NotImplementedError

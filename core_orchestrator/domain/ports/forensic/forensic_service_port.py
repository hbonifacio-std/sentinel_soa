"""Application service port for forensic workflows."""

from abc import ABC, abstractmethod
from typing import Optional, List

from core_orchestrator.domain.entities.telemetry.forensic import ForensicChatSession
from core_orchestrator.infrastructure.adapters.mongodb.responses import PaginatedResult
from core_orchestrator.infrastructure.dto.telemetry.forensic_analysis_dto import (
    ChatForensicQuestionDTO,
    ForensicChatSessionDTO,
    ForensicHistoryQueryDTO,
    ForensicHistoryResponseDTO,
)


class ForensicServicePort(ABC):
    """Contract used by API layer to run and read forensic analyses."""

    @abstractmethod
    async def analyze_activity(self, request: ChatForensicQuestionDTO) -> ForensicChatSession:
        """Run a forensic query and generate a persisted report."""
        raise NotImplementedError

    @abstractmethod
    async def get_analysis_history(self, query: ForensicHistoryQueryDTO) -> PaginatedResult[ForensicChatSession]:
        """Retrieve paginated forensic report history."""
        raise NotImplementedError

    @abstractmethod
    async def get_analysis_by_id(self, session_id: str, client_id: str) -> Optional[ForensicChatSessionDTO]:
        """Retrieve one forensic report by identifier."""
        raise NotImplementedError

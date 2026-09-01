"""Application service for forensic analysis workflows."""

from collections import Counter
from datetime import datetime, timezone
import logging
from typing import Any, List
from core_orchestrator.application.modules.auth_clients.tenant_provider_ai_service import TenantProviderAiService
from core_orchestrator.domain.entities.telemetry.forensic import  ForensicChatSession, \
    ChatMessage
from core_orchestrator.domain.ports import LlmAnalysisPort
from core_orchestrator.infrastructure.adapters.ai_providers.provider_factory import ProviderFactory
from core_orchestrator.infrastructure.adapters.ai_providers.resposes import ResponseForensic
from core_orchestrator.infrastructure.adapters.mongodb.responses import PaginatedResult
from core_orchestrator.infrastructure.dto.telemetry.forensic_analysis_dto import (
    ChatForensicQuestionDTO,
    ForensicHistoryQueryDTO,
)
from core_orchestrator.domain.ports.forensic import (
    ForensicAnalysisRepositoryPort,
    ForensicServicePort,
)


logger = logging.getLogger(__name__)


class ForensicService(ForensicServicePort):
    """Coordinates forensic queries and report persistence."""

    def __init__(
        self,
        forensic_repository: ForensicAnalysisRepositoryPort,
        tenant_provider_service: TenantProviderAiService,
        provider_ai_factory: ProviderFactory,
        llm_analysis: LlmAnalysisPort
    ):
        self.forensic_repository = forensic_repository
        self.provider_ai_factory = provider_ai_factory
        self.tenant_provider_service = tenant_provider_service
        self.llm_analysis = llm_analysis

    async def analyze_activity(self, request: ChatForensicQuestionDTO) -> ForensicChatSession | None:
        logger.info(
            "Starting forensic analysis for query=%r source_id=%r client_id=%r model_id=%r",
            request.query,
            request.source_id,
            request.client_id,
            request.model_id
        )
        session: ForensicChatSession
        if request.session_id:
            existing_session = (
                await self.forensic_repository.get_by_id(
                    session_id=request.session_id,client_id=request.client_id
                )
            )
            if not existing_session:
                raise ValueError(
                    f"Session with ID {request.session_id} not found."
                )
            session = existing_session
        else:
            session = ForensicChatSession(
                client_id=request.client_id,
                created_at_utc=datetime.now(timezone.utc),
            )
        session.messages.append(
            ChatMessage(
                role="user",
                content=request.query,
            )
        )
        provider = await self.tenant_provider_service.get_provider_config_for_model(request.client_id, request.model_id)

        model_config = await self.tenant_provider_service.get_model_ai_by_id(
            tenant_id=request.client_id,
            model_id=request.model_id
        )

        model = self.provider_ai_factory.create_provider(
            provider_config=provider,
            model_definition=model_config
        )

        response:ResponseForensic = await self.llm_analysis.ask_llm(
           ia_provider_client=model,
           messages=session.get_list_messages_dict(),
           response_format=ResponseForensic
        )

        session.messages.append(
            ChatMessage(
                role="assistant",
                content=response.response_markdown,
            )
        )
        session.add_highlights(response.highlighted)
        update_session = await self.forensic_repository.save_analysis(session)

        logger.info("Forensic analysis persisted")
        return update_session

    async def get_analysis_history(self, query: ForensicHistoryQueryDTO) -> PaginatedResult[ForensicChatSession]:
        history = await self.forensic_repository.get_history(query)
        return history

    async def get_analysis_by_id(self, session_id: str, client_id: str) -> ForensicChatSession | None:
        return await self.forensic_repository.get_by_id(session_id, client_id)


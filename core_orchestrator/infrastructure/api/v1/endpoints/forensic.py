"""Forensic endpoints for ad-hoc investigation and report history."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from core_orchestrator.domain.entities.telemetry.forensic import ForensicChatSession
from core_orchestrator.infrastructure.adapters.mongodb.responses import PaginatedResult
from core_orchestrator.infrastructure.dto.responses import ResponsePaginatedDTO
from core_orchestrator.infrastructure.dto.telemetry.forensic_analysis_dto import (
    ChatForensicQuestionDTO,
    ForensicChatSessionDTO,
    ForensicHistoryQueryDTO,
    ForensicHistoryResponseDTO,
)
from core_orchestrator.domain.entities.auth.user import UserInDB
from core_orchestrator.domain.ports.forensic import ForensicServicePort
from core_orchestrator.application.modules.auth_clients.tenant_provider_ai_service import TenantProviderAiService
from core_orchestrator.infrastructure.api.dependencies.general_dependencies import get_tenant_provider_service, \
    get_forensic_service
from core_orchestrator.infrastructure.api.dependencies.user_auth import get_analyst_user_with_client
from core_orchestrator.infrastructure.mappers.mappers import chat_forensic_mapper

router = APIRouter()


@router.get("/models")
async def get_available_models_for_chat(
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
    tenant_provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
):
    """
    Handles the retrieval of available AI models for chat functionality for the current user's tenant.
    Returns the default and available models based on the tenant configuration.

    Parameters:
        current_user (UserInDB): The authenticated user object associated with the current session,
            extracted using dependency injection.
        tenant_provider_service (TenantProviderAiService): Service responsible for managing tenant-specific
            AI model configurations and details, injected via dependency.

    Returns:
        Dict: A dictionary containing the default model ID (default_model_id) and the list of available
            model IDs (available_models).
    """
    models = await tenant_provider_service.get_available_models_for_tenant(
        current_user.client_id
    )
    tenant = await tenant_provider_service.get_tenant_by_client_id(current_user.client_id)
    default_model = tenant.default_log_analysis_model_id if tenant else None
    return {
        "default_model_id": default_model,
        "available_models": models
    }


@router.post("/analyze", status_code=status.HTTP_201_CREATED)
async def run_forensic_analysis(
    request: ChatForensicQuestionDTO,
    forensic_service: Annotated[ForensicServicePort, Depends(get_forensic_service)],
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
) -> ForensicChatSessionDTO:
    """
    Handles the forensic analysis of chat activities by invoking the corresponding
    service. The endpoint processes data input, incorporates user-specific details,
    and returns a structured response with the analysis results.

    Args:
        request (ChatForensicQuestionDTO): The DTO contains the input data needed for
            the forensic analysis process
        forensic_service (ForensicServicePort): The service dependency responsible
            for processing the forensic analysis
        current_user (UserInDB): The authenticated user making the request, with
            their associated client details

    Returns:
        ForensicChatSessionDTO: A DTO encapsulating the results of the forensic
        analysis and related details.
    """
    response_chat_forensic = await forensic_service.analyze_activity(
        request.model_copy(update={"client_id": current_user.client_id})
    )
    session_response = chat_forensic_mapper.to_dto(response_chat_forensic)
    return session_response


@router.get("/history")
async def get_forensic_history(
    forensic_service: Annotated[ForensicServicePort, Depends(get_forensic_service)],
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(le=100)] = 10

) -> ResponsePaginatedDTO[ForensicChatSessionDTO]:
    """List paginated forensic reports."""


    paginated_data: PaginatedResult[ForensicChatSession] = await forensic_service.get_analysis_history(
        ForensicHistoryQueryDTO(
            client_id=current_user.client_id,
            page=page,
            limit=limit,
        )
    )

    return chat_forensic_mapper.to_paginated_dto(
                        entities=paginated_data.results,
                        info_paginated=paginated_data.info,
                        path="/analytics/logs_row_telemetry"
    )


@router.get("/history/{analysis_id}")
async def get_forensic_report(
    analysis_id: str,
    forensic_service: Annotated[ForensicServicePort, Depends(get_forensic_service)],
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
) -> ForensicChatSessionDTO:
    """Return one forensic report by id."""

    report = await forensic_service.get_analysis_by_id(analysis_id, current_user.client_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic report not found")
    return report

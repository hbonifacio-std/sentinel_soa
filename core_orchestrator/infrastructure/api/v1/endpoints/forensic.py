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
    Fetches the available models for chat based on the current user's client and tenant information.

    This endpoint retrieves the list of models available for the tenant associated with the current
    user's client ID. Additionally, it provides the default log analysis model ID if specified for
    the tenant.

    Parameters:
        current_user: UserInDB
            The currently authenticated user, which includes their client ID information.
        tenant_provider_service: TenantProviderAiService
            The service responsible for handling tenant-specific operations related to models.

    Returns:
        dict: A dictionary containing the following keys:
            - default_model_id: str or None
                The ID of the default log analysis model for the tenant, or None if not specified.
            - available_models: list
                A list of model identifiers available to the tenant.
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
    Handles the forensic analysis request and initiates processing using the provided
    service and user information.

    Performs forensic analysis on chat-related activity based on the request data,
    current user's client context, and the forensic service implementation. Returns
    a detailed forensic chat session result after analysis.

    Args:
        request (ChatForensicQuestionDTO): The data transfer object containing the
            necessary details for forensic analysis
        forensic_service (ForensicServicePort): Dependency-injected service handling
            the forensic analysis logic
        current_user (UserInDB): Dependency-injected user data is used to determine
            the client context for the analysis

    Returns:
        ForensicChatSessionDTO: The result of the forensic chat session after
        successful analysis.
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
    """
    Retrieves the forensic analysis history for the current user.

    This endpoint fetches a paginated list of forensic chat sessions associated with the
    current user and their client. The data is retrieved through the forensic service
    and paginated according to the provided parameters. The result is converted to a
    ResponsePaginatedDTO format before being returned.

    Arguments:
        forensic_service (ForensicServicePort): Dependency that provides access to forensic service functionalities
        current_user (UserInDB): The currently authenticated user, retrieved through dependency injection
        page (int): The page number to retrieve must be greater than or equal to 1
        limit (int): The maximum number of records to retrieve per page must not exceed 100

    Returns:
        ResponsePaginatedDTO[ForensicChatSessionDTO]: A DTO containing the paginated results of forensic chat sessions.
    """


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


@router.get("/history/{session_id}")
async def get_forensic_report(
    session_id: str,
    forensic_service: Annotated[ForensicServicePort, Depends(get_forensic_service)],
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
) -> ForensicChatSessionDTO:
    """
    Fetch a forensic chat session report for a given session ID.

    Retrieves the analysis report corresponding to the specified session ID,
    validating that the requesting user has access to the associated client.
    If the report is not found, an exception is raised.

    Parameters:
    session_id: str
        The unique identifier of the forensic chat session to be retrieved.
    forensic_service: ForensicServicePort
        The forensic service implementation to fetch the analysis report. Dependency
        injected via FastAPI Depends.
    current_user: UserInDB
        The user object corresponding to the currently authenticated analyst. Dependency
        injected via FastAPI Depends.

    Returns:
    ForensicChatSessionDTO
        The DTO object containing the details of the forensic chat session report.

    Raises:
    HTTPException
        If the forensic analysis report for the given session ID is not found.
    """

    report = await forensic_service.get_analysis_by_id(session_id, current_user.client_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic report not found")
    return report

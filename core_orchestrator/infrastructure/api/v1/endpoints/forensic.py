"""Forensic endpoints for ad-hoc investigation and report history."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from core_orchestrator.domain.entities.forensic.forensic_analysis import (
    ForensicAnalyzeRequest,
    ForensicAnalysisRecord,
    ForensicHistoryQuery,
    ForensicHistoryResponse,
)
from core_orchestrator.domain.entities.auth.user import UserInDB
from core_orchestrator.domain.ports.forensic import ForensicServicePort
from core_orchestrator.application.modules.auth_clients.services.tenant_provider_ai_service import TenantProviderAiService
from core_orchestrator.infrastructure.api.dependencies.general_dependencies import get_tenant_provider_service, \
    get_forensic_service
from core_orchestrator.infrastructure.api.dependencies.user_auth import get_analyst_user_with_client

router = APIRouter()


@router.get("/models")
async def get_available_models_for_chat(
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
    tenant_provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
):
    """Devuelve los modelos disponibles para el tenant del usuario actual."""
    models = await tenant_provider_service.get_available_models_for_tenant(
        current_user.client_id
    )
    tenant = await tenant_provider_service._get_tenant(current_user.client_id)
    default_model = tenant.default_log_analysis_model_id if tenant else None
    return {
        "default_model_id": default_model,
        "available_models": models
    }


@router.post("/analyze", status_code=status.HTTP_201_CREATED)
async def run_forensic_analysis(
    request: ForensicAnalyzeRequest,
    forensic_service: Annotated[ForensicServicePort, Depends(get_forensic_service)],
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
) -> ForensicAnalysisRecord:
    """Run a forensic query and persist the generated report."""

    return await forensic_service.analyze_activity(
        request.model_copy(update={"client_id": current_user.client_id})
    )


@router.get("/history")
async def get_forensic_history(
    forensic_service: Annotated[ForensicServicePort, Depends(get_forensic_service)],
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
    source_id: str | None = None,
    page: int = Query(default=1, ge=1, description="Número de la página (mínimo 1)"),
    limit: int = Query(default=10, ge=1, le=100, description="Cantidad de registros por página (máximo 100)"),
) -> ForensicHistoryResponse:
    """List paginated forensic reports."""

    history_query = ForensicHistoryQuery(
        source_id=source_id,
        client_id=current_user.client_id,
        page=page,
        limit=limit,
    )
    return await forensic_service.get_analysis_history(history_query)


@router.get("/history/{analysis_id}")
async def get_forensic_report(
    analysis_id: str,
    forensic_service: Annotated[ForensicServicePort, Depends(get_forensic_service)],
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
) -> ForensicAnalysisRecord:
    """Return one forensic report by id."""

    report = await forensic_service.get_analysis_by_id(analysis_id, current_user.client_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic report not found")
    return report

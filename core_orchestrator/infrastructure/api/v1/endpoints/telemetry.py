import logging
from typing import List, Annotated
from fastapi import APIRouter, HTTPException, status, Depends, BackgroundTasks, Request

from core_orchestrator.infrastructure.adapters.security.tenant_auth_adapter import TenantContext
from core_orchestrator.infrastructure.dto.responses import OperationResponseDTO
from core_orchestrator.infrastructure.dto.telemetry.log_event_dto import LogEventDTO
from core_orchestrator.application.modules.telemetry.telemetry_service import TelemetryService
from core_orchestrator.application.modules.telemetry.telemetry_window_manager_service import TelemetryProcessingService
from core_orchestrator.infrastructure.api.dependencies.general_dependencies import get_telemetry_service, \
    get_telemetry_processing_service

from core_orchestrator.infrastructure.api.dependencies.tenant_auth import get_tenant_context, get_source_id
from core_orchestrator.infrastructure.mappers.mappers import log_event_mapper
from core_orchestrator.infrastructure.rate_limit.rate_limiter import limiter

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/ingest/batch", status_code=status.HTTP_202_ACCEPTED,response_model=OperationResponseDTO)
@limiter.limit("10/minute")
async def ingest_batch_events(
    request: Request,
    events: List[LogEventDTO],
    background_tasks: BackgroundTasks,
    tenant_context: Annotated[TenantContext, Depends(get_tenant_context)],
    source_id: Annotated[str, Depends(get_source_id)],
    telemetry_service: Annotated[TelemetryService, Depends(get_telemetry_service)] ,
    telemetry_processing_service: Annotated[TelemetryProcessingService, Depends(get_telemetry_processing_service)],
):
    """Batch ingest telemetry events with multitenant isolation and source tracking.
    
    Required headers:
    - X-Sentinel-API-Key: Tenant API key for authentication
    - X-Sentinel-Source-ID: Unique identifier of the telemetry source
    
    Server-side guarantees:
      - client_id is stamped from an authenticated tenant context (never trusts client input)
      - source_id is stamped from the request header (single source of truth)
    """
    if not events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The request body does not contain events."
        )

    for event in events:
        event.client_id = tenant_context.client_id
        event.source_id = source_id

    logger.info(
        f"Batch ingestion: {len(events)} events from source '{source_id}' for client '{tenant_context.client_id}'"
    )

    logs_events = log_event_mapper.to_dataclass_list(events)
    background_tasks.add_task(telemetry_service.ingest_bulk_logs, logs_events)
    await telemetry_processing_service.add_multiple_logs_events(logs_events)

    return OperationResponseDTO(
        status="accepted",
        client_id=tenant_context.client_id,
        source_id=source_id,
        message=f"Batch ingestion of {len(events)} events accepted for source '{source_id}'",
        affected_records=0,
        details={
            "processed_records": len(events)
        }
    )
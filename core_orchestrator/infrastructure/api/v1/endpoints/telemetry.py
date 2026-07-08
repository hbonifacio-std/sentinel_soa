
import asyncio
import json
import logging
from typing import List, Annotated
from fastapi import APIRouter, HTTPException, status, Depends, BackgroundTasks, Request

from core_orchestrator.infrastructure.agent.runner import AgentRunner
from core_orchestrator.infrastructure.api.dependencies import (
    get_telemetry_service,
    get_telemetry_processing_service,
    get_agent_runner,
)
from core_orchestrator.domain.models.auth.telemetry_client import (
    TelemetryClientAuthContext,
)
from core_orchestrator.domain.models.telemetry.log_event import LogEvent
from core_orchestrator.application.modules.telemetry.services.telemetry_service import TelemetryService
from core_orchestrator.application.modules.telemetry.services.telemetry_processing_service import TelemetryProcessingService
from core_orchestrator.infrastructure.security.dependencies import (
    verify_api_key_header,
)
# Corrected import path for redact_sensitive_data
from core_orchestrator.infrastructure.security.sanitizer import redact_sensitive_data

logger = logging.getLogger(__name__)

router = APIRouter()


from core_orchestrator.infrastructure.api.rate_limiter import limiter
from core_orchestrator.infrastructure.api.auth import get_tenant_context, TenantContext

@router.post("/", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(lambda request: f"{getattr(request.state, 'tenant_rate', 60)}/minute")
async def ingest_single_event(
    request: Request,
    event: LogEvent,
    background_tasks: BackgroundTasks,
    client: Annotated[TelemetryClientAuthContext, Depends(verify_api_key_header)],
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    telemetry_service: Annotated[TelemetryService, Depends(get_telemetry_service)],
    telemetry_processing_service: Annotated[TelemetryProcessingService, Depends(get_telemetry_processing_service)],
    agent_runner: Annotated[AgentRunner, Depends(get_agent_runner)]
):
    """Ingest a single event and stamp it with tenant context."""

    # Stamp tenant_id on the event server-side (never trust incoming tenant_id)
    event.tenant_id = tenant.tenant_id

    event_dict = event.model_dump()
    sanitized_event_json = json.dumps(redact_sensitive_data(event_dict))
    logger.info(f"Single event ingestion request received: {sanitized_event_json}")

    background_tasks.add_task(telemetry_service.ingest_log_event, event)
    await telemetry_processing_service.add_log_event(event)

    return {
        "status": "accepted",
        "client_id": client.client_id,
        "event_buffered": event.model_dump()
    }


@router.post("/ingest/batch", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(lambda request: f"{getattr(request.state, 'tenant_rate', 60)}/minute")
async def ingest_batch_events(
    request: Request,
    events: List[LogEvent],
    background_tasks: BackgroundTasks,
    client: Annotated[TelemetryClientAuthContext, Depends(verify_api_key_header)],
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    telemetry_service: Annotated[TelemetryService, Depends(get_telemetry_service)],
    telemetry_processing_service: Annotated[TelemetryProcessingService, Depends(get_telemetry_processing_service)],
    agent_runner: Annotated[AgentRunner, Depends(get_agent_runner)]
):
    
    if not events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The request body does not contain events."
        )

    
    first_source_id = events[0].source_id
    if any(event.source_id != first_source_id for event in events):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="All events in a batch must have the same source_id."
        )

    if first_source_id != client.source_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"The authenticated client '{client.client_id}' is not authorized to send source_id '{first_source_id}'."
        )

    # Stamp tenant_id server-side on every event
    for ev in events:
        ev.tenant_id = tenant.tenant_id

    # Apply redaction to batch events before logging
    logger.info(
        f"Batch ingestion request received with {len(events)} events from '{first_source_id}'. "
    )

    background_tasks.add_task(telemetry_service.ingest_bulk_logs, events)
    await telemetry_processing_service.add_multiple_logs_events(events)

    logger.debug(f"Processed and queued {len(events)} events.")
    
    return {
        "status": "accepted",
        "client_id": client.client_id,
        "processed_records": len(events)
    }

@router.post("/flush", status_code=status.HTTP_200_OK)
async def flush_windows(
        telemetry_processing_service: Annotated[TelemetryProcessingService, Depends(get_telemetry_processing_service)],
        agent_runner: Annotated[AgentRunner, Depends(get_agent_runner)]):
    
    logger.info("Manual flush request for telemetry windows received.")

    processed_windows = 0
    keys = await telemetry_processing_service.get_active_windows()
    if not keys:
        logger.info("No active windows found to process.")
        return {"status": "ok", "message": "No active windows to flush.", "processed_windows": 0}

    async def process_key(key):
        nonlocal processed_windows
        decoded_key = key.decode('utf-8')
        # Use agent_runner.cache_service.lock instead of agent_runner.redis_client.lock
        lock = agent_runner.cache_service.lock(f"lock:{decoded_key}", timeout=10)
        if await lock.acquire(blocking=False):
            try:
                telemetry_window = await telemetry_processing_service.process_window(decoded_key)
                if telemetry_window:
                    await agent_runner.run_analysis(telemetry_window.model_dump())
                    processed_windows += 1
            finally:
                await lock.release()
        else:
            logger.warning(f"Could not acquire lock for key {decoded_key}, skipping. It might already be being processed.")

    try:
        await asyncio.gather(*(process_key(key) for key in keys))
    except Exception as e:
        logger.error(
            f"Error during manual flush of windows: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during the flush operation: {e}"
        )

    logger.info(
        f"Manual flush completed. Processed windows: {processed_windows}/{len(keys)}")

    return {
        "status": "ok",
        "processed_windows": processed_windows,
        "total_active_windows_found": len(keys)
    }

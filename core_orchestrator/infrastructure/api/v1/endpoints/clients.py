"""
API endpoints for managing Telemetry Clients.
"""
import logging
from typing import List, Annotated
from fastapi import APIRouter, Depends, HTTPException, status

from core_orchestrator.infrastructure.api.dependencies import get_telemetry_client_service
from core_orchestrator.domain.models.auth.telemetry_client import (
    TelemetryClientCreate,
    TelemetryClientResponse,
)
from core_orchestrator.domain.models.auth.user import UserInDB
from core_orchestrator.application.modules.auth_clients.services.telemetry_client_service import TelemetryClientService
from core_orchestrator.infrastructure.security.dependencies import get_admin_user

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/clients", response_model=List[TelemetryClientResponse], status_code=status.HTTP_200_OK)
async def list_authorized_clients(
    telemetry_client_service: Annotated[TelemetryClientService, Depends(get_telemetry_client_service)],
    _admin: Annotated[UserInDB, Depends(get_admin_user)],
    include_inactive: bool = False,
):
    """
    Lists all authorized telemetry clients.
    
    Requires admin privileges.
    """
    clients = await telemetry_client_service.list_clients(include_inactive=include_inactive)
    return [TelemetryClientResponse.from_db_model(client) for client in clients]


@router.post("/clients", response_model=TelemetryClientResponse, status_code=status.HTTP_201_CREATED)
async def create_authorized_client(
    telemetry_client_service: Annotated[TelemetryClientService, Depends(get_telemetry_client_service)],
    payload: TelemetryClientCreate,
    _admin: Annotated[UserInDB, Depends(get_admin_user)],
):
    """
    Creates a new authorized telemetry client.

    Requires admin privileges.
    """
    existing = await telemetry_client_service.get_client_by_client_id(payload.client_id, include_inactive=True)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Telemetry client '{payload.client_id}' already exists."
        )

    client, _created, _updated = await telemetry_client_service.upsert_client(payload, overwrite_existing=False)
    return TelemetryClientResponse.from_db_model(client)

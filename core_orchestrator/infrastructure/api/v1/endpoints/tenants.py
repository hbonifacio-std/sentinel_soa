"""
Tenant management endpoints.

CRUD operations for tenant administration with proper authentication and authorization.
"""

import logging
from fastapi import APIRouter, HTTPException, status, Depends

from core_orchestrator.application.modules.auth_clients.services.tenant_service import TenantService
from core_orchestrator.infrastructure.api.dependencies import get_tenant_service
from core_orchestrator.domain.models.auth.tenant import (
    TenantCreate, TenantResponse, TenantResponseWithKey
)
from core_orchestrator.infrastructure.security.dependencies import get_current_user

logger = logging.getLogger("core_orchestrator.api.tenants")

router = APIRouter()


@router.post(
    "",
    response_model=TenantResponseWithKey,
    status_code=status.HTTP_201_CREATED,
    tags=["Tenants"],
    summary="Create a new tenant"
)
async def create_tenant(
    tenant_create: TenantCreate,
    tenant_service: TenantService = Depends(get_tenant_service),
    current_user = Depends(get_current_user)
):
    """
    Create a new tenant with auto-generated API key.
    
    **Note:** The API key is shown only at creation time. Store it securely.
    
    Args:
        tenant_create: Tenant creation payload
        
    Returns:
        Created tenant with plaintext API key (shown once)
        
    Raises:
        HTTPException: If tenant_id already exists or validation fails
    """
    # Check if user is admin
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can create tenants"
        )
    
    try:
        return await tenant_service.create_tenant(tenant_create)
    except Exception as e:
        logger.error(f"Error creating tenant: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get(
    "/{tenant_id}",
    response_model=TenantResponse,
    status_code=status.HTTP_200_OK,
    tags=["Tenants"],
    summary="Get tenant by ID"
)
async def get_tenant(
    tenant_id: str,
    tenant_service: TenantService = Depends(get_tenant_service),
    current_user = Depends(get_current_user)
):
    """
    Retrieve tenant information by ID.
    
    Args:
        tenant_id: The tenant identifier
        
    Returns:
        Tenant information
        
    Raises:
        HTTPException: If tenant not found
    """
    tenant = await tenant_service.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant {tenant_id} not found"
        )
    
    return TenantResponse(
        tenant_id=tenant.tenant_id,
        display_name=tenant.display_name,
        rate_limit_per_minute=tenant.rate_limit_per_minute,
        is_active=tenant.is_active,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at
    )


@router.get(
    "",
    response_model=list[TenantResponse],
    status_code=status.HTTP_200_OK,
    tags=["Tenants"],
    summary="List all tenants"
)
async def list_tenants(
    tenant_service: TenantService = Depends(get_tenant_service),
    current_user = Depends(get_current_user)
):
    """
    List all tenants.
    
    Returns:
        List of all tenants
    """
    # Check if user is admin
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can list tenants"
        )
    
    tenants = await tenant_service.list_tenants()
    return [
        TenantResponse(
            tenant_id=t.tenant_id,
            display_name=t.display_name,
            rate_limit_per_minute=t.rate_limit_per_minute,
            is_active=t.is_active,
            created_at=t.created_at,
            updated_at=t.updated_at
        )
        for t in tenants
    ]


@router.patch(
    "/{tenant_id}",
    response_model=TenantResponse,
    status_code=status.HTTP_200_OK,
    tags=["Tenants"],
    summary="Update tenant"
)
async def update_tenant(
    tenant_id: str,
    updates: dict,
    tenant_service: TenantService = Depends(get_tenant_service),
    current_user = Depends(get_current_user)
):
    """
    Update tenant fields.
    
    Args:
        tenant_id: The tenant identifier
        updates: Fields to update (display_name, rate_limit_per_minute, is_active)
        
    Returns:
        Updated tenant
        
    Raises:
        HTTPException: If tenant not found or user not admin
    """
    # Check if user is admin
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can update tenants"
        )
    
    # Filter allowed fields
    allowed_fields = {"display_name", "rate_limit_per_minute", "is_active"}
    filtered_updates = {k: v for k, v in updates.items() if k in allowed_fields}
    
    tenant = await tenant_service.update_tenant(tenant_id, **filtered_updates)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant {tenant_id} not found"
        )
    
    return TenantResponse(
        tenant_id=tenant.tenant_id,
        display_name=tenant.display_name,
        rate_limit_per_minute=tenant.rate_limit_per_minute,
        is_active=tenant.is_active,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at
    )


@router.delete(
    "/{tenant_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Tenants"],
    summary="Delete tenant"
)
async def delete_tenant(
    tenant_id: str,
    tenant_service: TenantService = Depends(get_tenant_service),
    current_user = Depends(get_current_user)
):
    """
    Delete a tenant (use with caution - this is irreversible).
    
    Args:
        tenant_id: The tenant identifier
        
    Raises:
        HTTPException: If tenant not found or user not admin
    """
    # Check if user is admin
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can delete tenants"
        )
    
    success = await tenant_service.delete_tenant(tenant_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant {tenant_id} not found"
        )
    
    logger.info(f"Tenant deleted: {tenant_id}")

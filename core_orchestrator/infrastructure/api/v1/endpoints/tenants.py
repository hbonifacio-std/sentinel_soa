"""
Tenant management endpoints.

CRUD operations for tenant administration with proper authentication and authorization.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, HTTPException, status, Depends

from core_orchestrator.application.modules.auth_clients.tenant_service import TenantService
from core_orchestrator.infrastructure.api.dependencies.general_dependencies import get_tenant_service
from core_orchestrator.infrastructure.api.dependencies.user_auth import get_current_user
from core_orchestrator.infrastructure.dto.auth.auth_dto import UserResponseDTO
from core_orchestrator.infrastructure.dto.tenant.tenant_dto import TenantCreatedResponseDTO, TenantCreateRequestDTO, \
    TenantResponseDTO

logger = logging.getLogger("core_orchestrator.api.tenants")

router = APIRouter()


@router.post(
    "",
    response_model=TenantCreatedResponseDTO,
    status_code=status.HTTP_201_CREATED,
    tags=["Tenants"],
    summary="Create a new tenant"
)
async def create_tenant(
    tenant_create: TenantCreateRequestDTO,
    tenant_service: Annotated[TenantService, Depends(get_tenant_service)],
    current_user: Annotated[UserResponseDTO, Depends(get_current_user)]

):
    """
    Create a new tenant using provided tenant details.

    The endpoint allows admin users to create new tenants in the system. It
    validates the current user's role to ensure only users with "admin" access
    rights can perform the operation. Upon successful execution, the service
    returns the details of the created tenant.

    Parameters:
        tenant_create (TenantCreateRequestDTO): The data transfer object containing tenant
            creation details such as name, description, and metadata
        tenant_service (TenantService): A dependency-injected instance of the
            tenant service for accessing tenant-related operations
        current_user (UserResponseDTO): The currently authenticated user object
            containing details such as role and user context

    Returns:
        TenantCreatedResponseDTO: The data transfer object containing the details
            of the successfully created tenant.

    Raises:
        HTTPException: If the current user is not an admin, a 403 Forbidden
            exception is raised. Additionally, if there are issues creating the
            tenant, a 400 Bad Request exception is thrown with an appropriate error
            message.
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
        logger.exception(f"Error creating tenant: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error creating tenant"
        )


@router.get(
    "/{tenant_id}",
    response_model=TenantResponseDTO,
    status_code=status.HTTP_200_OK,
    tags=["Tenants"],
    summary="Get tenant by ID"
)
async def get_tenant(
    tenant_id: str,
    tenant_service: Annotated[TenantService, Depends(get_tenant_service)]
):
    """
    Retrieves tenant details based on the provided tenant ID.

    This endpoint fetches information about a specific tenant, such as its display name,
    rate limit configuration, status, and timestamps. It ensures that only authorized users
    can access tenant data.

    Parameters:
        tenant_id (str): The unique identifier of the tenant to retrieve
        tenant_service (TenantService): A dependency-injected service for handling tenant
            data operations

    Raises:
        HTTPException: Raised if the tenant cannot be found with the specified tenant ID.

    Returns:
        TenantResponse: An object containing the tenant's details such as tenant ID, display name,
            rate limit per minute, status, and timestamps.
    """
    tenant = await tenant_service.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant {tenant_id} not found"
        )
    
    return tenant


@router.get(
    "",
    response_model=list[TenantResponseDTO],
    status_code=status.HTTP_200_OK,
    tags=["Tenants"],
    summary="List all tenants"
)
async def list_tenants(
    tenant_service: Annotated[TenantService, Depends(get_tenant_service)],
    current_user:  Annotated[UserResponseDTO, Depends(get_current_user)]
):
    """
    List all tenants.

    This function retrieves a list of all tenants using the provided tenant service. Access
    to this endpoint is restricted to users with an "admin" role. If the user is not an
    admin, an HTTP 403 Forbidden error is raised.

    Args:
        tenant_service: The service dependency responsible for handling tenant operations.
        current_user: The currently authenticated user details.

    Returns:
        A list of TenantResponseDTO objects representing the tenants.

    Raises:
        HTTPException: If the user is not an admin, with status code 403 Forbidden.
    """
    # Check if user is admin
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can list tenants"
        )
    
    tenants = await tenant_service.list_tenants()
    return tenants


@router.patch(
    "/{tenant_id}",
    response_model=TenantResponseDTO,
    status_code=status.HTTP_200_OK,
    tags=["Tenants"],
    summary="Update tenant"
)
async def update_tenant(
    tenant_id: str,
    updates: dict,
    tenant_service: Annotated[TenantService, Depends(get_tenant_service)],
    current_user: Annotated[UserResponseDTO, Depends(get_current_user)]
):
    """
    Updates the details of a tenant by its tenant ID. Permits modifications only to specific
    fields if the request is made by an admin user. Returns the updated tenant
    details upon success.

    Args:
        tenant_id: The unique identifier of the tenant to update.
        updates: A dictionary of the fields to be updated with their new values.
        tenant_service: The tenant service instance is injected via dependency injection.
        current_user: The currently authenticated user, injected via dependency injection.

    Raises:
        HTTPException: If the current user is not an admin.
        HTTPException: If the tenant is corresponding to the provided tenant, ID does not exist.

    Returns:
        TenantResponseDTO: The updated tenant details in the response model.
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
    
    return tenant


@router.delete(
    "/{tenant_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Tenants"],
    summary="Delete tenant"
)
async def delete_tenant(
    tenant_id: str,
    tenant_service:  Annotated[TenantService, Depends(get_tenant_service)],
    current_user: Annotated[UserResponseDTO, Depends(get_current_user)]
):
    """
    Deletes a tenant identified by the given tenant ID.

    This operation allows administrators to delete a specific tenant from the
    system. The logged-in user must have an "admin" role to perform this action.
    If the tenant is not found, a 404 HTTP response will be returned. A successful
    deletion results in a 204 No Content HTTP status response.

    Parameters:
        tenant_id (str): The unique identifier of the tenant to be deleted
        tenant_service (TenantService): The service handling tenant-related
            operations. Injected as a dependency
        current_user (UserResponseDTO): Information about the currently logged-in
            user. Injected as a dependency

    Raises:
        HTTPException: If the current user is not an admin, with a 403 Forbidden status.
        HTTPException: If the tenant is not found, with a 404 Not Found status.
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

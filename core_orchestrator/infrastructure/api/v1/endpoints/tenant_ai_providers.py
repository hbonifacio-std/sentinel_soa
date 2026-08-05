"""Tenant AI Provider management endpoints for Admin users."""

import logging
from typing import Annotated, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from core_orchestrator.domain.entities.auth.user import UserInDB
from core_orchestrator.application.modules.auth_clients.tenant_provider_ai_service import TenantProviderAiService
from core_orchestrator.infrastructure.api.dependencies.general_dependencies import get_tenant_provider_service
from core_orchestrator.infrastructure.api.dependencies.user_auth import get_current_user
from core_orchestrator.infrastructure.dto.tenant.tenant_dto import ProviderAiResponseDto, AddProviderAiRequestDto, \
    AddModelRequestDto, SetDefaultModelRequestDto, TenantResponseDTO, TenantModelDefinitionRequestDTO

logger = logging.getLogger(__name__)

router = APIRouter()

def _require_admin(user: UserInDB):
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can manage tenant AI provider configurations."
        )


@router.get("/{client_id}/providers", response_model=TenantResponseDTO)
async def list_tenant_providers(
    client_id: str,
    provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
    current_user: Annotated[UserInDB, Depends(get_current_user)],
):
    """
    Handles the HTTP GET request to retrieve tenant providers for a specified client ID.

    Raises a 404 error if the tenant with the given client ID cannot be found. Ensures
    the requesting user has admin privileges before proceeding.

    Arguments:
        client_id (str): The client ID of the tenant whose providers are being queried
        provider_service (TenantProviderAiService): Dependency-injected service for handling
            tenant-provider-related operations
        current_user (UserInDB): Dependency-injected current user object, used to validate
            administrative privileges

    Returns:
        TenantResponseDTO: A DTO containing information about the tenant's providers.

    Raises:
        HTTPException: If the tenant with the specified client ID does not exist or the user
            has insufficient permissions.
    """
    _require_admin(current_user)
    tenant = await provider_service.get_tenant_by_client_id(client_id)
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tenant '{client_id}' not found.")

    return tenant


@router.post("/{client_id}/providers", response_model=list[ProviderAiResponseDto])
async def add_or_update_tenant_provider(
    client_id: str,
    req_add_provider: AddProviderAiRequestDto,
    provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
    current_user: Annotated[UserInDB, Depends(get_current_user)]
):
    """
    Adds or updates a tenant AI provider configuration for the specified client.

    This endpoint allows administrators to configure or update the settings of
    an AI provider for a tenant specified by the client ID. It ensures required
    data is provided, such as an API key, when necessary for certain providers.

    Parameters:
        client_id: str
            The unique identifier of the client for which the AI provider is being modified or added.
        req_add_provider: AddProviderAiRequestDto
            The request body containing the AI provider details, such as the provider
            name, API key, base URL, and enabling status.
        provider_service: TenantProviderAiService
            The service dependency responsible for handling the tenant AI provider operations.
        current_user: UserInDB
            The authenticated user making the request. This user must have administrative
            privileges to perform this operation.

    Raises:
        HTTPException
            If the current user does not have admin privileges, an HTTP 403 Forbidden error is raised.
            If an API key is required for the specified provider but not provided or unavailable
            in the existing tenant configuration, an HTTP 400 Bad Request error is raised.

    Returns:
        ProviderAiResponseDto
            The updated or newly added provider configuration for the tenant.
    """
    _require_admin(current_user)
    if req_add_provider.provider in ("gemini", "openai", "groq") and not req_add_provider.api_key:
        # Check if tenant already has an encrypted key
        tenant = await provider_service.get_tenant_by_client_id(client_id)
        existing = next((p for p in (tenant.ai_providers if tenant else []) if p.provider == req_add_provider.provider), None)
        if not existing or not existing.api_key_encrypted:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"API key is required for provider '{req_add_provider.provider}'."
            )


    added_or_updated_tenant = await provider_service.add_or_update_provider(
            client_id=client_id,req_add_provider=req_add_provider
    )
    return added_or_updated_tenant



@router.delete("/{client_id}/providers/{provider}")
async def delete_tenant_provider(
    client_id: str,
    provider: str,
    provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
    current_user: Annotated[UserInDB, Depends(get_current_user)]
):
    """
    Deletes a provider from a tenant.

    This endpoint allows an admin to remove a specific provider
    associated with a given tenant. The operation is restricted
    to users with administrative privileges.

    Parameters:
        client_id (str): The unique identifier of the tenant from which
            the provider is being removed
        provider (str): The name of the provider to be removed.
        provider_service: The tenant provider service responsible
            for handling provider operations
        current_user: The currently authenticated user attempting
            the operation

    Raises:
        HTTPException: If the provided `client_id` or `provider` is invalid,
            an HTTP 400 Bad Request error is raised.

    Returns:
        dict: A confirmation message indicating the successful removal
            of the provider from the tenant.
    """
    _require_admin(current_user)

    await provider_service.remove_provider(client_id, provider)
    return {"message": f"Provider '{provider}' removed from tenant '{client_id}'."}



@router.get("/{client_id}/providers/models",response_model=Dict[str, TenantModelDefinitionRequestDTO])
async def list_tenant_models(
    client_id: str,
    provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
    current_user: Annotated[UserInDB, Depends(get_current_user)],
):
    """
    Handles retrieval of models available to a tenant based on the client ID, including
    the default log analysis model and a list of available models. Requires administrative
    access to perform this operation.

    Parameters:
        client_id: str
            The unique identifier of the tenant client.
        provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)]
            Injected service for accessing tenant provider AI functionalities.
        current_user: Annotated[UserInDB, Depends(get_current_user)]
            Injected object representing the authenticated user.

    Returns:
        dict
            A dictionary containing the following keys:
            - "default_log_analysis_model_id": The identifier of the tenant's default log analysis model
            - "available_models": A list of models available to the tenant

    Raises:
        HTTPException (status_code=404)
            If the specified tenant identified by client_id is not found.
    """
    _require_admin(current_user)
    tenant = await provider_service.get_tenant_models_by_client_id(client_id)
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Models de '{client_id}' not found.")

    return tenant


@router.post("/{client_id}/providers/models",response_model=Dict[str, TenantModelDefinitionRequestDTO])
async def add_or_update_tenant_model(
    client_id: str,
    request_add_model: AddModelRequestDto,
    provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
    current_user: Annotated[UserInDB, Depends(get_current_user)],
)-> Dict[str, TenantModelDefinitionRequestDTO]:
    """
    Handles the addition or update of a tenant's AI model configuration for a specific provider.

    This endpoint is designed to allow administrators to manage AI models linked to a specific
    tenant or client. The action includes updating an existing configuration or adding a new
    configuration if it does not exist. Only users with administrative permissions are
    authorized to perform this operation.

    Arguments:
        client_id (str): The unique identifier of the tenant associated with the model
        request_add_model (AddModelRequestDto): The data transfer object containing the details of the AI
            model, such as its ID, provider, name, and configuration settings
        provider_service (TenantProviderAiService): The service dependency responsible for managing
            tenant's AI provider operations
        current_user (UserInDB): The authenticated user initiating the request

    Returns:
        TenantResponseDTO: Contains updated information about the tenant's AI model configuration,
            reflecting the changes made during the operation.
    """
    _require_admin(current_user)

    updated_tenant = await provider_service.add_or_update_model(client_id,request_add_model)
    return updated_tenant



@router.delete("/{client_id}/providers/models/{model_id}")
async def delete_tenant_model(
    client_id: str,
    model_id: str,
    provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
    current_user: Annotated[UserInDB, Depends(get_current_user)],
):
    """
    Deletes a specific model associated with a tenant.

    This endpoint allows an admin user to delete a model associated with a specific tenant. The
    operation requires administrative privileges and validates the current user before proceeding.
    The operation interacts with the tenant provider AI service to remove the specified model.

    Parameters:
        client_id (str): The identifier of the tenant whose model is to be removed
        model_id (str): The identifier of the model to be removed
        provider_service (TenantProviderAiService): A dependency providing the
            tenant provider AI service for handling the model removal process
        current_user (UserInDB): A dependency providing the details of the authenticated
            current user

    Raises:
        HTTPException: Raised with a 400 status code if invalid arguments are provided
            or if an error occurs during model removal.

    Returns:
        dict: A message indicating the successful removal of the model from the tenant.
    """
    _require_admin(current_user)

    await provider_service.remove_model(client_id, model_id)
    return {"message": f"Model '{model_id}' removed from tenant '{client_id}'."}


@router.patch("/{client_id}/providers/models/default",response_model=TenantResponseDTO)
async def set_tenant_default_model(
    client_id: str,
    req: SetDefaultModelRequestDto,
    provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
    current_user: Annotated[UserInDB, Depends(get_current_user)],
)->TenantResponseDTO:
    """
    Handles the API endpoint for setting the default AI models for a tenant. This endpoint allows an
    administrator to assign or update the default log analysis and Mongo Translator models for the
    specified tenant, identified by `client_id`.

    Parameters:
        client_id: str
            The unique identifier of the tenant for which the default models are being set.

        req: SetDefaultModelRequestDto
            The request payload containing the model IDs to be set as default.

        provider_service: TenantProviderAiService
            The dependency-injected service used to manage tenant AI configurations.

        current_user: UserInDB
            The currently authenticated user, used to validate administrative privileges.

    Raises:
        HTTPException
            If the input values are invalid or a ValueError occurs while processing the request.

    Returns:
        dict
            A dictionary containing the updated default IDs for the log analysis and Mongo Translator
            models. If no updates were made, the default values will reflect the current tenant
            configuration.
    """
    _require_admin(current_user)

    log_model_id = req.default_log_analysis_model_id or req.model_id
    if log_model_id is not None:
        await provider_service.set_default_log_analysis_model(client_id, log_model_id)

    if req.default_mongo_translator_model_id is not None:
        await provider_service.set_default_mongo_translator_model(client_id, req.default_mongo_translator_model_id)

    tenant = await provider_service.get_tenant_by_client_id(client_id)
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tenant '{client_id}' not found.")
    return tenant


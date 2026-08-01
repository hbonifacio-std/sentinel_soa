"""
Module for tenant management service.

Provides functionalities for creating, updating, retrieving, listing, and managing tenants.
This includes API key generation, activation/deactivation of tenants, and tenant deletion.
"""

import logging
import secrets
import hashlib
from typing import Optional, List

from core_orchestrator.domain.entities.auth.tenant import Tenant
from core_orchestrator.domain.ports.auth.tenant_repository_port import TenantRepositoryPort
from core_orchestrator.infrastructure.dto.tenant.tenant_dto import TenantCreateDTO, TenantResponseDTO, \
    TenantCreatedResponseDTO

logger = logging.getLogger(__name__)


class TenantService:
    """
    Service for tenant management operations.
    
    Handles business logic for:
    - Creating, updating, and managing tenants
    - Tenant API key generation and validation
    - Telemetry client authentication (API keys, HMAC signatures)
    - HMAC signature verification for incoming telemetry
    """

    def __init__(self, tenant_repository: TenantRepositoryPort):
        self.tenant_repository = tenant_repository

    async def create_tenant(self, tenant_create: TenantCreateDTO) -> TenantCreatedResponseDTO:
        """
        Creates a new tenant in the system and returns the tenant details along with an
        API key.

        The method generates a plaintext API key and its hashed version, storing the
        hashed key in the tenant's record in the database. The plaintext API key is
        included in the response for use as a credential by the tenant.

        Parameters:
            tenant_create (TenantCreate): The data required to create the tenant,
            including details such as client ID, display name, and additional metadata.

        Returns:
            TenantResponseWithKey: Contains the details for the newly created tenant,
            including the plaintext API key.

        """

        api_key_plaintext = f"sk_{secrets.token_urlsafe(32)}"

        api_key_hash = hashlib.sha256(api_key_plaintext.encode("utf-8")).hexdigest()
        

        tenant_in_db = await self.tenant_repository.create(
            tenant_create=Tenant(**tenant_create.model_dump()),
            api_key_hash=api_key_hash,
            api_key_plaintext=api_key_plaintext
        )

        return TenantCreatedResponseDTO.model_validate(tenant_in_db)

    async def get_tenant(self, tenant_id: str) -> Optional[TenantResponseDTO]:
        """
        Retrieves a tenant from the repository based on the provided tenant ID.

        Args:
        tenant_id: The unique identifier of the tenant to retrieve.

        Returns:
        Optional[TenantInDB]: The tenant retrieved from the repository if found,
        else None.
        """
        tenant = await self.tenant_repository.get(tenant_id)
        return TenantResponseDTO.model_validate(tenant)


    async def list_tenants(self, include_inactive: bool = False) -> List[TenantResponseDTO]:
        """
        Lists all tenants available in the repository, optionally including inactive tenants.

        Parameters:
        include_inactive (bool): If True, includes inactive tenants in the list.
            Defaults to False.

        Returns:
        List[TenantInDB]: A list of TenantInDB objects representing the tenants.
        """
        tenants = await self.tenant_repository.list_all(include_inactive=include_inactive)
        return [ TenantResponseDTO.model_validate(t) for t in tenants]

    async def update_tenant(self, tenant_id: str, **kwargs) -> Optional[TenantResponseDTO]:
        """
        Updates an existing tenant with the provided data.

        This method updates a tenant identified by the tenant_id with the
        additional data provided through keyword arguments. The updated tenant
        information is returned if the operation is successful. If the tenant
        does not exist, None is returned.

        Arguments:
            tenant_id: The unique identifier of the tenant to update.
            kwargs: Additional tenant attributes to update. These must match
                the fields of the tenant data model.

        Returns:
            The updated tenant object as an instance of TenantInDB if the
            update is successful, or None if no tenant was found with the
            given tenant_id.

        Raises:
            This function does not explicitly raise errors, but errors may
            propagate from internal repository methods.
        """
        tenant_update = await self.tenant_repository.update(tenant_id, **kwargs)
        return TenantResponseDTO.model_validate(tenant_update)

    async def deactivate_tenant(self, tenant_id: str) -> Optional[TenantResponseDTO]:
        """
        Deactivate a tenant by setting its active status to False.

        Summary:
        This asynchronous method is used to deactivate a specific tenant within the
        system by updating their active status to False.

        Args:
            tenant_id (str): The unique identifier of the tenant to be deactivated.

        Returns:
            Optional[TenantInDB]: The updated tenant object if successful, or None if
            the tenant does not exist.
        """
        tenant_deactivated = await self.tenant_repository.update(tenant_id, is_active=False)
        return TenantResponseDTO.model_validate(tenant_deactivated)

    async def activate_tenant(self, tenant_id: str) -> Optional[TenantResponseDTO]:
        """
        Activates a tenant in the system by updating its active status to True.

        Parameters:
        tenant_id (str): The unique identifier of the tenant to be activated.

        Returns:
        Optional[TenantInDB]: The updated tenant object if the activation is successful,
        or None if the update fails.
        """
        tenant_activated = await self.tenant_repository.update(tenant_id, is_active=True)
        return TenantResponseDTO.model_validate(tenant_activated)

    async def delete_tenant(self, tenant_id: str) -> bool:
        """
        Deletes a tenant by its unique identifier.

        This asynchronous method interacts with the tenant repository to
        remove a tenant record corresponding to the provided tenant ID.

        Parameters:
        tenant_id (str): The unique identifier of the tenant to be deleted.

        Returns:
        bool: True if the tenant was successfully deleted, otherwise False.
        """
        return await self.tenant_repository.delete(tenant_id)

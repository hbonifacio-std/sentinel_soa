"""
Tenant repository port definition.

Defines the interface for tenant persistence operations.
Supports both multi-tenancy and telemetry client authentication.
"""

from abc import ABC, abstractmethod
from typing import Optional, List

from core_orchestrator.domain.entities.auth.tenant import Tenant, ProviderAIConfig


class TenantRepositoryPort(ABC):
    """
    An abstract base class representing a repository interface for managing Tenant data.

    This class defines the blueprint for operations related to Tenant management, such as
    retrieving, creating, updating, and deleting Tenant instances. It also includes methods
    for ensuring indexes and managing API keys. Subclasses must implement all abstract methods.
    """

    @abstractmethod
    async def get(self, tenant_id: str) -> Optional[Tenant]:
        """
        An abstract class method that retrieves a Tenant object for a given tenant ID.

        Parameters:
            tenant_id (str): The unique identifier for the tenant.

        Returns:
            Optional[Tenant]: A Tenant object if found, otherwise None.
        """
        pass

    @abstractmethod
    async def get_by_api_key_hash(self, api_key_hash: str) -> Optional[Tenant]:
        """
        Abstract method to retrieve a tenant by its API key hash.

        This method is expected to be implemented by subclasses to fetch a tenant
        object based on the provided API key hash. The operation is asynchronous
        and may return None if no matching tenant is found.

        Parameters:
        api_key_hash: str
            The hash of the API key used to identify and retrieve the corresponding
            tenant.

        Returns:
        Optional[Tenant]
            The tenant object associated with the provided API key hash, or None
            if no matching tenant is found.
        """
        pass

    @abstractmethod
    async def get_by_client_id(self, client_id: str, include_inactive: bool = False) -> Optional[Tenant]:
        """
        An abstract method designed to retrieve a Tenant object based on a given
        client ID. This method can optionally include inactive tenants in the
        retrieval process.

        The method is asynchronous and must be implemented by any subclass.

        Parameters:
            client_id (str): The unique identifier associated with the client for
                which the tenant is being retrieved
            include_inactive (bool, optional): A flag indicating whether to include
                inactive tenants in the result. Defaults to False

        Returns:
            Optional[Tenant]: An instance of the Tenant class if found, or None if no
                matching tenant exists.
        """
        pass

    @abstractmethod
    async def get_by_api_key(self, api_key: str) -> Optional[Tenant]:
        """
        An abstract method that retrieves a Tenant instance by its API key.

        This method is designed to be implemented by subclasses,
        providing an asynchronous way to fetch a Tenant object
        associated with the given API key.

        Args:
            api_key (str): The API key used to retrieve the corresponding Tenant.

        Returns:
            Optional[Tenant]: The Tenant instance if found, or None if no Tenant
            matches the provided API key.
        """
        pass

    @abstractmethod
    async def create(
        self, 
        tenant_create: Tenant,
        api_key_hash: str, 
        api_key_plaintext: str
    ) -> Tenant:
        """
        Abstract method to create a new tenant.

        This method is used to create and register a new tenant with the specified
        API key hash and plaintext value.

        Parameters:
        tenant_create: Tenant
            The tenant object containing the details required to create a new tenant.
        api_key_hash: str
            The hashed value of the API key associated with the tenant.
        api_key_plaintext: str
            The plaintext version of the API key for the tenant.

        Returns:
        Tenant
            Returns the newly created tenant instance.
        """
        pass

    @abstractmethod
    async def list_all(self, include_inactive: bool = False) -> List[Tenant]:
        """
        An abstract method to list all tenants, with an option to include inactive tenants.

        Arguments:
        include_inactive (bool): A flag indicating whether inactive tenants should be included
            in the returned list. Defaults to False.

        Returns:
        List[Tenant]: A list of tenant instances.
        """
        pass

    @abstractmethod
    async def update(self, tenant_id: str, **kwargs) -> Optional[Tenant]:
        """
        An abstract method that defines the blueprint for updating tenant data.

        The method is expected to be implemented in derived classes to provide specific
        logic for updating tenant information based on a provided tenant ID and additional
        keyword arguments.

        Parameters:
            tenant_id: str
                The unique identifier of the tenant to be updated.
            **kwargs
                Arbitrary additional data that might be required for updating the tenant.

        Returns:
            Optional[Tenant]: Returns an updated tenant object if the operation is
            successful, otherwise None.
        """
        pass

    @abstractmethod
    async def delete(self, tenant_id: str) -> bool:
        """
        Defines an abstract method for implementing tenant deletion functionality. This method
        must be overridden by subclasses to provide specific deletion logic for a tenant
        associated with the given tenant_id.

        Arguments:
            tenant_id (str): Unique identifier of the tenant to be deleted.

        Returns:
            bool: True if the tenant was successfully deleted, False otherwise.

        Raises:
            Exception: The implementation may raise any exception related to the deletion process.
        """
        pass

    @abstractmethod
    async def ensure_indexes(self) -> None:
        """
        An abstract method that ensures all necessary indexes are created in the
        underlying database or storage system. This method must be implemented
        by subclasses to provide specific logic for managing indexes.

        Returns:
            None: This method does not return any value but rather ensures that
            required indexes exist in the system.
        """
        pass

    @abstractmethod
    async def set_default_mongo_translator_model(self, client_id: str, model_id: Optional[str]) -> Optional[Tenant]:
        """
        Asynchronously sets the default MongoDB translator model for a specific client.

        This method updates the default translating model associated with a given client, identified
        by its client ID. If the model ID is provided, it will be set as the new default. The operation
        will return an updated `Tenant` object representing the client and its default model, or None if
        the action fails or no applicable client is found.

        Parameters:
        client_id: str
            The unique identifier for the client whose default translator model is being updated.

        model_id: Optional[str]
            The unique identifier for the MongoDB translator model to set as default. If None, the
            current default will be removed or no changes will be applied.

        Returns:
        Optional[Tenant]
            Returns an updated Tenant object with the newly set default model, or None if no changes
            were applied or the client was not found.
        """
        pass

    @abstractmethod
    async def set_default_log_analysis_model(self, client_id: str, model_id: Optional[str]) -> Optional[Tenant]:
        """
        Sets the default log analysis model for a given client.

        This method asynchronously sets the default model to be used for log analysis
        for a specific client. If the model_id parameter is not provided, it unsets the
        default model for the client. The operation returns an updated Tenant instance
        if successful, or None if no Tenant is associated.

        Args:
            client_id: The unique identifier for the client.
            model_id: The unique identifier for the log analysis model to be set as
                      default. Optional parameter; if None, the default model will
                      be unset.

        Returns:
            An updated Tenant instance if the operation is successful, otherwise None.
        """
        pass

    @abstractmethod
    async def remove_model(self, client_id: str, model_id: str) -> Optional[Tenant]:
        """
        An abstract method for removing a model associated with a specific client.

        Summary:
        This method is responsible for removing a model identified by its ID and associated with
        a given client. It is an asynchronous method and must be implemented by subclasses.

        Args:
            client_id: str
                The unique identifier of the client to which the model belongs.
            model_id: str
                The unique identifier of the model to be removed.

        Returns:
            Optional[Tenant]
                An optional tenant object, which will be returned if the removal process involves any
                tenant-specific information. Otherwise, None is returned.
        """
        pass

    @abstractmethod
    async def update_model(self, client_id: str, model_id: str, model_def: dict) -> Optional[Tenant]:
        pass

    @abstractmethod
    async def remove_provider(self, client_id: str, provider_name: str) -> Optional[Tenant]:
        pass

    @abstractmethod
    async def update_provider(self, client_id: str, provider_name: str, provider_def: ProviderAIConfig) -> Optional[Tenant]:
        pass

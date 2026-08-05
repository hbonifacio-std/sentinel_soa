"""
MongoDB implementation of the tenant repository.
"""

import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import List, Optional, Any
from core_orchestrator.domain.entities.auth.tenant import Tenant, ProviderAIConfig
from core_orchestrator.infrastructure.adapters.helper.map_to_dataclass import map_to_dataclass
from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
from core_orchestrator.domain.ports.auth.tenant_repository_port import TenantRepositoryPort


logger = logging.getLogger(__name__)


class MongoTenantRepositoryAdapter(TenantRepositoryPort):
    """
    Handles tenant data management and operations in the MongoDB database.

    This class provides methods to interact with the tenant collection in the database,
    allowing for creation, retrieval, updating, and deletion of tenant entities. It also
    provides functionality to manage AI provider configurations, model definitions, and
    other tenant-related attributes.
    """

    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager
        self.collection = db_manager.get_auth_db()["authorized_telemetry_clients"]

    async def get(self, tenant_id: str) -> Optional[Tenant]:
        tenant_doc = await self.collection.find_one({"client_id": tenant_id})
        if tenant_doc:
            return map_to_dataclass(Tenant, tenant_doc)
        return None

    async def get_by_api_key_hash(self, api_key_hash: str) -> Optional[Tenant]:
        """
        Retrieve a tenant document by the API key hash.

        This asynchronous method queries the database to find a tenant that matches
        the provided API key hash. If a matching tenant is found, an instance of
        the `Tenant` class is returned based on the document. Otherwise, it returns `None`.

        Parameters:
        api_key_hash (str): The hashed value of the API key to search for in the database.

        Returns:
        Optional[Tenant]: The tenant instance if a matching document is found, otherwise None.
        """
        tenant_doc = await self.collection.find_one({"api_key_hash": api_key_hash})
        if tenant_doc:
            return map_to_dataclass(Tenant, tenant_doc)
        return None

    async def get_by_client_id(self, client_id: str, include_inactive: bool = False) -> Optional[Tenant]:
        """
        Fetches a tenant document by its associated client ID.

        This asynchronous method retrieves a tenant document from the database
        based on the provided client ID. It provides an option to include or exclude
        inactive tenants in the search results. If a tenant document is found, it is
        deserialized into a Tenant object.

        Parameters:
        client_id: str
            The unique identifier for the client whose tenant record is being
            retrieved.
        include_inactive: bool, optional
            A flag indicating whether to include inactive tenants in the search
            results. Defaults to False.

        Returns:
        Optional[Tenant]
            A Tenant object if a matching tenant document is found, otherwise None.
        """
        query: dict[str, Any] = {"client_id": client_id,}
        if not include_inactive:
            query["is_active"] = True
        
        tenant_doc = await self.collection.find_one(query)
        if tenant_doc:
            return map_to_dataclass(Tenant, tenant_doc)
        return None

    async def get_by_api_key(self, api_key: str) -> Optional[Tenant]:
        """
        Retrieves an active tenant based on the provided API key.

        This asynchronous method searches for a tenant in the database whose API key matches the
        provided value and whose 'is_active' status is set to True. If a matching tenant is found,
        it returns a Tenant instance initialized with the retrieved data. Otherwise, it returns None.

        Parameters:
            api_key (str): The API key is used to identify the tenant.

        Returns:
            Optional[Tenant]: A Tenant object if a matching active tenant is found, otherwise None.
        """
        tenant_doc = await self.collection.find_one({
            "api_key": api_key,
            "is_active": True
        })
        if tenant_doc:
            return map_to_dataclass(Tenant, tenant_doc)
        return None

    async def create(
        self, 
        tenant_create: Tenant,
        api_key_hash: str, 
        api_key_plaintext: str
    ) -> Tenant:
        """
        Creates a new tenant in the database and returns the created tenant object.

        The function is responsible for creating a tenant document based on the provided
        `tenant_create` input. It stores the generated tenant record in the database and
        logs the creation event. This function ensures default values for certain attributes
        if they are not specified in the input.

        Parameters:
            tenant_create (Tenant): The `Tenant` object containing the details of the tenant to be created
            api_key_hash (str): The hashed representation of the API key for the tenant
            api_key_plaintext (str): The plaintext version of the API key for the tenant

        Returns:
            Tenant: The newly created tenant object based on the stored document.
        """
        tenant_create.api_key_hash = api_key_hash
        tenant_create.api_key_plaintext = api_key_plaintext

        await self.collection.insert_one(asdict(tenant_create))
        logger.info(f"Tenant created: {tenant_create.client_id} ({tenant_create.display_name})")

        return tenant_create

    async def list_all(self, include_inactive: bool = False) -> List[Tenant]:
        """
        Fetches a list of all tenants from the database with options to include or exclude inactive tenants.

        Parameters:
        include_inactive (bool): When set to True, includes both active and inactive tenants.
                                Defaults too False to fetch only active tenants.

        Returns:
        List[Tenant]: A list of Tenant objects retrieved from the database.

        """
        query = {} if include_inactive else {"is_active": True}
        cursor = self.collection.find(query)
        tenants = await cursor.to_list(length=None)
        return [map_to_dataclass(Tenant, doc) for doc in tenants]

    async def update(self, tenant_id: str, **kwargs) -> Optional[Tenant]:
        """
        Updates the tenant information with the provided data.

        If no additional keyword arguments are provided, the method retrieves
        the existing tenant information without making any updates.

        Args:
            tenant_id (str): The unique identifier of the tenant to update.
            **kwargs: Arbitrary keyword arguments representing the fields to
                update along with their new values.

        Returns:
            Optional[Tenant]: The updated tenant object if the update is
                successful, otherwise None.
        """
        if not kwargs:
            return await self.get(tenant_id)

        kwargs["updated_at"] = datetime.now(timezone.utc)
        
        result = await self.collection.find_one_and_update(
            {"client_id": tenant_id},
            {"$set": kwargs},
            return_document=True
        )
        
        if result:
            return map_to_dataclass(Tenant, result)
        return None

    async def delete(self, tenant_id: str) -> bool:
        """
        Deletes a tenant by its unique identifier.

        This method attempts to delete a single tenant document from the database
        collection using the provided tenant ID. If the deletion is successful,
        it logs the event and returns True. Otherwise, it returns False.

        Parameters:
        tenant_id (str): The unique identifier of the tenant to be deleted.

        Returns:
        bool: True if the tenant was successfully deleted; otherwise, False.
        """
        result = await self.collection.delete_one({"client_id": tenant_id})
        if result.deleted_count > 0:
            logger.info(f"Tenant deleted: {tenant_id}")
            return True
        return False

    async def ensure_indexes(self) -> None:
        """
        Ensures that the necessary indexes are created on the associated database collection. This method
        is used to improve query performance and enforce uniqueness constraints where applicable.

        Raises:
            OperationalError: If creating indexes on the database fails.
        """
        await self.collection.create_index("client_id", unique=True)
        await self.collection.create_index([("client_id", 1), ("ai_providers.provider", 1)])

    async def update_provider(self, client_id: str,provider_config:ProviderAIConfig) -> Optional[Tenant]:
        """
        Updates the AI provider configuration for a tenant in the database.

        This method updates the existing provider configuration for a specific client
        ID by first removing the current configuration of the specified provider and
        then adding the new configuration. If the operation is successful, the updated
        tenant object is returned; otherwise, None is returned.

        Parameters:
            client_id (str): The unique identifier of the client for which the provider
                configuration is being updated
            provider_config (ProviderAIConfig): The new provider configuration to be applied. It
                must contain the key "provider" indicating the provider's name.

        Returns:
            Optional[Tenant]: An updated tenant instance if the operation is
                successful, or None if the client ID is not found.
        """
        now = datetime.now(timezone.utc)
        # Pull existing provider configuration if present
        provider_name = provider_config.provider
        provider_dict = asdict(provider_config)
        await self.collection.update_one(
            {"client_id": client_id},
            {"$pull": {"ai_providers": {"provider": provider_name}}}
        )
        # Push new provider configuration
        result = await self.collection.find_one_and_update(
            {"client_id": client_id},
            {
                "$push": {"ai_providers": provider_dict},
                "$set": {"updated_at": now}
            },
            return_document=True
        )
        if result:
            return map_to_dataclass(Tenant, result)
        return None

    async def remove_provider(self, client_id: str, provider_name: str) -> Optional[Tenant]:
        """
        Removes a specific AI provider from a tenant's configuration.

        This asynchronous method removes the specified provider from the list of AI providers
        associated with the tenant identified by the given client ID. It also removes any models
        associated with the specified provider and updates the tenant's configuration
        accordingly, including adjusting the default log analysis model if necessary.

        Parameters:
        client_id: str
            The unique identifier for the tenant from which the provider is to be removed.
        provider_name: str
            The name of the provider to remove from the tenant's configuration.

        Returns:
        Optional[Tenant]
            The updated tenant object after successfully removing the provider, or None if the
            tenant is not found.

        Raises:
            This method may raise exceptions from underlying database or data access layers.
        """
        now = datetime.now(timezone.utc)
        tenant = await self.get(client_id)
        if not tenant:
            return None

        new_models = {
            mid: model_definition.__dict__ for mid, model_definition in tenant.available_models.items()
            if model_definition.provider != provider_name
        }
        new_default = tenant.default_log_analysis_model_id
        if new_default and new_default not in new_models:
            new_default = None

        result = await self.collection.find_one_and_update(
            {"client_id": client_id},
            {
                "$pull": {"ai_providers": {"provider": provider_name}},
                "$set": {
                    "available_models": new_models,
                    "default_log_analysis_model_id": new_default,
                    "updated_at": now
                }
            },
            return_document=True
        )
        if result:
            return map_to_dataclass(Tenant, result)
        return None

    async def update_model(self, client_id: str, model_id:str, model_def: dict) -> Optional[Tenant]:
        """
        Updates the model definition for the specified client and model ID.

        This asynchronous method updates the specified model's definition
        within the available models of the given client in the database. It
        also updates the `updated_at` timestamp to reflect the change. If
        successful, the updated tenant data is returned.

        Arguments:
            client_id: The unique identifier of the client whose model is to
                be updated.
            model_id: The unique identifier of the model to update.
            model_def: A dictionary representing the updated definition of
                the model.

        Returns:
            An instance of `Tenant` representing the updated tenant data if
            the update is successful, or `None` if the update failed.
        """
        now = datetime.now(timezone.utc)
        model_data = {**model_def, "model_id": model_id}
        result = await self.collection.find_one_and_update(
            {"client_id": client_id},
            {
                "$set": {
                    f"available_models.{model_id}": model_data,
                    "updated_at": now
                }
            },
            return_document=True
        )
        if result:
            return map_to_dataclass(Tenant, result)
        return None

    async def remove_model(self, client_id: str, model_id: str) -> Optional[Tenant]:
        """
        Removes a model associated with a given client from the available models list and updates
        the default log analysis model if it matches the specified model ID. The operation ensures
        the database integrity by unsetting the model and updating the timestamp of the modification.

        Parameters:
        client_id: str
            The unique identifier of the client whose model will be removed.
        model_id: str
            The unique identifier of the model to be removed.

        Returns:
        Optional[Tenant]
            Returns an updated Tenant object if the operation is successful. Returns None if the
            client does not exist or the model removal fails.
        """
        now = datetime.now(timezone.utc)
        tenant = await self.get(client_id)
        if not tenant:
            return None

        new_default = tenant.default_log_analysis_model_id
        if new_default == model_id:
            new_default = None

        result = await self.collection.find_one_and_update(
            {"client_id": client_id},
            {
                "$unset": {f"available_models.{model_id}": ""},
                "$set": {
                    "default_log_analysis_model_id": new_default,
                    "updated_at": now
                }
            },
            return_document=True
        )
        if result:
            return map_to_dataclass(Tenant, result)
        return None

    async def set_default_log_analysis_model(self, client_id: str, model_id: Optional[str]) -> Optional[Tenant]:
        """
        Sets the default log analysis model for a given client.

        This asynchronous method updates the default log analysis model associated with
        a specified client in the database. If a model ID is provided, it will be set
        as the default. The method also updates the timestamp for when the change
        was made. If the operation is successful, the updated tenant information is
        returned. If no matching client is found, it returns None.

        Arguments:
            client_id (str): The unique identifier of the client for which the default
                log analysis model is being updated
            model_id (Optional[str]): The identifier of the log analysis model is
                set as default. If None, the default will be cleared

        Returns:
            Optional[Tenant]: The updated tenant object if the operation is
                successful, or None if no matching client is found.
        """
        now = datetime.now(timezone.utc)
        result = await self.collection.find_one_and_update(
            {"client_id": client_id},
            {
                "$set": {
                    "default_log_analysis_model_id": model_id,
                    "updated_at": now
                }
            },
            return_document=True
        )
        if result:
            return map_to_dataclass(Tenant, result)
        return None

    async def set_default_mongo_translator_model(self, client_id: str, model_id: Optional[str]) -> Optional[Tenant]:
        """
        Updates the default MongoDB translator model for a specified client.

        This asynchronous method updates the default translator model associated with a
        given client ID in the MongoDB collection and sets the current UTC timestamp
        as the update time. If the update is successful, it returns a Tenant object
        created from the updated document; otherwise, it returns None.

        Parameters:
        client_id: str
            The unique identifier of the client whose default translator model is
            being updated.
        model_id: Optional[str]
            The unique identifier of the translator model to be set as default for
            the provided client. Can be None if the default translator model is to
            be unset.

        Returns:
        Optional[Tenant]
            A Tenant object created from the updated MongoDB document if the operation
            succeeds, or None if no matching document is found.
        """
        now = datetime.now(timezone.utc)
        result = await self.collection.find_one_and_update(
            {"client_id": client_id},
            {
                "$set": {
                    "default_mongo_translator_model_id": model_id,
                    "updated_at": now
                }
            },
            return_document=True
        )
        if result:
            return map_to_dataclass(Tenant, result)
        return None

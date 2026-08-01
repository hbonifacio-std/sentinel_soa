import json
import logging
from typing import Optional, Dict, cast

from core_orchestrator.domain.entities.auth.tenant import Tenant, TenantModelAIDefinition, ProviderAIConfig, \
    ProviderType, VALID_PROVIDERS
from core_orchestrator.domain.exceptions.database_exceptions import  DatabaseOperationError
from core_orchestrator.domain.exceptions.domain_exceptions import \
    MongoTranslatorNotConfiguredException, ModelNotFoundError, TenantNotFoundException, ModelNotAvailableException, \
    ModelDisabledException, InvalidProviderException
from core_orchestrator.domain.ports import CacheRepositoryPort
from core_orchestrator.domain.ports.auth.tenant_repository_port import TenantRepositoryPort
from core_orchestrator.domain.ports.auth.api_key_cipher_port import ApiKeyCipherPort
from core_orchestrator.infrastructure.adapters.helper.map_to_dataclass import string_to_dataclass

logger = logging.getLogger(__name__)


class TenantProviderAiService:
    """
    Handles tenant-specific configuration and setup for AI provider services.

    This class provides methods to retrieve, update, and manage tenant configurations
    for AI models and providers. It interfaces with backend services such as a tenant
    repository, a cipher for API key management, and an optional caching layer.
    These configurations enable the system to resolve provider-specific setups
    for tasks such as log analysis, translation, and interactive analysis.

    Attributes:
    tenant_repository: TenantRepositoryPort
        Port responsible for interacting with the tenant repository database.
    cipher: ApiKeyCipherPort
        Port for encrypting and decrypting API keys for secure storage.
    cache: CachePort
        Optional caching interface for improving performance by reducing
        database lookups.
    """

    def __init__(
        self,
        tenant_repository: TenantRepositoryPort,
        cipher: ApiKeyCipherPort,
        cache_repository: CacheRepositoryPort,
    ):
        self._tenant_repo = tenant_repository
        self._cipher = cipher
        self._cache_repository = cache_repository

    async def _get_tenant(self, client_id: str) -> Optional[Tenant]:
        """
        Retrieves a tenant by its client ID, optionally using a cache for optimized retrieval.

        This method first tries to fetch the tenant from a cache repository (if available). If the tenant
        is found in the cache, it will be returned immediately after converting the cached string data
        to the `Tenant` dataclass. If the tenant is not in the cache, it will fetch the tenant from the
        `_tenant_repo`. If a tenant is successfully retrieved from the repository and a cache is enabled,
        the tenant data will be added to the cache for future requests.

        Parameters:
        client_id: str
            The client ID associated with the tenant to be retrieved.

        Returns:
        Optional[Tenant]
            The retrieved tenant object, or None if no tenant exists for the given client ID.
        """
        if self._cache_repository:
            cached = await self._cache_repository.get(client_id)
            if cached:
                return string_to_dataclass(Tenant,cached)

        tenant = await self._tenant_repo.get_by_client_id(client_id)
        if tenant and self._cache_repository:
            await self._cache_repository.set(client_id, json.dumps(tenant))
        return tenant

    async def get_default_provider_config(
            self, client_id: str
    ) -> Optional[TenantModelAIDefinition]:
        """
        Retrieve the default provider configuration for the specified client.

        This asynchronous method retrieves the default log analysis model provider configuration
        associated with a given client ID. If the tenant or default model is not found, it returns None.
        If an exception occurs while fetching the provider configuration, it logs the issue and
        returns None.

        Parameters:
            client_id (str): The unique identifier of the client.

        Returns:
            Optional[TenantModelAIDefinition]: The provider configuration for the default log
            analysis model if available, or None if no configuration can be resolved.

        Raises:
            TenantNotFoundException: If the tenant is associated with the client, ID is not found.
            ModelNotAvailableException: If the requested model is not available.
            ModelDisabledException: If the requested model is disabled.
        """
        tenant = await self._get_tenant(client_id)
        if not tenant or not tenant.default_log_analysis_model_id:
            return None

        try:
            return await self.get_provider_config_for_model(
                client_id=client_id,
                model_id=tenant.default_log_analysis_model_id
            )
        except (TenantNotFoundException, ModelNotAvailableException, ModelDisabledException) as exc:
            logger.warning(f"Failed to resolve default log model for '{client_id}': {exc.message}")
            return None

    async def get_mongo_translator_provider_config(
            self, client_id: str
    ) -> Optional[TenantModelAIDefinition]:
        """
        Retrieves the MongoDB translator provider configuration for a given client.

        The method fetches configuration details related to a MongoDB translator for
        a specified client ID. It validates that a tenant is found for the given
        client ID and that the MongoDB translator is configured for the tenant.

        Args:
            client_id (str): The unique identifier of the client.

        Returns:
            Optional[TenantModelAIDefinition]: The configuration details for the
            MongoDB translator provider if available, otherwise None.

        Raises:
            TenantNotFoundException: If no tenant is found for the provided client ID.
            MongoTranslatorNotConfiguredException: If the MongoDB translator is not
            configured for the tenant.
        """
        tenant = await self._get_tenant(client_id)
        if not tenant:
            raise TenantNotFoundException(client_id)

        if not tenant.default_mongo_translator_model_id:
            raise MongoTranslatorNotConfiguredException(client_id)

        return await self.get_provider_config_for_model(
            client_id=client_id,
            model_id=tenant.default_mongo_translator_model_id
        )

    async def get_provider_config_for_model(self, client_id: str, model_id: str) -> TenantModelAIDefinition:
        """
        Retrieves the provider configuration for a specified model and tenant.

        This method fetches the configuration of an AI model linked to a specific tenant
        (client) after validating the tenant's existence, model availability, and model
        state (enabled or disabled). Raises specific exceptions in cases where the tenant
        is not found, the model is unavailable under the tenant's configuration, or the
        model is disabled.

        Parameters:
            client_id: str
                The unique identifier of the client (tenant) requesting the model configuration.
            model_id: str
                The unique identifier of the model for which the configuration is requested.

        Returns:
            TenantModelAIDefinition
                The provider configuration of the requested model associated with the tenant.

        Raises:
            TenantNotFoundException
                If the tenant with the specified client_id does not exist.
            ModelNotAvailableException
                If the specified model_id is not available for the tenant.
            ModelDisabledException
                If the specified model_id exists but is disabled for the tenant.
        """
        tenant = await self._get_tenant(client_id)
        if not tenant:
            raise TenantNotFoundException(client_id)

        if model_id not in tenant.available_models:
            raise ModelNotAvailableException(model_id, client_id)

        model_def = tenant.available_models[model_id]
        if not model_def.enabled:
            raise ModelDisabledException(model_id, client_id)

        return  self._resolve_provider_config(tenant, model_id)

    async def get_available_models_for_tenant(self, client_id: str) -> Dict[str, TenantModelAIDefinition]:
        """
        Retrieve available models for a specific tenant.

        This asynchronous method retrieves the models available for the tenant
        associated with the provided client identifier. The available models
        are filtered to include only those that are explicitly enabled and return
        an organized dictionary detailing model attributes.

        Parameters:
        client_id: str
            The identifier for the client whose tenant's available models need to
            be retrieved.

        Returns:
        Dict[str, Any]
            A dictionary where keys represent model IDs and values are dictionaries
            containing model attributes such as provider, model name, maximum output
            tokens, and maximum input tokens. Returns an empty dictionary if no
            tenant is found or no enabled models are available.
        """
        tenant = await self._get_tenant(client_id)
        if not tenant:
            return {}

        res = {}
        for mid, model_definition in tenant.available_models.items():
            if model_definition.enabled:
                res[mid] =  model_definition
        return res

    async def add_or_update_provider(
        self,
        client_id: str,
        provider: str,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        enabled: bool = True,
    ) -> Tenant:
        """
        Adds or updates a provider configuration for a tenant.

        This method allows the client to add a new provider configuration or update the
        existing one for a tenant identified by the given client ID. If the API key is not
        provided, the method retrieves an existing encrypted API key from the currently
        configured providers for the tenant. The provider configuration is then updated
        in the repository. If the operation is unsuccessful, an error is raised.
        Additionally, any tenant-specific cache is invalidated if a caching repository
        is configured.

        Raises:
            DatabaseOperationError: If the provider configuration could not be updated
            in the repository.

        Args:
            client_id (str): The unique identifier of the tenant
            provider (str): The name of the provider to be added or updated
            api_key (Optional[str]): The API key for the provider. Defaults to None
            base_url (Optional[str]): The base URL for the provider's API. Defaults to None
            enabled (bool): A flag indicating whether the provider configuration is to
            be active or inactive. Defaults to True

        Returns:
            Tenant: The updated tenant object with the new or modified provider
            configuration.
        """
        encrypted_key = self._cipher.encrypt(api_key) if api_key else None

        if not api_key:
            existing_tenant = await self._tenant_repo.get_by_client_id(client_id)
            if existing_tenant:
                for p in existing_tenant.ai_providers:
                    if p.provider == provider and p.api_key_encrypted:
                        encrypted_key = p.api_key_encrypted
                        break

        if provider not in VALID_PROVIDERS:
            raise InvalidProviderException(provider,VALID_PROVIDERS)

        provider_cfg = ProviderAIConfig(
            provider=cast(ProviderType,provider),
            api_key_encrypted=encrypted_key,
            base_url=base_url,
            enabled=enabled,
        )

        updated = await self._tenant_repo.update_provider(client_id,provider, provider_cfg)
        if not updated:
            raise DatabaseOperationError(f"Failed to update provider for tenant '{client_id}'.")

        if self._cache_repository:
            await self._cache_repository.delete(client_id)
        return updated

    async def remove_provider(self, client_id: str, provider: str) -> Tenant:
        """
        Removes a provider from a tenant's data and updates the tenant repository.

        The method attempts to remove the specified provider associated with the given client ID
        from the tenant data. If the removal is successful and a cache repository is available, it
        will delete the corresponding cache entry for the client ID. If the removal fails, a
        ValueError is raised.

        Parameters:
        client_id: str
            Unique identifier for the tenant whose provider is to be removed.
        provider: str
            The name of the provider to be removed.

        Raises:
        ValueError
            If the provider could not be removed from the tenant data.

        Returns:
        Tenant
            The updated Tenant object after the provider has been successfully removed.
        """
        updated = await self._tenant_repo.remove_provider(client_id, provider)
        if not updated:
            raise DatabaseOperationError(f"Failed to remove provider for tenant '{client_id}'.")
        if self._cache_repository:
            await self._cache_repository.delete(client_id)
        return updated

    async def add_or_update_model(
        self,
        client_id: str,
        model_id: str,
        provider: str,
        model_name: str,
        max_output_tokens: Optional[int] = None,
        max_input_tokens: Optional[int] = None,
        enabled: bool = True,
    ) -> Tenant:
        """
        Updates or adds a model associated with a tenant in the database and handles
        cache invalidation if applicable.

        Parameters:
        client_id : str
            The unique identifier for the tenant.
        model_id : str
            The unique identifier for the model to be updated or added.
        provider : str
            The provider name of the model.
        model_name : str
            The name of the model to be updated or added.
        max_output_tokens : Optional[int]
            The maximum number of tokens that the model can output. Default is None.
        max_input_tokens : Optional[int]
            The maximum number of tokens that the model can accept as input. Default is None.
        enabled : bool
            A boolean indicating if the model should be enabled. Default is True.

        Returns:
        Tenant
            The updated tenant object after adding or updating the model.

        Raises:
        DatabaseOperationError
            If the model fails to update for the specified tenant in the database.
        """
        model_def = {
            "provider": provider,
            "model_name": model_name,
            "max_output_tokens": max_output_tokens,
            "max_input_tokens": max_input_tokens,
            "enabled": enabled,
        }
        updated = await self._tenant_repo.update_model(client_id, model_id, model_def)
        if not updated:
            raise DatabaseOperationError(f"Failed to update model for tenant '{client_id}'.")
        if self._cache_repository:
            await self._cache_repository.delete(client_id)
        return updated

    async def remove_model(self, client_id: str, model_id: str) -> Tenant:
        """
        Asynchronously removes a model associated with a given client identifier.

        This method coordinates the removal of a specific model tied to a client's
        account. If the operation fails or cannot identify the model, a `ValueError`
        exception is raised. Additionally, it handles cache invalidation for the
        specified client if a cache repository is configured.

        Parameters:
            client_id: str
                The unique identifier of the client whose model should be removed.
            model_id: str
                The unique identifier of the model to be removed.

        Returns:
            Tenant
                The updated tenant entity after the model is removed.

        Raises:
            ValueError
                If the model removal operation fails.
        """
        updated = await self._tenant_repo.remove_model(client_id, model_id)
        if not updated:
            raise ValueError(f"Failed to remove model for tenant '{client_id}'.")
        if self._cache_repository:
            await self._cache_repository.delete(client_id)
        return updated

    async def set_default_log_analysis_model(self, client_id: str, model_id: Optional[str]) -> Tenant:
        """
        Sets the default log analysis model for a specified client.

        This method is used to set or update the default log analysis model for a tenant's
        log analysis settings. It ensures that the specified model is available in the
        tenant's configuration before updating it in the repository. If the operation is
        successful, the tenant's cache is updated to reflect the new model configuration.

        Parameters:
        client_id: str
            The unique identifier of the client (tenant) for which the default log analysis
            model is being set.
        model_id: Optional[str]
            The ID of the model to set as the default. If not provided, the default model
            will be cleared.

        Returns:
        Tenant
            The updated tenant object with the new default log analysis model.

        Raises:
        ValueError
            If the provided model ID is not configured in the tenant's"""
        if model_id:
            tenant = await self._get_tenant(client_id)
            if not tenant or model_id not in tenant.available_models:
                raise ValueError(f"Model '{model_id}' is not configured in available_models for tenant '{client_id}'.")

        updated = await self._tenant_repo.set_default_log_analysis_model(client_id, model_id)
        if not updated:
            raise DatabaseOperationError(f"Failed to set default log analysis model for tenant '{client_id}'.")
        if self._cache_repository:
            await self._cache_repository.delete(client_id)
        return updated

    async def set_default_mongo_translator_model(self, client_id: str, model_id: Optional[str]) -> Tenant:
        """
        Sets a default mongo translator model for a tenant.

        This method updates the default mongo translator model for a specific tenant
        based on the provided client ID and model ID. If a valid model ID is provided,
        it checks if the model is part of the tenant's available models. If the
        operation succeeds, it optionally invalidates the cache for the tenant if
        cache support is enabled.

        Parameters:
        client_id: str
            The unique identifier of the tenant for which the default mongo translator
            model is to be set.

        model_id: Optional[str]
            The ID of the model to be set as the default translator model for the
            tenant. If None, the existing default is unset and no model is selected
            as default.

        Returns:
        Tenant
            The updated tenant object representing the tenant after setting the default
            mongo translator model.

        Raises:
        ValueError
            If the specified model ID is not part of the tenant's available models or
            if the update operation fails.

        """
        if model_id:
            tenant = await self._get_tenant(client_id)
            if not tenant or model_id not in tenant.available_models:
                raise MongoTranslatorNotConfiguredException(f"Model '{model_id}' is not configured in available_models for tenant '{client_id}'.")

        updated = await self._tenant_repo.set_default_mongo_translator_model(client_id, model_id)
        if not updated:
            raise DatabaseOperationError(f"Failed to set default mongo translator model for tenant '{client_id}'.")
        if self._cache_repository:
            await self._cache_repository.delete(client_id)
        return updated

    @staticmethod
    def _resolve_provider_config(tenant: Tenant, model_id: str) -> TenantModelAIDefinition:
        """
        Resolves the configuration for a specific AI provider for the given tenant and model ID.

        The method identifies the appropriate AI provider configuration based on the provided tenant and
        model ID. It verifies the availability and enabled status of the AI provider and retrieves
        the necessary details such as API key, base URL, model name, and token limits. An error is raised
        if the provider is not enabled or configured for the specified tenant.

        Parameters:
            tenant (Tenant): The tenant object representing the client that owns the model definition
            model_id (str): The identifier of the model for which the provider configuration is to
                be resolved.

        Returns:
            Dict[str, Any]: A dictionary containing the provider configuration information,
            including the provider name, API key, base URL, model name, token limits,
            and model ID.

        Raises:
            ValueError: If the provider is not enabled or configured for the given tenant.
        """
        available_models = tenant.available_models[model_id]
        provider_conf = next(
            (p for p in tenant.ai_providers if p.provider == available_models.provider), None
        )
        if not provider_conf or not provider_conf.enabled:
            raise ModelNotFoundError(f"Provider '{available_models.provider}' is not enabled or configured for tenant '{tenant.client_id}'.")

        return available_models

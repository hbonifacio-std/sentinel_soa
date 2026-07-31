import json
import logging
from typing import Optional, Dict, Any

from redis.asyncio import Redis

from core_orchestrator.domain.entities.auth.tenant import Tenant, ProviderAIConfig
from core_orchestrator.domain.ports.auth.tenant_repository_port import TenantRepositoryPort
from core_orchestrator.domain.ports.auth.api_key_cipher_port import ApiKeyCipherPort

logger = logging.getLogger(__name__)


class TenantProviderService:
    """Service to handle tenant AI provider credentials, model selection, and override resolution."""

    def __init__(
        self,
        tenant_repository: TenantRepositoryPort,
        cipher: ApiKeyCipherPort,
        cache: Optional[Redis],
    ):
        self._tenant_repo = tenant_repository
        self._cipher = cipher
        self._cache = cache

    async def _get_tenant(self, client_id: str) -> Optional[Tenant]:
        """Fetch tenant either from cache or Mongo DB repository."""
        if self._cache:
            cached = await self._cache.get(client_id)
            if cached:
                return Tenant(**cached)

        tenant = await self._tenant_repo.get_by_client_id(client_id)
        if tenant and self._cache:
            await self._cache.set(client_id, json.dumps(tenant))
        return tenant

    async def get_default_provider_config(self, client_id: str) -> Optional[ProviderAIConfig]:
        """
        Fetches the default provider configuration for the specified client.

        This method retrieves the default configuration for log analysis models associated
        with a tenant identified by the given client ID. If the client ID is invalid, the
        corresponding tenant does not exist, or if no default model is configured or
        available, the method returns None.

        Parameters:
        client_id: str
            The unique identifier of the client for whom the provider configuration
            needs to be retrieved.

        Returns:
        Optional[ProviderAIConfig]
            The provider configuration for the default log analysis model, or None if
            no valid configuration can be resolved.

        Raises:
            This method does not explicitly raise any exceptions but can propagate
            exceptions from internal calls to `_get_tenant` and `_resolve_provider_config`.
        """
        if not client_id:
            return None

        tenant = await self._get_tenant(client_id)
        if not tenant or not tenant.default_log_analysis_model_id:
            return None

        model_id = tenant.default_log_analysis_model_id
        if model_id not in tenant.available_models:
            logger.warning(f"Default model '{model_id}' not found in available_models for tenant '{client_id}'")
            return None

        return await self._resolve_provider_config(tenant, model_id)

    async def get_mongo_translator_provider_config(self, client_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the MongoDB translator provider configuration for a given client ID.

        This asynchronous method fetches the tenant configuration associated with the given
        `client_id` and resolves the appropriate MongoDB translator provider configuration,
        if available. It ensures that the requested translation model exists within the
        tenant's available models and resolves the configuration accordingly.

        Parameters:
            client_id (str): The identifier of the client for which the MongoDB translator
            configuration is to be retrieved.

        Returns:
            Optional[Dict[str, Any]]: The resolved MongoDB translator provider configuration
            as a dictionary if a valid configuration exists, or None if no valid configuration
            is found.
        """
        if not client_id:
            return None

        tenant = await self._get_tenant(client_id)
        if not tenant or not tenant.default_mongo_translator_model_id:
            return None

        model_id = tenant.default_mongo_translator_model_id
        if model_id not in tenant.available_models:
            logger.warning(f"Mongo translator model '{model_id}' not found in available_models for tenant '{client_id}'")
            return None

        return await self._resolve_provider_config(tenant, model_id)

    async def get_provider_config_for_model(
        self, client_id: str, model_id: str
    ) -> Dict[str, Any]:
        """
        Flow 2: Forensic Chat / Interactive Analysis.
        Resolves decrypted provider config for a requested model_id selected by the user.
        Raises ValueError if tenant does not exist or model is not enabled for the tenant.
        """
        tenant = await self._get_tenant(client_id)
        if not tenant:
            raise ValueError(f"Tenant '{client_id}' not found.")

        if model_id not in tenant.available_models:
            raise ValueError(f"Model '{model_id}' is not enabled for tenant '{client_id}'.")

        model_def = tenant.available_models[model_id]
        if not model_def.enabled:
            raise ValueError(f"Model '{model_id}' is disabled for tenant '{client_id}'.")

        return await self._resolve_provider_config(tenant, model_id)

    async def get_available_models_for_tenant(self, client_id: str) -> Dict[str, Any]:
        """
        Lists enabled entities for tenant frontend model pickers.
        Excludes sensitive API keys.
        """
        tenant = await self._get_tenant(client_id)
        if not tenant:
            return {}

        res = {}
        for mid, mdef in tenant.available_models.items():
            if mdef.enabled:
                res[mid] = {
                    "provider": mdef.provider,
                    "model_name": mdef.model_name,
                    "max_output_tokens": mdef.max_output_tokens,
                    "max_input_tokens": mdef.max_input_tokens,
                }
        return res

    async def add_or_update_provider(
        self,
        client_id: str,
        provider: str,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        enabled: bool = True,
    ) -> Tenant:
        """Add or update an AI provider entry for a tenant."""
        encrypted_key = self._cipher.encrypt(api_key) if api_key else None

        if not api_key:
            existing_tenant = await self._tenant_repo.get_by_client_id(client_id)
            if existing_tenant:
                for p in existing_tenant.ai_providers:
                    if p.provider == provider and p.api_key_encrypted:
                        encrypted_key = p.api_key_encrypted
                        break

        provider_cfg = {
            "provider": provider,
            "api_key_encrypted": encrypted_key,
            "base_url": base_url,
            "enabled": enabled,
        }

        updated = await self._tenant_repo.update_provider(client_id, provider_cfg)
        if not updated:
            raise ValueError(f"Failed to update provider for tenant '{client_id}'.")

        if self._cache:
            await self._cache.invalidate(client_id)
        return updated

    async def remove_provider(self, client_id: str, provider: str) -> Tenant:
        """Remove a provider from tenant configuration."""
        updated = await self._tenant_repo.remove_provider(client_id, provider)
        if not updated:
            raise ValueError(f"Failed to remove provider for tenant '{client_id}'.")
        if self._cache:
            await self._cache.invalidate(client_id)
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
        """Add or update a model in tenant available entities dictionary."""
        model_def = {
            "provider": provider,
            "model_name": model_name,
            "max_output_tokens": max_output_tokens,
            "max_input_tokens": max_input_tokens,
            "enabled": enabled,
        }
        updated = await self._tenant_repo.update_model(client_id, model_id, model_def)
        if not updated:
            raise ValueError(f"Failed to update model for tenant '{client_id}'.")
        if self._cache:
            await self._cache.invalidate(client_id)
        return updated

    async def remove_model(self, client_id: str, model_id: str) -> Tenant:
        """Remove a model from tenant available entities."""
        updated = await self._tenant_repo.remove_model(client_id, model_id)
        if not updated:
            raise ValueError(f"Failed to remove model for tenant '{client_id}'.")
        if self._cache:
            await self._cache.invalidate(client_id)
        return updated

    async def set_default_log_analysis_model(self, client_id: str, model_id: Optional[str]) -> Tenant:
        """Set tenant default model for automated log analysis."""
        if model_id:
            tenant = await self._get_tenant(client_id)
            if not tenant or model_id not in tenant.available_models:
                raise ValueError(f"Model '{model_id}' is not configured in available_models for tenant '{client_id}'.")

        updated = await self._tenant_repo.set_default_log_analysis_model(client_id, model_id)
        if not updated:
            raise ValueError(f"Failed to set default log analysis model for tenant '{client_id}'.")
        if self._cache:
            await self._cache.invalidate(client_id)
        return updated

    async def set_default_mongo_translator_model(self, client_id: str, model_id: Optional[str]) -> Tenant:
        """Set tenant default model for NLQ to MongoDB query translation."""
        if model_id:
            tenant = await self._get_tenant(client_id)
            if not tenant or model_id not in tenant.available_models:
                raise ValueError(f"Model '{model_id}' is not configured in available_models for tenant '{client_id}'.")

        updated = await self._tenant_repo.set_default_mongo_translator_model(client_id, model_id)
        if not updated:
            raise ValueError(f"Failed to set default mongo translator model for tenant '{client_id}'.")
        if self._cache:
            await self._cache.invalidate(client_id)
        return updated

    async def _resolve_provider_config(self, tenant: Tenant, model_id: str) -> Dict[str, Any]:
        """Resolves raw decrypted provider configuration for MCP tool execution."""
        model_def = tenant.available_models[model_id]
        provider_conf = next(
            (p for p in tenant.ai_providers if p.provider == model_def.provider), None
        )
        if not provider_conf or not provider_conf.enabled:
            raise ValueError(f"Provider '{model_def.provider}' is not enabled or configured for tenant '{tenant.client_id}'.")

        api_key = None
        if provider_conf.api_key_encrypted:
            api_key = self._cipher.decrypt(provider_conf.api_key_encrypted)

        return {
            "provider": model_def.provider,
            "api_key": api_key,
            "base_url": provider_conf.base_url,
            "model_name": model_def.model_name,
            "max_output_tokens": model_def.max_output_tokens,
            "max_input_tokens": model_def.max_input_tokens,
            "model_id": model_id,
        }

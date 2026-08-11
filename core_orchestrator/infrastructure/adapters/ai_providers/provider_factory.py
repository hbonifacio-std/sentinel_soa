from typing import Dict, Type

from core_orchestrator.domain.entities.auth.tenant import ProviderAIConfig, TenantModelAIDefinition
from core_orchestrator.domain.ports.agent.ai_providers import AiProvider
from core_orchestrator.domain.ports.auth.api_key_cipher_port import ApiKeyCipherPort
from core_orchestrator.infrastructure.adapters.ai_providers.gemini_provider_adapter import GeminiProviderAdapter
from core_orchestrator.infrastructure.adapters.ai_providers.groq_provider_adapter import GroqProviderAdapter
from core_orchestrator.infrastructure.adapters.ai_providers.ollama_provider_adapter import OllamaProviderAdapter
from core_orchestrator.infrastructure.adapters.ai_providers.opeai_provider_adapter import OpenAiProviderAdapter


class ProviderFactory:
    """Instancia y configura los proveedores de IA concretos basándose en la configuración del Tenant."""
    _PROVIDERS: Dict[str, Type[AiProvider]] = {
        "openai": OpenAiProviderAdapter,
        "gemini": GeminiProviderAdapter,
        "ollama": OllamaProviderAdapter,
        "groq": GroqProviderAdapter,
    }

    def __init__(self, cipher_adapter: ApiKeyCipherPort):
        self.cipher_adapter = cipher_adapter

    @classmethod
    def register_provider(cls, provider_type: str, adapter_cls: Type[AiProvider]) -> None:
        """Permite registrar nuevos adaptadores externamente sin modificar el código fuente."""
        cls._PROVIDERS[provider_type.lower()] = adapter_cls

    def create_provider(
        self,
        provider_config: ProviderAIConfig,
        model_definition: TenantModelAIDefinition,
    ) -> AiProvider:
        provider_type = provider_config.provider.lower()
        adapter_cls = self._PROVIDERS.get(provider_type)

        if not adapter_cls:
            raise ValueError(f"Unsupported provider: '{provider_type}'")

        api_key_encrypted = provider_config.api_key_encrypted or ""
        api_key_plaintext = self.cipher_adapter.decrypt(
            api_key_encrypted
        )

        return adapter_cls(
            model_name=model_definition.model_name,
            api_key=api_key_plaintext,
            max_output_tokens=model_definition.max_output_tokens,
            base_url=provider_config.base_url
        )
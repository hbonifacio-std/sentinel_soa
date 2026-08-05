import pytest
from unittest.mock import AsyncMock, Mock

from core_orchestrator.domain.entities.auth.tenant import ProviderAIConfig, TenantModelAIDefinition
from core_orchestrator.application.modules.auth_clients.tenant_provider_ai_service import TenantProviderAiService


def _build_test_tenant(client_id: str = "acme"):
    return TenantInDB(
        client_id=client_id,
        display_name="Acme Corp",
        ai_providers=[
            ProviderAIConfig(
                provider="groq",
                api_key_encrypted="enc_secret_key",
                enabled=True,
            )
        ],
        available_models={
            "groq-llama": TenantModelAIDefinition(
                provider="groq",
                model_name="llama-3.3-70b-versatile",
                max_output_tokens=12000,
                enabled=True,
            )
        },
        default_log_analysis_model_id="groq-llama",
    )


@pytest.mark.asyncio
async def test_get_default_provider_config_success():
    repo = AsyncMock()
    cipher = Mock()
    cipher.decrypt.return_value = "gsk_decrypted_key"
    cache = AsyncMock()
    cache.get.return_value = None

    tenant = _build_test_tenant("acme")
    repo.get_by_client_id.return_value = tenant

    service = TenantProviderAiService(tenant_repository=repo, cipher=cipher, cache_repository=cache)
    config = await service.get_default_provider_config("acme")

    assert config is not None
    assert config["provider"] == "groq"
    assert config["api_key"] == "gsk_decrypted_key"
    assert config["model_name"] == "llama-3.3-70b-versatile"
    assert config["model_id"] == "groq-llama"


@pytest.mark.asyncio
async def test_get_provider_config_for_model_raises_if_not_enabled():
    repo = AsyncMock()
    cipher = Mock()
    cache = AsyncMock()
    cache.get.return_value = None

    tenant = _build_test_tenant("acme")
    repo.get_by_client_id.return_value = tenant

    service = TenantProviderAiService(tenant_repository=repo, cipher=cipher, cache_repository=cache)

    with pytest.raises(ValueError, match="not enabled"):
        await service.get_provider_config_for_model("acme", "non-existent-model")

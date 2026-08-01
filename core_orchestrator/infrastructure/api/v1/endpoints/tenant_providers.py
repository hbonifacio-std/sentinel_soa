"""Tenant AI Provider management endpoints for Admin users."""

import logging
from typing import Annotated, Optional, List, Literal
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from core_orchestrator.domain.entities.auth.user import UserInDB
from core_orchestrator.application.modules.auth_clients.services.tenant_provider_ai_service import TenantProviderAiService
from core_orchestrator.infrastructure.api.dependencies.general_dependencies import get_tenant_provider_service
from core_orchestrator.infrastructure.api.dependencies.user_auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter()


# Request/Response Payloads
class AddProviderRequest(BaseModel):
    provider: Literal["gemini", "openai", "groq", "ollama"]
    api_key: Optional[str] = Field(default=None, description="API Key for cloud providers (Gemini, OpenAI, Groq)")
    base_url: Optional[str] = Field(default=None, description="Base URL (Required for Ollama or self-hosted)")
    enabled: bool = Field(default=True)


class ProviderResponse(BaseModel):
    provider: str
    has_api_key: bool
    base_url: Optional[str] = None
    enabled: bool


class AddModelRequest(BaseModel):
    model_id: str = Field(..., min_length=1, max_length=100, description="Unique model ID per tenant (e.g. groq-llama)")
    provider: Literal["gemini", "openai", "groq", "ollama"]
    model_name: str = Field(..., min_length=1, max_length=200, description="Provider model name e.g. llama-3.3-70b-versatile")
    max_output_tokens: Optional[int] = Field(default=None, ge=1)
    max_input_tokens: Optional[int] = Field(default=None, ge=1)
    enabled: bool = Field(default=True)


class SetDefaultModelRequest(BaseModel):
    model_id: Optional[str] = Field(default=None, description="Model ID to use as default for background log analysis (alias for default_log_analysis_model_id)")
    default_log_analysis_model_id: Optional[str] = Field(default=None, description="Model ID for background log analysis")
    default_mongo_translator_model_id: Optional[str] = Field(default=None, description="Model ID for NLQ to MongoDB query translation")


def _require_admin(user: UserInDB):
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can manage tenant AI provider configurations."
        )


@router.get("/{client_id}/providers", response_model=List[ProviderResponse])
async def list_tenant_providers(
    client_id: str,
    provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
    current_user: Annotated[UserInDB, Depends(get_current_user)],
):
    """List AI providers configured for tenant (never returns raw API keys)."""
    _require_admin(current_user)
    tenant = await provider_service._get_tenant(client_id)
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tenant '{client_id}' not found.")

    return [
        ProviderResponse(
            provider=p.provider,
            has_api_key=bool(p.api_key_encrypted),
            base_url=p.base_url,
            enabled=p.enabled,
        )
        for p in tenant.ai_providers
    ]


@router.post("/{client_id}/providers", response_model=List[ProviderResponse])
async def add_or_update_tenant_provider(
    client_id: str,
    req: AddProviderRequest,
    provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
    current_user: Annotated[UserInDB, Depends(get_current_user)],
):
    """Add or update an AI provider entry for a tenant."""
    _require_admin(current_user)
    if req.provider in ("gemini", "openai", "groq") and not req.api_key:
        # Check if tenant already has an encrypted key
        tenant = await provider_service._get_tenant(client_id)
        existing = next((p for p in (tenant.ai_providers if tenant else []) if p.provider == req.provider), None)
        if not existing or not existing.api_key_encrypted:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"API key is required for provider '{req.provider}'."
            )

    try:
        updated_tenant = await provider_service.add_or_update_provider(
            client_id=client_id,
            provider=req.provider,
            api_key=req.api_key,
            base_url=req.base_url,
            enabled=req.enabled,
        )
        return [
            ProviderResponse(
                provider=p.provider,
                has_api_key=bool(p.api_key_encrypted),
                base_url=p.base_url,
                enabled=p.enabled,
            )
            for p in updated_tenant.ai_providers
        ]
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/{client_id}/providers/{provider}")
async def delete_tenant_provider(
    client_id: str,
    provider: str,
    provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
    current_user: Annotated[UserInDB, Depends(get_current_user)],
):
    """Remove an AI provider from a tenant."""
    _require_admin(current_user)
    try:
        await provider_service.remove_provider(client_id, provider)
        return {"message": f"Provider '{provider}' removed from tenant '{client_id}'."}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{client_id}/providers/models")
async def list_tenant_models(
    client_id: str,
    provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
    current_user: Annotated[UserInDB, Depends(get_current_user)],
):
    """List available AI entities configured for tenant."""
    _require_admin(current_user)
    tenant = await provider_service._get_tenant(client_id)
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tenant '{client_id}' not found.")

    return {
        "default_log_analysis_model_id": tenant.default_log_analysis_model_id,
        "available_models": tenant.available_models,
    }


@router.post("/{client_id}/providers/models")
async def add_or_update_tenant_model(
    client_id: str,
    req: AddModelRequest,
    provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
    current_user: Annotated[UserInDB, Depends(get_current_user)],
):
    """Add or update an AI model in tenant catalog."""
    _require_admin(current_user)
    try:
        updated_tenant = await provider_service.add_or_update_model(
            client_id=client_id,
            model_id=req.model_id,
            provider=req.provider,
            model_name=req.model_name,
            max_output_tokens=req.max_output_tokens,
            max_input_tokens=req.max_input_tokens,
            enabled=req.enabled,
        )
        return {
            "default_log_analysis_model_id": updated_tenant.default_log_analysis_model_id,
            "available_models": updated_tenant.available_models,
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/{client_id}/providers/models/{model_id}")
async def delete_tenant_model(
    client_id: str,
    model_id: str,
    provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
    current_user: Annotated[UserInDB, Depends(get_current_user)],
):
    """Delete an AI model from tenant catalog."""
    _require_admin(current_user)
    try:
        await provider_service.remove_model(client_id, model_id)
        return {"message": f"Model '{model_id}' removed from tenant '{client_id}'."}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.patch("/{client_id}/providers/models/default")
async def set_tenant_default_model(
    client_id: str,
    req: SetDefaultModelRequest,
    provider_service: Annotated[TenantProviderAiService, Depends(get_tenant_provider_service)],
    current_user: Annotated[UserInDB, Depends(get_current_user)],
):
    """Set tenant default entities for background log analysis and/or MongoDB query translation."""
    _require_admin(current_user)
    try:
        log_model_id = req.default_log_analysis_model_id or req.model_id
        if log_model_id is not None:
            await provider_service.set_default_log_analysis_model(client_id, log_model_id)

        if req.default_mongo_translator_model_id is not None:
            await provider_service.set_default_mongo_translator_model(client_id, req.default_mongo_translator_model_id)

        tenant = await provider_service._get_tenant(client_id)
        return {
            "default_log_analysis_model_id": tenant.default_log_analysis_model_id if tenant else None,
            "default_mongo_translator_model_id": tenant.default_mongo_translator_model_id if tenant else None,
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

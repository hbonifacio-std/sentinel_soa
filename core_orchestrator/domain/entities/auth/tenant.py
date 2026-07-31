"""
Module providing data models and associated functionality for managing AI providers, tenants, and
model configurations in a multi-tenant environment.

This module includes classes to define provider configurations, tenant model definitions, and tenant
details. It also provides functionality for tenant management actions such as deactivation, API key
management, and checking provider availability.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Literal


@dataclass
class ProviderAIConfig:
    provider: Literal["gemini", "openai", "groq", "ollama"]
    api_key_encrypted: Optional[str] = None
    base_url: Optional[str] = None
    enabled: bool = True


@dataclass
class TenantModelAIDefinition:
    provider: str
    model_name: str
    base_url: Optional[str] = None
    max_output_tokens: Optional[int] = None
    max_input_tokens: Optional[int] = None
    enabled: bool = True


@dataclass
class Tenant:
    client_id: str
    display_name: str
    description: Optional[str] = None
    rate_limit_per_minute: int = 60
    is_active: bool = True
    api_key_hash: Optional[str] = None
    api_key_plaintext: Optional[str] = None

    ai_providers: List[ProviderAIConfig] = field(default_factory=list)
    available_models: Dict[str, TenantModelAIDefinition] = field(default_factory=dict)
    default_log_analysis_model_id: Optional[str] = None
    default_mongo_translator_model_id: Optional[str] = None


    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def deactivate(self) -> None:
        self.is_active = False
        self.updated_at = datetime.now(timezone.utc)

    def set_api_key_hash(self, key_hash: str) -> None:
        self.api_key_hash = key_hash
        self.updated_at = datetime.now(timezone.utc)

    def is_provider_enabled(self, provider_name: str) -> bool:
        return any(p.provider == provider_name and p.enabled for p in self.ai_providers)

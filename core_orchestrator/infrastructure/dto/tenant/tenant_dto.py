from datetime import datetime
from typing import Dict, List, Optional, Literal
from pydantic import BaseModel, Field


class ProviderConfigDTO(BaseModel):
    """
    Data Transfer Object for provider configuration.

    This class is used to encapsulate configuration details for a provider, such as provider name,
    encrypted API key, custom base URL, and whether the provider is enabled or not. It ensures
    proper data validation and type enforcement for its fields.

    Attributes:
        provider (Literal["gemini", "openai", "groq", "ollama"]): Name of the provider
        api_key_encrypted (Optional[str]): Encrypted API key, used for authentication with the provider
        base_url (Optional[str]): Base URL for custom endpoints if required by the provider
        enabled (bool): Indicates whether the provider is enabled. Defaults to True
    """
    provider: Literal["gemini", "openai", "groq", "ollama"]
    api_key_encrypted: Optional[str] = Field(default=None, description="Encrypted API key")
    base_url: Optional[str] = Field(default=None, description="Base URL required for custom endpoints")
    enabled: bool = Field(default=True)
    class Config:
        from_attributes = True


class TenantModelDefinitionRequestDTO(BaseModel):
    """
    Represents the definition of a tenant's model in the domain.

    This class is used for defining the details of a particular model associated
    with a tenant. It includes specific attributes of the model such as provider,
    identifier, name, input/output token limitations, and whether the model is
    enabled or not. This is typically useful in scenarios where multiple models
    need to be managed and their configurations stored.

    Attributes:
        provider (str): The provider of the model
        model_id (str): The unique identifier of the model
        model_name (str): The name of the model
        max_output_tokens (Optional[int]): The maximum number of tokens the model
            can output. This attribute is optional
        max_input_tokens (Optional[int]): The maximum number of tokens the model
            can accept as input. This attribute is optionally
        enabled (bool): Indicates if the model is enabled or not. Defaults to True
    """
    provider: str
    model_id: str
    model_name: str
    max_output_tokens: Optional[int] = None
    max_input_tokens: Optional[int] = None
    enabled: bool = True
    class Config:
        from_attributes = True


class TenantCreateRequestDTO(BaseModel):
    """
    Data transfer object for creating a tenant.

    This class represents the necessary and optional attributes required
    to create a tenant. It validates input constraints such as the length
    of strings or numerical ranges where applicable. Used primarily for
    tenant creation workflows.
    """
    client_id: str = Field(..., min_length=1, max_length=100, description="Unique tenant identifier")
    display_name: str = Field(..., min_length=1, max_length=200, description="Human-readable tenant name")
    description: Optional[str] = Field(default=None, description="Optional description")
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10000)



class TenantUpdateRequestDTO(BaseModel):
    """
    Represents a data transfer object for updating tenant information.

    Provides fields for updating various tenant details such as display name,
    description, rate limit, activation status, and default model IDs. This class
    validates input constraints where applicable and is used to encapsulate
    and transfer the tenant update data within the application.
    """
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = None
    rate_limit_per_minute: Optional[int] = Field(default=None, ge=1, le=10000)
    is_active: Optional[bool] = None
    default_log_analysis_model_id: Optional[str] = None
    default_mongo_translator_model_id: Optional[str] = None
    class Config:
        from_attributes = True


# --- DTOs de Response (Salida API) ---

class TenantResponseDTO(BaseModel):
    """
    Represents a data transfer object (DTO) for a tenant response.

    This class encapsulates the data structure used to capture and transport
    information about a tenant, including its identifiers, configuration,
    status, associated models, and timestamps. It is typically used to
    facilitate communication between different layers or services in an
    application.

    Attributes:
        client_id: A unique identifier for the tenant.
        display_name: The display name of the tenant.
        description: An optional description of the tenant.
        rate_limit_per_minute: The rate limit for requests per minute is
            associated with the tenant.
        is_active: A boolean indicating whether the tenant is active.
        ai_providers: A list of AI providers' configuration DTOs associated
            with the tenant.
        available_models: A dictionary mapping model identifiers to their
            definitions specific to the tenant.
        default_log_analysis_model_id: An optional identifier for the default
            model used for log analysis.
        default_mongo_translator_model_id: An optional identifier for the
            default MongoDB translator model associated with the tenant.
        created_at: The datetime when the tenant was created.
        updated_at: The datetime when the tenant was last updated.
    """
    client_id: str
    display_name: str
    description: Optional[str] = None
    rate_limit_per_minute: int
    is_active: bool
    ai_providers: List[ProviderConfigDTO] = []
    available_models: Dict[str, TenantModelDefinitionRequestDTO] = {}
    default_log_analysis_model_id: Optional[str] = None
    default_mongo_translator_model_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TenantCreatedResponseDTO(TenantResponseDTO):
    """
    Represents the response data transfer object (DTO) for an event of tenant creation.

    This class extends TenantResponseDTO and is used specifically to include
    details relevant to a newly created tenant, such as the API key. The API key
    provided in this DTO will be shown only once, and it is the responsibility of
    the caller to securely store it immediately after retrieval.

    Attributes:
        api_key_plaintext: Str
            API key generated for this tenant, shown only once at the time of creation.
    """
    api_key_plaintext: str = Field(..., description="API key generated for this tenant (Shown only once)")


class AddProviderAiRequestDto(BaseModel):
    provider: Literal["gemini", "openai", "groq", "ollama"]
    api_key: Optional[str] = Field(default=None, description="API Key for cloud providers (Gemini, OpenAI, Groq)")
    base_url: Optional[str] = Field(default=None, description="Base URL (Required for Ollama or self-hosted)")
    enabled: bool = Field(default=True)


class ProviderAiResponseDto(BaseModel):
    provider: str
    base_url: Optional[str] = None
    enabled: bool


class AddModelRequestDto(BaseModel):
    model_id: str = Field(..., min_length=1, max_length=100, description="Unique model ID per tenant (e.g. groq-llama)")
    provider: Literal["gemini", "openai", "groq", "ollama"]
    model_name: str = Field(..., min_length=1, max_length=200, description="Provider model name e.g. llama-3.3-70b-versatile")
    max_output_tokens: Optional[int] = Field(default=None, ge=1)
    max_input_tokens: Optional[int] = Field(default=None, ge=1)
    enabled: bool = Field(default=True)


class SetDefaultModelRequestDto(BaseModel):
    model_id: Optional[str] = Field(default=None, description="Model ID to use as default for background log analysis (alias for default_log_analysis_model_id)")
    default_log_analysis_model_id: Optional[str] = Field(default=None, description="Model ID for background log analysis")
    default_mongo_translator_model_id: Optional[str] = Field(default=None, description="Model ID for NLQ to MongoDB query translation")

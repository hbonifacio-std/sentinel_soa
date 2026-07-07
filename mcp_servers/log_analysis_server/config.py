"""Configuration module for the MCP Log Analysis Server.

Uses pydantic-settings to robustly and type-safely read environment variables
that are **inherited from the parent process (Core Orchestrator)**.
This module does not load its own .env file, ensuring that configuration
is centralized in the orchestrator.
"""

from typing import Optional, Dict
from pydantic import Field, SecretStr, field_validator, BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict


class ModelDefinition(BaseModel):
    """Defines the structure for a single LLM model in the catalog."""
    provider: str
    model_name: str
    max_output_tokens: Optional[int] = None
    max_input_tokens: Optional[int] = None


class LogAnalysisServerSettings(BaseSettings):
    """Encapsulates the environment configuration for the MCP analysis node.
    
    Reads environment variables that the Core Orchestrator provides when
    starting it as a subprocess.
    """

    # ========== MODEL CATALOG CONFIGURATION ==========
    
    default_model_id: str = Field(
        default="qwen2_5_coder7",
        validation_alias="DEFAULT_MODEL_ID",
        description="ID of the model from the catalog to use by default."
    )

    available_models: Dict[str, ModelDefinition] = Field(
        default={
            "qwen2_5_coder7": ModelDefinition(provider="ollama", model_name="qwen2.5-coder:7b"),
            "sentinel-analyst": ModelDefinition(provider="ollama", model_name="sentinel-analyst"),
            "sentinel-translator-mongodb": ModelDefinition(provider="ollama", model_name="sentinel-translator-mongodb", max_output_tokens=8192),
            "gemini-3.5-flash": ModelDefinition(provider="gemini", model_name="gemini-3.5-flash", max_output_tokens=8192),
            "gemini-3.2-flash": ModelDefinition(provider="gemini", model_name="gemini-3.2-flash",max_output_tokens=8192),
            "openai-gpt3_5-turbo": ModelDefinition(provider="openai", model_name="gpt-3.5-turbo-instruct-0914", max_output_tokens=8192),
            "groq-llama-3_3-70b-versatile": ModelDefinition(provider="groq", model_name="llama-3.3-70b-versatile",max_output_tokens=12000, max_input_tokens=8192)
        },
        description="Catalog of available LLM models for analysis."
    )

    # ========== LLM PROVIDER CONFIGURATION ==========
    
    # Using SecretStr prevents the API key from being accidentally exposed in logs
    gemini_api_key: Optional[SecretStr] = Field(
        default=None,
        validation_alias="GEMINI_API_KEY",
        description="Secret key for the Google Gemini API, inherited."
    )
    gemini_model_name: str = Field(
        default="gemini-3.5-flash",
        validation_alias="GEMINI_MODEL",
        description="Name of the Gemini model to use for analysis."
    )
    
    gemini_max_output_tokens: int = Field(
        default=4160,
        validation_alias="GEMINI_MAX_OUTPUT_TOKENS",
        gt=0,
        description="Maximum output token limit allowed in the Gemini agent verdict."
    )
    
    # ========== OLLAMA CONFIGURATION (Local) ==========
    
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        validation_alias="OLLAMA_BASE_URL",
        description="Base URL of the Ollama server, inherited."
    )
    
    ollama_timeout_seconds: int = Field(
        default=900,
        validation_alias="OLLAMA_TIMEOUT_SECONDS",
        gt=0,
        description="Timeout in seconds for requests to Ollama"
    )

    # ========== OPENAI CONFIGURATION ==========
    
    openai_api_key: Optional[SecretStr] = Field(
        default=None,
        validation_alias="OPENAI_API_KEY",
        description="Secret key for the OpenAI API, inherited."
    )
    
    openai_max_output_tokens: int = Field(
        default=4096,
        validation_alias="OPENAI_MAX_OUTPUT_TOKENS",
        gt=0,
        description="Maximum output token limit for OpenAI."
    )

    openai_timeout_seconds: int = Field(
        default=60,
        validation_alias="OPENAI_TIMEOUT_SECONDS",
        gt=0,
        description="Timeout in seconds for OpenAI requests."
    )

    # ========== GROQ CONFIGURATION ==========
    
    groq_api_key: Optional[SecretStr] = Field(
        default=None,
        validation_alias="GROQ_API_KEY",
        description="Secret key for the GROQ API, inherited."
    )
    
    groq_max_output_tokens: int = Field(
        default=4096,
        validation_alias="GROQ_MAX_OUTPUT_TOKENS",
        gt=0,
        description="Maximum output token limit for GROQ."
    )

    groq_timeout_seconds: int = Field(
        default=60,
        validation_alias="GROQ_TIMEOUT_SECONDS",
        gt=0,
        description="Timeout in seconds for GROQ requests."
    )

    # Internal Pydantic Settings parser configuration
    model_config = SettingsConfigDict(
        # No env_file specified to force reading from the system environment.
        # This is crucial so it inherits configuration from the parent process.
        extra="ignore"
    )

    @field_validator('ollama_base_url')
    @classmethod
    def validate_ollama_base_url(cls, v: str) -> str:
        """Ensures the Docker-friendly Ollama endpoint is used when the env var is empty."""
        return (v or '').strip() or 'http://ollama:11434'

    def get_provider_config(self) -> dict:
        """
        Returns a dictionary with the configuration specific to the selected provider.
        
        This method makes it easy to pass the correct configuration to the provider factory.
        
        Returns:
            dict: Provider-specific configuration
        """
        return {
            'gemini_api_key': self.gemini_api_key.get_secret_value() if self.gemini_api_key else None,
            'gemini_max_output_tokens': self.gemini_max_output_tokens,
            'ollama_base_url': self.ollama_base_url,
            'ollama_timeout_seconds': self.ollama_timeout_seconds,
            'openai_api_key': self.openai_api_key.get_secret_value() if self.openai_api_key else None,
            'openai_max_output_tokens': self.openai_max_output_tokens,
            'openai_timeout_seconds': self.openai_timeout_seconds,
            'groq_api_key': self.groq_api_key.get_secret_value() if self.groq_api_key else None,
            'groq_max_output_tokens': self.groq_max_output_tokens,
            'groq_timeout_seconds': self.groq_timeout_seconds,
        }


# Unique singleton instance exposed for centralized resource access on the server
try:
    server_settings = LogAnalysisServerSettings()
except Exception as e:
    import sys
    import logging
    # Configure logging to send errors to stderr, avoiding stdout contamination.
    logging.basicConfig(
        level=logging.ERROR,
        stream=sys.stderr,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True
    )
    logger = logging.getLogger("MCP_SERVER_CONFIG")
    logger.error(
        "Critical failure initializing the MCP Server. Required environment variables "
        f"inherited from the orchestrator were not found. Details: {e}"
    )
    # Fail-fast: stop the stdio subprocess immediately to notify the Host
    sys.exit(1)
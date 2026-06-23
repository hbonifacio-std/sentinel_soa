"""Configuration module for the MCP Log Analysis Server.

Uses pydantic-settings to robustly and type-safely read environment variables
that are **inherited from the parent process (Core Orchestrator)**.
This module does not load its own .env file, ensuring that configuration
is centralized in the orchestrator.
"""

from typing import Optional
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogAnalysisServerSettings(BaseSettings):
    """Encapsulates the environment configuration for the MCP analysis node.
    
    Reads environment variables that the Core Orchestrator provides when
    starting it as a subprocess.
    """

    # ========== LLM PROVIDER CONFIGURATION ==========
    
    llm_provider: str = Field(
        default="gemini",
        validation_alias="LLM_PROVIDER",
        description="LLM provider to use, inherited from the orchestrator."
    )
    
    # ========== GEMINI CONFIGURATION (Default) ==========
    
    # Using SecretStr prevents the API key from being accidentally exposed in logs
    gemini_api_key: Optional[SecretStr] = Field(
        default=None,
        validation_alias="GEMINI_API_KEY",
        description="Secret key for the Google Gemini API, inherited."
    )
    
    gemini_model: str = Field(
        default="gemini-3.5-flash",
        validation_alias="GEMINI_MODEL",
        description="Exact version of the Gemini model to invoke for heuristics."
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
    
    ollama_model: str = Field(
        default="mistral",
        validation_alias="OLLAMA_MODEL",
        description="Name of the Ollama model to use (e.g., mistral, llama2, neural-chat)"
    )
    
    ollama_timeout_seconds: int = Field(
        default=900,
        validation_alias="OLLAMA_TIMEOUT_SECONDS",
        gt=0,
        description="Timeout in seconds for requests to Ollama"
    )

    # Internal Pydantic Settings parser configuration
    model_config = SettingsConfigDict(
        # No env_file specified to force reading from the system environment.
        # This is crucial so it inherits configuration from the parent process.
        extra="ignore"
    )
    
    @field_validator('llm_provider')
    @classmethod
    def validate_provider(cls, v: str) -> str:
        """Validates that the provider is one of the supported ones."""
        valid_providers = ['gemini', 'ollama']
        v_lower = (v or '').lower().strip() or 'ollama'
        if v_lower not in valid_providers:
            raise ValueError(f"LLM_PROVIDER must be one of {valid_providers}, got: {v}")
        return v_lower

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
        config = {
            'gemini_api_key': self.gemini_api_key.get_secret_value() if self.gemini_api_key else None,
            'gemini_model': self.gemini_model,
            'gemini_max_output_tokens': self.gemini_max_output_tokens,
            'ollama_base_url': self.ollama_base_url,
            'ollama_model': self.ollama_model,
            'ollama_timeout_seconds': self.ollama_timeout_seconds,
        }
        return config


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
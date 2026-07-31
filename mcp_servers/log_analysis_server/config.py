"""Configuration module for the MCP Log Analysis Server.

Uses pydantic-settings to robustly and type-safely read environment variables
that are **inherited from the parent process (Core Orchestrator)**.
This module does not load its own .env file, ensuring that configuration
is centralized in the orchestrator.
"""

import json
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional, Dict, Any
from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator, BaseModel
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

    app_env: str = Field(
        default="development",
        validation_alias="APP_ENV",
        description="Execution environment (development, staging, production, test)."
    )

    secret_source: str = Field(
        default="env",
        validation_alias="SECRET_SOURCE",
        description="Secret origin provider inherited from core orchestrator."
    )

    require_https_in_production: bool = Field(
        default=True,
        validation_alias="REQUIRE_HTTPS_IN_PRODUCTION",
        description="If true, production rejects non-HTTPS provider endpoints."
    )

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
        description="Catalog of available LLM entities for analysis."
    )
    
    available_models_json_path: Optional[str] = Field(
        default=None,
        validation_alias="AVAILABLE_MODELS_JSON_PATH",
        description="Optional path to a JSON file that overrides the model catalog (enables zero-redeploy model updates)."
    )

    # ========== FORENSIC SAMPLING CONFIGURATION ==========
    
    forensic_low_volume_log_threshold: int = Field(
        default=100,
        validation_alias="FORENSIC_LOW_VOLUME_LOG_THRESHOLD",
        gt=0,
        description="Threshold below which forensic logs are considered low-volume and subject to sampling."
    )
    
    forensic_sampled_log_count: int = Field(
        default=20,
        validation_alias="FORENSIC_SAMPLED_LOG_COUNT",
        gt=0,
        description="Number of logs to sample when low-volume threshold is exceeded."
    )
    
    mitre_matrix_json_path: Optional[str] = Field(
        default=None,
        validation_alias="MITRE_MATRIX_JSON_PATH",
        description="Optional path to a JSON file that overrides the MITRE matrix (enables dynamic updates without redeploy)."
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

    gemini_timeout_seconds: int = Field(
        default=60,
        validation_alias="GEMINI_TIMEOUT_SECONDS",
        gt=0,
        description="Timeout in seconds for Gemini requests."
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
    def validate_ollama_base_url(cls, v: str, info: ValidationInfo) -> str:
        """Ensures the Docker-friendly Ollama endpoint is used when the env var is empty."""
        value = (v or '').strip() or 'http://ollama:11434'
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("OLLAMA_BASE_URL must be a valid http(s) URL.")

        app_env = (info.data.get("app_env") or "development").lower()
        require_https = bool(info.data.get("require_https_in_production", True))
        if app_env == "production" and require_https and parsed.scheme != "https":
            raise ValueError("OLLAMA_BASE_URL must use https in production.")
        return value

    @field_validator("app_env")
    @classmethod
    def validate_app_env(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed = {"development", "staging", "production", "test"}
        if normalized not in allowed:
            raise ValueError(
                f"APP_ENV must be one of {sorted(allowed)}, got '{value}'.")
        return normalized

    @field_validator("secret_source")
    @classmethod
    def validate_secret_source(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed = {
            "env",
            "vault",
            "aws_secrets_manager",
            "gcp_secret_manager",
            "azure_key_vault",
        }
        if normalized not in allowed:
            raise ValueError(
                f"SECRET_SOURCE must be one of {sorted(allowed)}, got '{value}'.")
        return normalized

    @model_validator(mode="after")
    def validate_production_secret_policy(self) -> "LogAnalysisServerSettings":
        if self.app_env == "production" and self.secret_source == "env":
            raise ValueError(
                "SECRET_SOURCE cannot be 'env' in production. Use a managed secret provider.")
        return self
    
    def _load_models_from_json(self, json_path: str) -> Dict[str, ModelDefinition]:
        """Load model catalog from external JSON file."""
        try:
            path = Path(json_path)
            if not path.exists():
                import sys
                import logging
                logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
                logger = logging.getLogger("MCP_CONFIG")
                logger.warning(f"Models JSON file not found: {json_path}. Using default catalog.")
                return self.available_models
            
            with open(path, 'r') as f:
                data = json.load(f)
            
            models = {}
            for key, model_data in data.items():
                models[key] = ModelDefinition(**model_data)
            return models
        except Exception as e:
            import sys
            import logging
            logging.basicConfig(level=logging.ERROR, stream=sys.stderr)
            logger = logging.getLogger("MCP_CONFIG")
            logger.error(f"Failed to load entities from {json_path}: {e}. Using default catalog.")
            return self.available_models
    
    def _load_mitre_matrix_from_json(self, json_path: str) -> Dict[str, Any]:
        """Load MITRE matrix from external JSON file."""
        try:
            path = Path(json_path)
            if not path.exists():
                import sys
                import logging
                logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
                logger = logging.getLogger("MCP_CONFIG")
                logger.warning(f"MITRE matrix JSON file not found: {json_path}. Using default matrix.")
                return None
            
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            import sys
            import logging
            logging.basicConfig(level=logging.ERROR, stream=sys.stderr)
            logger = logging.getLogger("MCP_CONFIG")
            logger.error(f"Failed to load MITRE matrix from {json_path}: {e}. Using default matrix.")
            return None

    def __init__(self, **data):
        """Override init to load entities from external JSON if configured."""
        super().__init__(**data)
        if self.available_models_json_path:
            self.available_models = self._load_models_from_json(self.available_models_json_path)

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
            'gemini_timeout_seconds': self.gemini_timeout_seconds,
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
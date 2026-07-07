"""
Factory module for creating LLM provider instances.

Implements the Factory pattern to encapsulate the creation of LLM providers
and allow dynamic selection based on configuration.
"""

import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

from mcp_servers.log_analysis_server.llm_providers.base import (
    LLMProviderInterface,
    LLMException,
)

if TYPE_CHECKING:
    from mcp_servers.log_analysis_server.llm_providers.gemini_provider import GeminiProvider
    from mcp_servers.log_analysis_server.llm_providers.ollama_provider import OllamaProvider
    from mcp_servers.log_analysis_server.llm_providers.openai_provider import OpenAIProvider
    from mcp_servers.log_analysis_server.llm_providers.groq_provider import GroqProvider

logger = logging.getLogger("mcp_servers.log_analysis_server.llm_providers")


def create_llm_provider(
    provider_name: str, 
    model_name: str, 
    max_output_tokens: Optional[int],
    config: Dict[str, Any],
    max_input_tokens: Optional[int] = None
) -> LLMProviderInterface:
    """
    Factory function that returns the correct LLM provider instance.
    
    Uses the 'provider_name' parameter to determine which concrete adapter
    to instantiate and returns an instance of LLMProviderInterface.
    
    Args:
        provider_name (str): Provider name ('gemini', 'ollama', 'openai', 'groq')
        model_name (str): The specific model name to use (e.g., 'gemini-1.5-flash').
        max_output_tokens (int): The maximum number of output tokens for the model.
        config (Dict[str, Any]): Configuration dictionary with environment variables.
        max_input_tokens (Optional[int]): The maximum number of input tokens for the model.
        
    Returns:
        LLMProviderInterface: Instance of the requested provider.
        
    Raises:
        LLMException: If the provider is not recognized or configuration is invalid.
    """
    
    provider_name_lower = provider_name.lower().strip()
    available = "gemini, ollama, openai, groq"

    try:
        logger.info(f"Creating LLM provider instance: {provider_name_lower} with model {model_name}")

        if provider_name_lower == 'gemini':
            from mcp_servers.log_analysis_server.llm_providers.gemini_provider import GeminiProvider
            init_args = {
                "model_name": model_name,
                "api_key": config.get('gemini_api_key'),
                "max_output_tokens": max_output_tokens or config.get('gemini_max_output_tokens')
            }
            provider_instance = GeminiProvider(**init_args)
        elif provider_name_lower == 'ollama':
            from mcp_servers.log_analysis_server.llm_providers.ollama_provider import OllamaProvider
            init_args = {
                "model_name": model_name,
                "base_url": config.get('ollama_base_url'),
                "timeout": config.get('ollama_timeout_seconds')
            }
            provider_instance = OllamaProvider(**init_args)
        elif provider_name_lower == 'openai':
            from mcp_servers.log_analysis_server.llm_providers.openai_provider import OpenAIProvider
            init_args = {
                "model_name": model_name,
                "api_key": config.get('openai_api_key'),
                "max_output_tokens": max_output_tokens or config.get('openai_max_output_tokens'),
                "timeout": config.get('openai_timeout_seconds')
            }
            provider_instance = OpenAIProvider(**init_args)
        elif provider_name_lower == 'groq':
            from mcp_servers.log_analysis_server.llm_providers.groq_provider import GroqProvider
            init_args = {
                "model_name": model_name,
                "api_key": config.get('groq_api_key'),
                "max_output_tokens": max_output_tokens or config.get('groq_max_output_tokens'),
                "timeout": config.get('groq_timeout_seconds')
            }
            if max_input_tokens is not None:
                init_args["max_input_tokens"] = max_input_tokens
            provider_instance = GroqProvider(**init_args)
        else:
            raise LLMException(
                f"Provider '{provider_name}' not supported. "
                f"Available providers: {available}"
            )
        
        logger.debug(f"Provider {provider_name_lower} initialized successfully")
        return provider_instance
        
    except TypeError as type_err:
        logger.error(f"Configuration error for provider {provider_name_lower}: {str(type_err)}")
        raise LLMException(
            f"Invalid configuration for {provider_name_lower}: {str(type_err)}"
        ) from type_err
        
    except Exception as exc:
        logger.error(f"Error creating provider {provider_name_lower}: {str(exc)}", exc_info=True)
        raise LLMException(f"Error initializing {provider_name_lower}: {str(exc)}") from exc


__all__ = [
    'create_llm_provider',
    'LLMProviderInterface',
    'LLMException',
]

"""
Factory module for creating LLM provider instances.

Implements the Factory pattern to encapsulate the creation of LLM providers
and allow dynamic selection based on configuration.
"""

import logging
from typing import Any, Dict, TYPE_CHECKING

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


def create_llm_provider(provider_name: str, config: Dict[str, Any]) -> LLMProviderInterface:
    """
    Factory function that returns the correct LLM provider instance.
    
    Uses the 'provider_name' parameter to determine which concrete adapter
    to instantiate and returns an instance of LLMProviderInterface.
    
    Args:
        provider_name (str): Provider name ('gemini', 'ollama', 'openai', 'groq')
        config (Dict[str, Any]): Configuration dictionary with environment variables
        
    Returns:
        LLMProviderInterface: Instance of the requested provider
        
    Raises:
        LLMException: If the provider is not recognized or configuration is invalid
        
    Examples:
        >>> config = {'gemini_api_key': 'sk-...', 'gemini_model': 'gemini-1.5-flash'}
        >>> provider = create_llm_provider('gemini', config)
        
        >>> config = {'ollama_base_url': 'http://localhost:11434', 'ollama_model': 'mistral'}
        >>> provider = create_llm_provider('ollama', config)
        
        >>> config = {'openai_api_key': 'sk-...', 'openai_model': 'gpt-4o-mini'}
        >>> provider = create_llm_provider('openai', config)
        
        >>> config = {'groq_api_key': 'gsk_...', 'groq_model': 'mixtral-8x7b-32768'}
        >>> provider = create_llm_provider('groq', config)
    """
    
    provider_name_lower = provider_name.lower().strip()

    available = "gemini, ollama, openai, groq"

    if provider_name_lower == 'gemini':
        from mcp_servers.log_analysis_server.llm_providers.gemini_provider import GeminiProvider
        provider_class = GeminiProvider
    elif provider_name_lower == 'ollama':
        from mcp_servers.log_analysis_server.llm_providers.ollama_provider import OllamaProvider
        provider_class = OllamaProvider
    elif provider_name_lower == 'openai':
        from mcp_servers.log_analysis_server.llm_providers.openai_provider import OpenAIProvider
        provider_class = OpenAIProvider
    elif provider_name_lower == 'groq':
        from mcp_servers.log_analysis_server.llm_providers.groq_provider import GroqProvider
        provider_class = GroqProvider
    else:
        raise LLMException(
            f"Provider '{provider_name}' not supported. "
            f"Available providers: {available}"
        )
    
    try:
        logger.info(f"Creating LLM provider instance: {provider_name_lower}")
        provider_instance = provider_class(config)
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

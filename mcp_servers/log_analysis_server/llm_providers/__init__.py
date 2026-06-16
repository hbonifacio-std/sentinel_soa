"""
Módulo de factory para crear instancias de proveedores LLM.

Implementa el patrón Factory para encapsular la creación de proveedores LLM
y permitir selección dinámica basada en configuración.
"""

import logging
from typing import Any, Dict

from mcp_servers.log_analysis_server.llm_providers.base import (
    LLMProviderInterface,
    LLMException,
)
from mcp_servers.log_analysis_server.llm_providers.gemini_provider import GeminiProvider
from mcp_servers.log_analysis_server.llm_providers.ollama_provider import OllamaProvider

logger = logging.getLogger("mcp_servers.log_analysis_server.llm_providers")


def create_llm_provider(provider_name: str, config: Dict[str, Any]) -> LLMProviderInterface:
    """
    Factory function que retorna la instancia correcta del proveedor LLM.
    
    Utiliza el parámetro 'provider_name' para determinar qué adaptador
    concreto instanciar y retorna una instancia de LLMProviderInterface.
    
    Args:
        provider_name (str): Nombre del proveedor ('gemini', 'ollama', 'claude', 'openai')
        config (Dict[str, Any]): Diccionario de configuración con variables de entorno
        
    Returns:
        LLMProviderInterface: Instancia del proveedor solicitado
        
    Raises:
        LLMException: Si el proveedor no es reconocido o la configuración es inválida
        
    Examples:
        >>> config = {'gemini_api_key': 'sk-...', 'gemini_model': 'gemini-1.5-flash'}
        >>> provider = create_llm_provider('gemini', config)
        
        >>> config = {'ollama_base_url': 'http://localhost:11434', 'ollama_model': 'mistral'}
        >>> provider = create_llm_provider('ollama', config)
    """
    
    providers_map = {
        'gemini': GeminiProvider,
        'ollama': OllamaProvider,
        # 'claude': ClaudeProvider,  # Futuro
        # 'openai': OpenAIProvider,  # Futuro
    }
    
    provider_name_lower = provider_name.lower().strip()
    
    if provider_name_lower not in providers_map:
        available = ", ".join(providers_map.keys())
        raise LLMException(
            f"Proveedor '{provider_name}' no soportado. "
            f"Proveedores disponibles: {available}"
        )
    
    try:
        logger.info(f"Creando instancia de proveedor LLM: {provider_name_lower}")
        provider_class = providers_map[provider_name_lower]
        provider_instance = provider_class(config)
        logger.debug(f"Proveedor {provider_name_lower} inicializado exitosamente")
        return provider_instance
        
    except TypeError as type_err:
        logger.error(f"Error de configuración para proveedor {provider_name_lower}: {str(type_err)}")
        raise LLMException(
            f"Configuración inválida para {provider_name_lower}: {str(type_err)}"
        ) from type_err
        
    except Exception as exc:
        logger.error(f"Error creando proveedor {provider_name_lower}: {str(exc)}", exc_info=True)
        raise LLMException(f"Error inicializando {provider_name_lower}: {str(exc)}") from exc


__all__ = [
    'create_llm_provider',
    'GeminiProvider',
    'OllamaProvider',
    'LLMProviderInterface',
    'LLMException',
]

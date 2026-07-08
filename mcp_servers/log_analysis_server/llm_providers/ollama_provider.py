"""
Ollama adapter module for the generic LLM interface.

Implements LLMProviderInterface for Ollama (local LLM models), allowing
analysis execution without external API dependencies and without costs.
"""

import json
import logging
from typing import Optional

import httpx
from httpx import Timeout
from pydantic import ValidationError

from mcp_servers.log_analysis_server.llm_providers.base import (
    LLMProviderInterface,
    LLMResponse,
    LLMException,
)
from mcp_servers.log_analysis_server.llm_providers.response_normalizer import (
    parse_llm_decision_response,
)

logger = logging.getLogger("mcp_servers.log_analysis_server.llm_providers.ollama_provider")


class OllamaProvider(LLMProviderInterface):
    """
    Ollama adapter for the generic LLM framework.
    
    Allows running local LLM models (Mistral, Llama2, etc.) without
    external API dependencies, ideal for development and testing.
    
    Requires Ollama to be running (typically in Docker):
        docker run -d -p 11434:11434 ollama/ollama
        docker exec <container_id> ollama pull mistral
    """

    _PROVIDER_NAME = "ollama"
    _TIMEOUT_SECONDS = 900  # 15 minutes by default

    def __init__(self, *, model_name: str, base_url: str, timeout: Optional[int] = None):
        """
        Initialize the Ollama provider with specific configuration.
        
        Args:
            model_name: The specific Ollama model to use (e.g., 'mistral').
            base_url: The base URL of the Ollama server.
            timeout: Optional request timeout in seconds.
        """
        super().__init__()
        self._base_url = (base_url or "http://localhost:11434").rstrip("/")
        self._model_name = model_name or "mistral"
        self._timeout = timeout or self._TIMEOUT_SECONDS
        self._client = None
        
        if not self._model_name:
            raise LLMException("Ollama model name is required.")

        logger.info(f"OllamaProvider initialized for model: {self._model_name} at {self._base_url}")

    def _get_client(self) -> httpx.AsyncClient:
        """
        Get or create an asynchronous HTTP client for Ollama.

        Reuses a single client instance for the lifetime of the provider.

        Returns:
            httpx.AsyncClient: Client with configured timeout
        """
        if self._client is None:
            structured_timeout = Timeout(
                timeout=float(self._timeout),
                read=float(self._timeout),
                connect=10.0,
            )
            self._client = httpx.AsyncClient(timeout=structured_timeout)
        return self._client

    async def call_model(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """
        Invoke Ollama with the provided prompt.
        
        Makes an HTTP request to the Ollama API (/api/generate endpoint) and
        returns the response as a string.
        
        Args:
            prompt (str): Structured prompt for analysis
            max_tokens (Optional[int]): Maximum number of tokens (ignored by Ollama in this endpoint)
            
        Returns:
            str: Model response as string
            
        Raises:
            LLMException: If there is an error communicating with Ollama
        """
        client = self._get_client()
        url = f"{self._base_url}/api/generate"
        
        payload = {
            "model": self._model_name,
            "prompt": prompt,
            "stream": False,  # Do not use streaming for structured responses
            "format": "json",  # Request JSON format
        }

        try:
            logger.debug(f"Sending request to Ollama: {url}")
            
            response = await client.post(url, json=payload)
            response.raise_for_status()
            
            result = response.json()

            generated_text = result.get("response", "")
            logger.debug("Raw Ollama response (first 500 chars): %s", generated_text[:500])
            if not generated_text:
                logger.error("Ollama returned empty response")
                raise LLMException("Empty response from Ollama")
            
            logger.debug("Response received from Ollama successfully")
            return generated_text.strip()
            
        except httpx.HTTPError as http_err:
            logger.error(f"HTTP error in Ollama: {str(http_err)}")
            raise LLMException(f"HTTP error in Ollama: {str(http_err)}") from http_err
            
        except Exception as exc:
            logger.error(f"Error in Ollama call: {str(exc)}", exc_info=True)
            raise LLMException(f"Ollama failure: {str(exc)}") from exc

    async def validate_response(self, response: str) -> LLMResponse:
        """
        Validate and parse the Ollama response.
        
        Converts the response to JSON and validates it against the LLMResponse schema.
        
        Args:
            response (str): Ollama response
            
        Returns:
            LLMResponse: Validated object
            
        Raises:
            LLMException: If there is a parsing or validation error
        """
        try:
            normalized = parse_llm_decision_response(response, use_fallback_defaults=True)
            logger.debug("JSON parsed successfully")
            
            # Validate with Pydantic
            validated = LLMResponse(**normalized)
            logger.debug("Response validated against LLMResponse schema")
            return validated
            
        except json.JSONDecodeError as json_err:
            logger.error(f"Error parsing Ollama JSON: {str(json_err)}")
            raise LLMException(f"Invalid JSON from Ollama: {str(json_err)}") from json_err
            
        except ValidationError as val_err:
            logger.error(f"Error validating response schema: {str(val_err)}")
            raise LLMException(f"Response does not conform to schema: {str(val_err)}") from val_err
            
        except Exception as exc:
            logger.error(f"Unexpected error in validate_response: {str(exc)}")
            raise LLMException(f"Unexpected error: {str(exc)}") from exc

    @property
    def provider_name(self) -> str:
        """Returns 'ollama' as the unique provider identifier."""
        return self._PROVIDER_NAME

    @property
    def model_name(self) -> str:
        """Returns the name of the Ollama model being used."""
        return self._model_name

    async def health_check(self) -> bool:
        """
        Verify Ollama availability.
        
        Makes a call to the /api/tags endpoint to verify that the service
        is available and that the model is downloaded.
        
        Returns:
            bool: True if Ollama is available and the model exists, False otherwise
        """
        client = self._get_client()
        url = f"{self._base_url}/api/tags"
        
        try:
            logger.info("Running Ollama health check")
            
            response = await client.get(url)
            response.raise_for_status()
            
            data = response.json()
            models = [m.get("name", "") for m in data.get("models", [])]
            
            # Verify that the model exists
            model_found = any(self._model_name in m for m in models)
            
            if model_found:
                logger.info(f"Health check OK: model {self._model_name} available in Ollama")
                return True
            else:
                logger.warning(f"Health check: model {self._model_name} not found. Available models: {models}")
                return False
                
        except Exception as exc:
            logger.error(f"Ollama health check failed: {str(exc)}")
            return False

    async def close(self):
        """Close connection with Ollama."""
        if self._client:
            await self._client.aclose()
            self._client = None

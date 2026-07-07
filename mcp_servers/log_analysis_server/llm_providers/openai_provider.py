"""
OpenAI adapter module for the generic LLM interface.

Implements LLMProviderInterface for OpenAI, encapsulating all OpenAI
API-specific logic and keeping it agnostic from the rest of the system.
"""

import json
import logging
from typing import Any, Optional, List

from openai import AsyncOpenAI
from pydantic import ValidationError

from mcp_servers.log_analysis_server.llm_providers.base import (
    LLMProviderInterface,
    LLMResponse,
    LLMException,
)
from mcp_servers.log_analysis_server.services.prompt_builder import AnalysisPromptBuilder

logger = logging.getLogger("mcp_servers.log_analysis_server.llm_providers.openai_provider")


class OpenAIProvider(LLMProviderInterface):
    """
    OpenAI adapter for the generic LLM framework.
    
    Encapsulates all particularities of the OpenAI API,
    including authentication, generation configuration, and error handling.
    """

    _PROVIDER_NAME = "openai"

    def __init__(self, *, model_name: str, api_key: str, max_output_tokens: Optional[int] = None, timeout: Optional[int] = None):
        """
        Initialize the OpenAI provider with specific configuration.
        
        Args:
            model_name: The specific OpenAI model to use (e.g., 'gpt-4o-mini').
            api_key: The API key for OpenAI authentication.
            max_output_tokens: Optional maximum number of tokens for the response.
            timeout: Optional request timeout in seconds.
        """
        super().__init__()
        self._api_key = api_key
        self._model_name = model_name or "gpt-4o-mini"
        self._max_tokens = max_output_tokens or 4096
        self._timeout = timeout or 60
        
        if not self._api_key:
            raise LLMException("OpenAI API key is required.")
        
        # Initialize OpenAI async client
        self._client = AsyncOpenAI(
            api_key=self._api_key,
            timeout=self._timeout
        )
        logger.info(f"OpenAIProvider initialized for model: {self._model_name}")

    def build_analysis_prompt(self, telemetry: Any, history: List[Any]) -> str:
        """Generates the analysis prompt for OpenAI."""
        return AnalysisPromptBuilder.build_full_prompt(telemetry, history)

    async def call_model(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """
        Invoke OpenAI with the provided prompt.
        
        Args:
            prompt (str): The analysis prompt
            max_tokens (Optional[int]): Override max tokens if provided
            
        Returns:
            str: Model response as JSON string
            
        Raises:
            LLMException: If there's an error with the API call
        """
        try:
            current_max_tokens = max_tokens or self._max_tokens
            if current_max_tokens < 2048:
                current_max_tokens = 4096

            logger.debug(f"Sending prompt to OpenAI ({self._model_name})")

            # Use the system instruction from prompt builder
            system_instruction = AnalysisPromptBuilder.get_system_instructions()

            response = await self._client.chat.completions.create(
                model=self._model_name,
                messages=[
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=current_max_tokens,
                temperature=0.1,
                response_format={"type": "json_object"}
            )

            if not response.choices or not response.choices[0].message.content:
                logger.error("OpenAI returned empty response")
                raise LLMException("Empty response from OpenAI API")

            response_text = response.choices[0].message.content.strip()
            logger.debug("Response received from OpenAI successfully")
            return response_text

        except Exception as exc:
            logger.error(f"Error in OpenAI API call: {str(exc)}", exc_info=True)
            raise LLMException(f"OpenAI API failure: {str(exc)}") from exc

    async def validate_response(self, response: str) -> LLMResponse:
        """
        Validate and parse the OpenAI response.
        
        Converts JSON string to LLMResponse and handles cases where
        the JSON is malformed.
        
        Args:
            response (str): JSON response from OpenAI
            
        Returns:
            LLMResponse: Validated object
            
        Raises:
            LLMException: If there is a parsing or validation error
        """
        try:
            parsed = json.loads(response)
            logger.debug("JSON parsed successfully")

            # Keep a provider-agnostic contract: only cognitive LLM fields are accepted.
            filtered = {
                "threat_score": parsed.get("threat_score", 0),
                "reasoning_summary": parsed.get("reasoning_summary", ""),
                "recommendation": parsed.get("recommendation", ""),
            }
            
            # Try to validate with Pydantic
            validated = LLMResponse(**filtered)
            logger.debug("Response validated against LLMResponse schema")
            return validated
            
        except json.JSONDecodeError as json_err:
            logger.error(f"Error parsing OpenAI JSON: {str(json_err)}")
            raise LLMException(f"Invalid JSON from OpenAI: {str(json_err)}") from json_err
            
        except ValidationError as val_err:
            logger.error(f"Error validating response schema: {str(val_err)}")
            raise LLMException(f"Response does not conform to schema: {str(val_err)}") from val_err
            
        except Exception as exc:
            logger.error(f"Unexpected error in validate_response: {str(exc)}")
            raise LLMException(f"Unexpected error: {str(exc)}") from exc

    @property
    def provider_name(self) -> str:
        """Returns 'openai' as the unique provider identifier."""
        return self._PROVIDER_NAME

    @property
    def model_name(self) -> str:
        """Returns the exact name of the OpenAI model being used."""
        return self._model_name

    async def health_check(self) -> bool:
        """
        Verify OpenAI API availability.
        
        Makes a minimal call to the model to verify authentication
        and service availability.
        
        Returns:
            bool: True if available, False otherwise
        """
        try:
            logger.info("Running OpenAI health check")
            
            # Make minimal call to verify connectivity
            response = await self._client.chat.completions.create(
                model=self._model_name,
                messages=[
                    {"role": "user", "content": "Say OK"}
                ],
                max_tokens=10,
                temperature=0.1
            )
            
            if response and response.choices and response.choices[0].message.content:
                logger.info("OpenAI health check successful")
                return True
            else:
                logger.warning("OpenAI health check: empty response")
                return False
                
        except Exception as exc:
            logger.error(f"OpenAI health check failed: {str(exc)}")
            return False

    async def close(self):
        """Close connection with OpenAI."""
        if self._client:
            await self._client.close()


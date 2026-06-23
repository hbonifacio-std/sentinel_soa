"""
Gemini adapter module for the generic LLM interface.

Implements LLMProviderInterface for Google Gemini, encapsulating all Gemini
API-specific logic and keeping it agnostic from the rest of the system.
"""

import asyncio
import copy
import json
import logging
from typing import Any, Dict, Optional, List

import google.generativeai as genai
from google.generativeai.types import generation_types
from pydantic import ValidationError

from mcp_servers.log_analysis_server.llm_providers.base import (
    LLMProviderInterface,
    LLMResponse,
    LLMException,
)
from mcp_servers.log_analysis_server.services.prompt_builder import AnalysisPromptBuilder

logger = logging.getLogger("mcp_servers.log_analysis_server.llm_providers.gemini_provider")


class GeminiProvider(LLMProviderInterface):
    """
    Google Gemini adapter for the generic LLM framework.
    
    Encapsulates all particularities of the Google Gemini API,
    including authentication, generation configuration, and error handling.
    """

    _PROVIDER_NAME = "gemini"

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Gemini provider with specific configuration.
        
        Args:
            config (Dict[str, Any]): Must contain:
                - gemini_api_key: Authentication key for Google Gemini
                - gemini_model: Model name (default: gemini-1.5-flash)
                - gemini_max_output_tokens: Maximum output tokens (default: 1024)
        """
        super().__init__(config)
        self._api_key = config.get("gemini_api_key")
        self._model_name = config.get("gemini_model", "gemini-3.5-flash")
        self._max_tokens = config.get("gemini_max_output_tokens", 4160)
        
        if not self._api_key:
            raise LLMException("gemini_api_key is required in the configuration")
        
        # Configure the Gemini API lazily
        self._model = None
        logger.info(f"GeminiProvider initialized for model: {self._model_name}")

    def build_analysis_prompt(self, telemetry: Any, history: List[Any]) -> str:
        """Generates the classic extended prompt required for Gemini."""
        return AnalysisPromptBuilder.build_full_prompt(telemetry, history)

    async def call_model(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """
        Invoke Google Gemini with the provided prompt.
        Compatible with Gemini 2.5+ strict specifications.
        """
        # 1. Force a healthy minimum of tokens to avoid JSON truncation
        current_max_tokens = max_tokens or self._max_tokens
        if current_max_tokens < 2048:
            current_max_tokens = 4160  # Assign generous space for log analysis

        # 2. Clean and robust initialization of the base model
        if self._model is None or not hasattr(self, "_base_config"):
            genai.configure(api_key=self._api_key)

            # In Gemini 2.5+ it is vital to define the mime_type from the root
            self._base_config = generation_types.GenerationConfig(
                temperature=0.1,
                response_mime_type="application/json",
                response_schema=LLMResponse.to_dict_schema()
            )

            self._model = genai.GenerativeModel(
                model_name=self._model_name,
                generation_config=self._base_config,
                system_instruction=AnalysisPromptBuilder.get_system_instructions()
            )

        try:
            logger.debug(f"Sending prompt to Gemini ({self._model_name})")

            # 3. Clone and mutate the configuration exclusively for this call
            runtime_config = copy.copy(self._base_config)
            runtime_config.max_output_tokens = current_max_tokens

            # 4. Safe invocation using lambda to prevent thread signature issues
            response = await asyncio.to_thread(
                lambda: self._model.generate_content(
                    prompt,
                    generation_config=runtime_config
                )
            )

            if not response or not response.text:
                logger.error("Gemini returned empty response")
                raise LLMException("Empty response from Gemini API")

            logger.debug("Response received from Gemini successfully")
            return response.text.strip()

        except Exception as exc:
            logger.error(f"Error in Gemini API call: {str(exc)}", exc_info=True)
            raise LLMException(f"Gemini API failure: {str(exc)}") from exc

    async def validate_response(self, response: str) -> LLMResponse:
        """
        Validate and parse the Gemini response.
        
        Converts JSON string to LLMResponse and handles cases where
        the JSON is malformed.
        
        Args:
            response (str): JSON response from Gemini
            
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
            logger.error(f"Error parsing Gemini JSON: {str(json_err)}")
            raise LLMException(f"Invalid JSON from Gemini: {str(json_err)}") from json_err
            
        except ValidationError as val_err:
            logger.error(f"Error validating response schema: {str(val_err)}")
            raise LLMException(f"Response does not conform to schema: {str(val_err)}") from val_err
            
        except Exception as exc:
            logger.error(f"Unexpected error in validate_response: {str(exc)}")
            raise LLMException(f"Unexpected error: {str(exc)}") from exc

    @property
    def provider_name(self) -> str:
        """Returns 'gemini' as the unique provider identifier."""
        return self._PROVIDER_NAME

    @property
    def model_name(self) -> str:
        """Returns the exact name of the Gemini model being used."""
        return self._model_name

    async def health_check(self) -> bool:
        """
        Verify Gemini API availability.
        
        Makes a minimal call to the model to verify authentication
        and service availability.
        
        Returns:
            bool: True if available, False otherwise
        """
        try:
            logger.info("Running Gemini health check")
            
            # Initialize if necessary
            if self._model is None:
                genai.configure(api_key=self._api_key)
                generation_config = {
                    "temperature": 0.1,
                    "max_output_tokens": 4160,
                    "response_mime_type": "application/json",
                }
                self._model = genai.GenerativeModel(
                    model_name=self._model_name,
                    generation_config=generation_config
                )
            
            # Make minimal call
            test_prompt = '{"test": true}'
            response = await asyncio.to_thread(
                self._model.generate_content,
                f'Respond with valid JSON: {test_prompt}'
            )
            
            if response and response.text:
                logger.info("Gemini health check successful")
                return True
            else:
                logger.warning("Gemini health check: empty response")
                return False
                
        except Exception as exc:
            logger.error(f"Gemini health check failed: {str(exc)}")
            return False

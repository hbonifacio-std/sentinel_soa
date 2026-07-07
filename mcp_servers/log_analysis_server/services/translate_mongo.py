import json
import logging
import re
from typing import Any, Optional

from mcp_servers.log_analysis_server.config import server_settings
from mcp_servers.log_analysis_server.llm_providers import create_llm_provider, LLMProviderInterface
from mcp_servers.log_analysis_server.services.prompt_factory import build_nlq_to_mongo_prompt

logger = logging.getLogger(__name__)


class TranslateMongo:
    """
    Translates natural language queries into MongoDB query filters using an LLM.
    This class now uses the centralized prompt factory for prompt generation.
    """

    def __init__(self, model_id: str, provider: Optional[LLMProviderInterface] = None):
        self.model_id = model_id
        model_def = server_settings.available_models.get(self.model_id)
        if not model_def:
            raise ValueError(f"Model ID '{self.model_id}' not found in the available models catalog.")
        
        self.provider_name = model_def.provider
        self._provider = provider or self._create_default_provider()
        logger.info(f"TranslateMongo initialized with provider: {self._provider.__class__.__name__}")

    def _create_default_provider(self) -> LLMProviderInterface:
        """Creates the default LLM provider from settings."""
        model_def = server_settings.available_models.get(self.model_id)
        # This check is technically redundant due to the __init__ check, but good for safety
        if not model_def:
            raise ValueError(f"Model ID '{self.model_id}' not found in the available models catalog.")

        config = server_settings.get_provider_config()
        
        return create_llm_provider(
            provider_name=self.provider_name,
            model_name=model_def.model_name,
            max_output_tokens=model_def.max_output_tokens,
            config=config
        )

    @staticmethod
    def _extract_json_object(raw_text: str) -> dict[str, Any]:
        """Safely extracts a JSON object from a raw string."""
        stripped = str(raw_text or "").strip()
        if not stripped:
            return {}

        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            logger.warning(f"Initial JSON parse failed for: {stripped}")

        fenced = re.search(r"```(?:json)?\s*(\{.*})\s*```", stripped, re.DOTALL | re.IGNORECASE)
        if fenced:
            try:
                return json.loads(fenced.group(1).strip())
            except json.JSONDecodeError:
                logger.error(f"Failed to parse fenced JSON: {fenced.group(1)}")
                return {}

        start = stripped.find("{")
        end = stripped.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(stripped[start : end + 1])
            except json.JSONDecodeError:
                logger.error(f"Failed to parse substring JSON: {stripped[start:end+1]}")
                return {}
        
        logger.error(f"Could not find a valid JSON object in the response: {raw_text}")
        return {}


    async def translate_query(self, query: str, source_id: Optional[str] = None) -> dict[str, Any]:
        """
        Translates a natural language query to a MongoDB filter.
        
        Args:
            query: The natural language query.
            source_id: Optional source_id to scope the query.

        Returns:
            A dictionary containing the MongoDB filter and detected terms.
        """
        if not query:
            return {}

        # Use the centralized prompt factory
        user_prompt = build_nlq_to_mongo_prompt(
            query=query,
            provider_name=self.provider_name,
            source_id=source_id
        )
        
        try:
            # The system prompt is now embedded in the user_prompt by the factory
            response_text = await self._provider.call_model(prompt=user_prompt)
            
            parsed_response = self._extract_json_object(response_text)

            if "mongo_filter" not in parsed_response:
                logger.error(f"Response from LLM is missing 'mongo_filter': {parsed_response}")
                # Return a structured error response
                return {
                    "error": "Failed to translate query.",
                    "details": "Response from LLM was missing the 'mongo_filter' key.",
                    "llm_response": parsed_response
                }

            return {
                "mongo_filter": parsed_response.get("mongo_filter", {})
            }

        except Exception as e:
            logger.critical(f"Error during LLM query translation: {e}", exc_info=True)
            return {
                "error": "An exception occurred during translation.",
                "details": str(e)
            }

async def generate_mongo_query_from_nl(query: str, source_id: Optional[str] = None) -> dict[str, Any]:
    """
    High-level function to generate a MongoDB query from a natural language query.
    It uses the TranslateMongo class to perform the translation.
    """
    # Using the default model ID from settings for translation tasks
    translator = TranslateMongo(model_id=server_settings.default_translator_model_id or server_settings.default_model_id)
    return await translator.translate_query(query, source_id)


import logging
from typing import Any, Optional

from mcp_servers.log_analysis_server.config import server_settings
from mcp_servers.log_analysis_server.llm_providers import create_llm_provider, LLMProviderInterface
from mcp_servers.log_analysis_server.services.json_utils import extract_json_object
from mcp_servers.log_analysis_server.services.prompt_factory import build_nlq_to_mongo_prompt

logger = logging.getLogger(__name__)


class TranslateMongo:
    """
    Translates natural language queries into MongoDB query filters using an LLM.
    This class now uses the centralized prompt factory for prompt generation.
    """

    def __init__(
        self,
        model_id: Optional[str] = None,
        provider: Optional[LLMProviderInterface] = None,
        provider_override: Optional[dict[str, Any]] = None,
    ):
        self.provider_override = provider_override
        if provider_override:
            self.provider_name = provider_override["provider"]
            self._provider = provider or self._create_override_provider(provider_override)
            self.model_id = provider_override.get("model_id", "override")
        else:
            self.model_id = model_id or server_settings.default_model_id
            model_def = server_settings.available_models.get(self.model_id)
            if not model_def:
                raise ValueError(f"Model ID '{self.model_id}' not found in the available models catalog.")
            self.provider_name = model_def.provider
            self._provider = provider or self._create_default_provider()

        logger.info(f"TranslateMongo initialized with provider: {self._provider.__class__.__name__} (model: {self.provider_name})")

    def _create_override_provider(self, override: dict[str, Any]) -> LLMProviderInterface:
        provider_name = override["provider"]
        model_name = override["model_name"]
        max_output_tokens = override.get("max_output_tokens")
        max_input_tokens = override.get("max_input_tokens")

        config = server_settings.get_provider_config()
        if override.get("api_key"):
            config[f"{provider_name}_api_key"] = override["api_key"]
        if override.get("base_url"):
            config[f"{provider_name}_base_url"] = override["base_url"]

        return create_llm_provider(
            provider_name=provider_name,
            model_name=model_name,
            max_output_tokens=max_output_tokens,
            max_input_tokens=max_input_tokens,
            config=config,
        )

    def _create_default_provider(self) -> LLMProviderInterface:
        """Creates the default LLM provider from settings."""
        model_def = server_settings.available_models.get(self.model_id)
        if not model_def:
            raise ValueError(f"Model ID '{self.model_id}' not found in the available models catalog.")

        config = server_settings.get_provider_config()
        
        return create_llm_provider(
            provider_name=self.provider_name,
            model_name=model_def.model_name,
            max_output_tokens=model_def.max_output_tokens,
            config=config
        )

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
            logger.info("Translating forensic query to Mongo filter")
            # The system prompt is now embedded in the user_prompt by the factory
            response_text = await self._provider.call_model(prompt=user_prompt)
            logger.info("Mongo translation completed")
            
            parsed_response = extract_json_object(response_text, strict=False)

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

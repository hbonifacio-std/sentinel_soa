"""LLM provider integration for threat analysis.

Encapsulates LLM provider invocation logic and response processing.
"""

import logging
from typing import Any, Dict

from mcp_servers.log_analysis_server.config import server_settings as settings
from mcp_servers.log_analysis_server.llm_providers import create_llm_provider
from mcp_servers.log_analysis_server.services.prompt_factory import build_web_activity_prompt

logger = logging.getLogger(__name__)

_LLM_DECISION_FIELDS = ("threat_score", "reasoning_summary", "recommendation")


def _llm_signature_suffix(provider_name: str, model_name: str) -> str:
    """Builds a normalized suffix signature for LLM-authored text fields."""
    provider = str(provider_name or "").strip().lower()
    model = str(model_name or "").strip().lower()
    if not provider or not model:
        return ""
    return f"({provider}-{model})"


def _append_llm_signature(text: Any, provider_name: str, model_name: str) -> str:
    """Appends `(provider-model)` once, preserving the original text contract."""
    content = str(text or "").strip()
    suffix = _llm_signature_suffix(provider_name, model_name)
    if not content or not suffix:
        return content
    if content.lower().endswith(suffix.lower()):
        return content
    return f"{content} {suffix}"


def _extract_llm_decision_fields(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only the cognitive fields produced by the LLM provider."""
    if not isinstance(raw, dict):
        return {}
    return {k: raw.get(k) for k in _LLM_DECISION_FIELDS if k in raw}


class LLMAnalyzer:
    """Encapsulates the LLM provider invocation logic.

    This class is instantiated with a specific model definition or provider_override
    and provides an agnostic analysis method that works with any configured provider.
    """

    def __init__(self, model_id: str = None, provider_override: Dict[str, Any] = None):
        """Initializes the analyzer with a specific model or tenant provider_override.

        Args:
            model_id: Optional model identifier from settings catalog.
            provider_override: Optional decrypted provider config from tenant settings.
        """
        if provider_override:
            provider_name = provider_override["provider"]
            model_name = provider_override["model_name"]
            max_output_tokens = provider_override.get("max_output_tokens")
            max_input_tokens = provider_override.get("max_input_tokens")

            config = settings.get_provider_config()
            if provider_override.get("api_key"):
                config[f"{provider_name}_api_key"] = provider_override["api_key"]
            if provider_override.get("base_url"):
                config[f"{provider_name}_base_url"] = provider_override["base_url"]

            self._provider = create_llm_provider(
                provider_name=provider_name,
                model_name=model_name,
                max_output_tokens=max_output_tokens,
                max_input_tokens=max_input_tokens,
                config=config,
            )
        else:
            requested_model_id = model_id or settings.default_model_id
            model_def = settings.available_models.get(requested_model_id)

            if not model_def:
                logger.warning(
                    f"Model ID '{requested_model_id}' not found. "
                    f"Falling back to default model '{settings.default_model_id}'."
                )
                requested_model_id = settings.default_model_id
                model_def = settings.available_models.get(requested_model_id)
                if not model_def:
                    raise ValueError(f"Default model ID '{settings.default_model_id}' not found in catalog.")

            config = settings.get_provider_config()
            self._provider = create_llm_provider(
                provider_name=model_def.provider,
                model_name=model_def.model_name,
                max_output_tokens=model_def.max_output_tokens,
                max_input_tokens=model_def.max_input_tokens,
                config=config,
            )

        logger.info(
            "LLMAnalyzer initialized with provider=%s model=%s",
            self._provider.provider_name,
            self._provider.model_name,
        )

    async def analyze_with_context(self, telemetry: Any, history: list) -> Dict[str, Any]:
        """Performs the analysis by requesting the specific prompt from the active provider
        and calling the model.

        Args:
            telemetry: The analysis input telemetry.
            history: Previous alert history for context.

        Returns:
            Dictionary with LLM decision fields (threat_score, reasoning_summary, recommendation).
        """
        try:
            logger.debug("Sending analysis to provider=%s", self._provider.provider_name)

            # The provider generates its own situational prompt polymorphically
            prompt = build_web_activity_prompt(
                telemetry,
                history,
                provider_name=self._provider.provider_name
            )
            logger.debug(
                "Built analysis prompt provider=%s model=%s prompt_chars=%d history_items=%d",
                self._provider.provider_name,
                self._provider.model_name,
                len(prompt),
                len(history),
            )

            # Invoke the provider with the generated prompt
            response_text = await self._provider.call_model(prompt)
            logger.debug(
                "Received provider response provider=%s model=%s response_chars=%d",
                self._provider.provider_name,
                self._provider.model_name,
                len(response_text),
            )

            # Validate response
            validated_response = await self._provider.validate_response(response_text)

            # Enforce the cross-provider contract before returning to orchestration logic.
            decision = _extract_llm_decision_fields(validated_response.model_dump())
            decision["reasoning_summary"] = _append_llm_signature(
                decision.get("reasoning_summary"),
                self._provider.provider_name,
                self._provider.model_name,
            )
            decision["recommendation"] = _append_llm_signature(
                decision.get("recommendation"),
                self._provider.provider_name,
                self._provider.model_name,
            )
            return decision

        except Exception as exc:
            logger.error("Error in LLMAnalyzer.analyze_with_context: %s", str(exc), exc_info=True)
            raise

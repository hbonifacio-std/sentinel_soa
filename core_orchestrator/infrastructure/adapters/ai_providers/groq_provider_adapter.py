import logging
from typing import Optional

from groq import AsyncGroq
from groq.types.chat import ChatCompletionSystemMessageParam, ChatCompletionUserMessageParam
from groq.types.chat.completion_create_params import ResponseFormatResponseFormatJsonObject

from core_orchestrator.domain.exceptions.llm_exceptions import LLMException
from core_orchestrator.domain.ports.agent.ai_providers import AiProvider
from core_orchestrator.infrastructure.adapters.ai_providers.system_instructions import get_analysis_system_instructions


logger = logging.getLogger("core_orchestrator.infrastructure.adapters.ai_providers.groq_provider_adapter")

class GroqProviderAdapter(AiProvider):
    """
        GROQ adapter for the generic LLM framework.

        Encapsulates all particularities of the GROQ API,
        including authentication, generation configuration, and error handling.
        """

    _PROVIDER_NAME = "groq"

    def __init__(self, *, model_name: str, api_key: str, max_output_tokens: Optional[int] = None,
                 timeout: Optional[int] = None, max_input_tokens: Optional[int] = None):
        """
        Initialize the GROQ provider with specific configuration.

        Args:
            model_name: The specific GROQ model to use (e.g., 'mixtral-8x7b-32768').
            api_key: The API key for GROQ authentication.
            max_output_tokens: Optional maximum number of tokens for the response.
            timeout: Optional request timeout in seconds.
            max_input_tokens: Optional maximum number of tokens for the input prompt.
        """

        super().__init__(model_name, api_key, max_output_tokens)
        self._api_key = api_key
        self._model_name = model_name or "mixtral-8x7b-32768"
        self._max_tokens = max_output_tokens or 4096
        self._timeout = timeout or 60
        self._max_input_tokens = max_input_tokens or 8192

        if not self._api_key:
            raise LLMException("GROQ API key is required.")

        # Initialize GROQ async client
        self._client = AsyncGroq(
            api_key=self._api_key,
            timeout=self._timeout
        )
        logger.info(f"GroqProvider initialized for model: {self._model_name}")
    async def call_model(self, prompt: str, max_tokens: Optional[int] = 12000) -> str:
        """
              Invoke GROQ with the provided prompt.
              """
        try:
            # Rough token estimation: 1 token ~= 4 characters
            estimated_tokens = len(prompt) / 4
            if self._max_input_tokens and estimated_tokens > self._max_input_tokens:
                raise LLMException(
                    f"Input prompt exceeds max input tokens ({self._max_input_tokens}). "
                    f"Estimated tokens: {int(estimated_tokens)}"
                )

            current_max_tokens = max_tokens or self._max_tokens
            if current_max_tokens < 2048:
                current_max_tokens = 4096

            logger.debug(f"Sending prompt to GROQ ({self._model_name})")

            # Use the system instruction from prompt builder
            system_instruction = get_analysis_system_instructions()

            response = await self._client.chat.completions.create(
                model=self._model_name,
                messages=[
                    ChatCompletionSystemMessageParam(role="system", content=system_instruction),
                    ChatCompletionUserMessageParam(role= "user", content= prompt)

                ],
                max_tokens=current_max_tokens,
                temperature=0.1,
                response_format=ResponseFormatResponseFormatJsonObject(type="json_object")
            )

            if not response.choices or not response.choices[0].message.content:
                logger.error("GROQ returned empty response")
                raise LLMException("Empty response from GROQ API")

            response_text = response.choices[0].message.content.strip()
            logger.debug("Response received from GROQ successfully")
            return response_text

        except Exception as exc:
            logger.exception(f"Error in GROQ API call: {str(exc)}", exc_info=True)
            raise LLMException(f"GROQ API failure: {str(exc)}") from exc

    @property
    def provider_name(self) -> str:
        """Returns 'groq' as the unique provider identifier."""
        return self._PROVIDER_NAME

    @property
    def model_name(self) -> str:
        """Returns the exact name of the GROQ model being used."""
        return self._model_name

    async def health_check(self) -> bool:
        """
        Verify GROQ API availability.

        Makes a minimal call to the model to verify authentication
        and service availability.

        Returns:
            bool: True if available, False otherwise
        """
        try:
            logger.info("Running GROQ health check")

            # Make minimal call to verify connectivity
            response = await self._client.chat.completions.create(
                model=self._model_name,
                messages=[
                    ChatCompletionUserMessageParam(role="user", content="say Ok")

                ],
                max_tokens=10,
                temperature=0.1,
            )

            if response and response.choices and response.choices[0].message.content:
                logger.info("GROQ health check successful")
                return True
            else:
                logger.warning("GROQ health check: empty response")
                return False

        except Exception as exc:
            logger.exception(f"GROQ health check failed: {str(exc)}")
            return False

    async def close(self):
        """Close connection with GROQ."""
        if self._client:
            await self._client.close()
import logging
from typing import Optional


from openai import AsyncOpenAI
from openai.types.chat import ChatCompletionSystemMessageParam, ChatCompletionUserMessageParam
from openai.types.shared_params import ResponseFormatJSONObject

from core_orchestrator.domain.exceptions.llm_exceptions import LLMException
from core_orchestrator.domain.ports.agent.ai_providers import AiProvider
from core_orchestrator.infrastructure.adapters.ai_providers.system_instructions import get_analysis_system_instructions


logger = logging.getLogger("core_orchestrator.adapters.ai_providers.opeai_provider_adapter")
class OpeaiProviderAdapter(AiProvider):
    """
        OpenAI adapter for the generic LLM framework.

        Encapsulates all particularities of the OpenAI API,
        including authentication, generation configuration, and error handling.
        """

    _PROVIDER_NAME = "openai"

    def __init__(self, *, model_name: str, api_key: str, max_output_tokens: Optional[int] = None,
                 timeout: Optional[int] = None):
        """
        Initialize the OpenAI provider with a specific configuration.

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


    async def call_model(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """
        Invoke OpenAI with the provided prompt.

        Args:
            prompt (str): The analysis prompts
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
            system_instruction = get_analysis_system_instructions()

            response = await self._client.chat.completions.create(
                model=self._model_name,
                messages=[
                    ChatCompletionSystemMessageParam(role="system", content=system_instruction),
                    ChatCompletionUserMessageParam(role="user", content=prompt)
                ],
                max_tokens=current_max_tokens,
                temperature=0.1,
                response_format=ResponseFormatJSONObject(type="json_object")
            )

            if not response.choices or not response.choices[0].message.content:
                logger.error("OpenAI returned empty response")
                raise LLMException("Empty response from OpenAI API")

            response_text = response.choices[0].message.content.strip()
            logger.debug("Response received from OpenAI successfully")
            return response_text

        except Exception as exc:
            logger.exception(f"Error in OpenAI API call: {str(exc)}", exc_info=True)
            raise LLMException(f"OpenAI API failure: {str(exc)}") from exc


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
                    ChatCompletionUserMessageParam(role="user", content="say ok")
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
            logger.exception(f"OpenAI health check failed: {str(exc)}")
            return False

    async def close(self):
        """Close connection with OpenAI."""
        if self._client:
            await self._client.close()
import logging
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger("core_orchestrator.domain.ports.agent.ai_providers")

class AiProvider(ABC):
    """
      Abstract interface defining the contract for all LLM providers.

      Each concrete implementation (Gemini, Ollama, Claude, OpenAI) must inherit
      from this class and implement all abstract methods.
    """

    def __init__(self):
        logger.debug(f"Initializing AI provider: {self.provider_name}")

    @abstractmethod
    async def call_model(self, prompt: str, max_tokens: Optional[int] = 12000)-> str:
        """
        Invoke the LLM model with the provided prompt.

        Must return the response as a valid JSON string that can be parsed
        by validate_response().

        Args:
            prompt (str): Complete prompt with context, instructions and data to analyze
            max_tokens (Optional[int]): Response token limit (if applicable)

        Returns:
            str: Response JSON as string

        Raises:
            LLMException: If there is an error in the model call (timeout, auth, etc.)
        """
        pass


    @property
    @abstractmethod
    def provider_name(self) -> str:
        """
        Unique provider name (lowercase).

        Examples: 'gemini', 'ollama', 'claude', 'openai'

        Returns:
            str: Provider name
        """
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """
        Name of the specific model being used.

        Examples: 'gemini-1.5-flash', 'mistral', 'claude-3-sonnet'

        Returns:
            str: Model name
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Verify that the provider is available and functional.

        Must make a minimal call (without significant cost) to
        verify connectivity, authentication and service availability.

        Returns:
            bool: True if the provider is available, False otherwise
        """
        pass
import logging
from abc import ABC, abstractmethod
from typing import Optional, Any, List, Dict, Union, Type

from pydantic import BaseModel

from core_orchestrator.domain.entities.agent.agents import LLMResponse

logger = logging.getLogger("core_orchestrator.domain.ports.agent.ai_providers")

class AiProvider(ABC):

    """
      Abstract interface defining the contract for all LLM providers.

      Each concrete implementation (Gemini, Ollama, Claude, OpenAI) must inherit
      from this class and implement all abstract methods.
    """

    def __init__(
        self,
        model_name: str,
        api_key: str,
        max_output_tokens: Optional[int] = 12000,
        base_url: Optional[str] = "",
    ):
        self._model_name = model_name
        self._api_key = api_key
        self._max_output_tokens = max_output_tokens
        self._base_url = (base_url or "http://localhost:11434").rstrip("/")
        logger.debug(f"Initializing AI provider: {self.provider_name}")

    @abstractmethod
    async def call_model(self,
                         messages: Optional[List[Dict[str, Any]]] = None,
                         tools: Optional[List[Dict[str, Any]]] = None,
                         max_tokens: Optional[int] = 12000,
                         response_format: Optional[Union[Type[BaseModel], Dict[str, Any]]] = None)->LLMResponse:
        """
        This abstract method is designed to call an underlying model with a given
        prompt and optional additional inputs such as messages and tools. The method
        provides flexibility to specify the maximum number of tokens expected in the
        response. It must be implemented by subclasses and is intended to support
        asynchronous execution.

        Args:
            prompt: A string representing the prompt or input query for the model.
            messages: An optional list of dictionaries where each dictionary
                represents a message. This can be used to include prior context or
                messages for the model.
            tools: An optional list of dictionaries where each dictionary
                represents a tool or capability that may augment the model's
                functionality.
            max_tokens: An optional integer specifying the maximum number of tokens
                that the model should include in its output.

        Returns:
            A dictionary containing the output from the model. The structure and
            content of this dictionary depend on the specific model implementation and
            should be well-defined in the subclass.

        Raises:
            NotImplementedError: If the method is called directly from the base class
                without a subclass implementation.
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
        verify connectivity, authentication, and service availability.

        Returns:
            bool: True if the provider is available, False otherwise
        """
        pass
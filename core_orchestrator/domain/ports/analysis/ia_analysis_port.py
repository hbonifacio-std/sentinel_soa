from abc import ABC, abstractmethod
from typing import Dict, Any

from core_orchestrator.domain.entities.agent.agents import LLMResponseAnalyzer


class AiAnalysisPort(ABC):

    @abstractmethod
    async def analyze_activity(self, telemetry_payload: Dict[str, Any]) -> str:
        """
        Analyzes telemetry data and returns an analysis result.
        """
        pass

    @abstractmethod
    async def format_response(self, response: str) -> LLMResponseAnalyzer:
        """
        Validate and parse the model response to structured LLMResponseAnalyzer.

        Ensures the response conforms to the expected schema and handles
        deviations or format errors.

        Args:
            response (str): JSON string from the model response

        Returns:
            LLMResponseAnalyzer: Validated object with structured response

        Raises:
            ValidationError: If JSON does not conform to LLMResponseAnalyzer schema
        """

from abc import ABC, abstractmethod
from typing import Any, Dict

from core_orchestrator.domain.ports.agent.ai_providers import AiProvider


class LlmAnalysisPort(ABC):
    @abstractmethod
    async def ask_llm(self,ia_provider_client:AiProvider, prompt: str) -> Dict[str, Any]|str:
        """Executes threat analysis for a telemetry window and returns structured data."""
        pass

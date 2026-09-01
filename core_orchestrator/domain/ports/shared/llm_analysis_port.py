from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Union, Type, TypeVar

from pydantic import BaseModel

from core_orchestrator.domain.ports.agent.ai_providers import AiProvider

T = TypeVar("T", bound=BaseModel)
class LlmAnalysisPort(ABC):
    @abstractmethod
    async def ask_llm(self,ia_provider_client:AiProvider, messages: list[Dict[str, Any]],allow_mcp: bool = True,
                      max_steps: int = 5,
                      response_format: Optional[Union[Type[BaseModel], Dict[str, Any]]] = None) -> Any:
        """Executes threat analysis for a telemetry window and returns structured data."""
        pass

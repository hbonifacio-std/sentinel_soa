import json
import asyncio
import logging
import re
from typing import Any, Dict, List

from core_orchestrator.domain.ports.agent.ai_providers import AiProvider
from core_orchestrator.domain.ports.mcp_server.mcp_client_port import MCPClientPort
from core_orchestrator.domain.ports.shared.llm_analysis_port import LlmAnalysisPort


logger = logging.getLogger(__name__)
_MCP_TOOL_TIMEOUT_S = 1800.0

class LlmExecuterAnalysisAdapter(LlmAnalysisPort):
    """
    Adapter class for executing LLM-related operations and parsing their results.

    This class serves as an interface between a given AI provider client and higher-level
    application processes to facilitate the handling of interactions with
    language models. It contains methods for querying the language model and parsing
    its response for structured processing.

    Attributes:
        mcp_manager (MCPClientPort): An instance of MCPClientPort interface used to manage
            AI provider client communication.
    """

    def __init__(self, mcp_manager: MCPClientPort):
        self.mcp_manager = mcp_manager

    async def ask_llm(self,ia_provider_client: AiProvider, prompt: str) -> Dict[str, Any] | str:
        """
        Asynchronously interacts with a large language model (LLM) provider, sending a prompt and processing
        the result. Handles timeouts and exceptions during the interaction.

        Args:
            ia_provider_client (AiProvider): The client interface that communicates with the
            LLM provider

            prompt (str): The input prompt to be sent to the LLM provider

        Returns:
            Dict[str, Any] | str: Either the processed result from the LLM or an error response in
            case of timeout or exception.
        """
        try:
            mcp_tools = await self.mcp_manager.get_tool_list()
            messages: List[Dict[str, Any]] = [
                {"role": "user", "content": prompt}
            ]

            logger.info("mcp_tools: %s", mcp_tools.tools)
            raw_result = await asyncio.wait_for(
                ia_provider_client.call_model(prompt=prompt),
                timeout=_MCP_TOOL_TIMEOUT_S
            )

            return self._parse_result(raw_result)
        except asyncio.TimeoutError:
            logger.error(
                "error time out calling llm provider"

            )
            return {
                "response": "error time out calling llm provider"
            }
        except Exception as exc:
            logger.exception(
                "error calling llm provider:",
                exc,
                exc_info=True,
            )
            return {
                "response": "error calling llm provider:"
            }

    @staticmethod
    def _parse_json_object(text: str) -> Dict[str, Any] | None:
        if not text:
            return None

        def _as_dict(candidate: str) -> Dict[str, Any] | None:
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                return None
            return parsed if isinstance(parsed, dict) else None

        stripped = text.strip()
        if parsed := _as_dict(stripped):
            return parsed

        fenced_matches = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, flags=re.IGNORECASE | re.DOTALL)
        for candidate in fenced_matches:
            if parsed := _as_dict(candidate.strip()):
                return parsed

        first_brace = stripped.find("{")
        last_brace = stripped.rfind("}")
        if first_brace != -1 and last_brace > first_brace:
            candidate = stripped[first_brace:last_brace + 1]
            if parsed := _as_dict(candidate):
                return parsed

        return None

    @staticmethod
    def _parse_result(raw_result: Any) -> Dict[str, Any]:
        if isinstance(raw_result, dict):
            return raw_result

        if hasattr(raw_result, "content") and raw_result.content:
            for content_item in raw_result.content:
                text_value = getattr(content_item, "text", "")
                parsed = LlmExecuterAnalysisAdapter._parse_json_object(text_value)
                if parsed is not None:
                    return parsed
            logger.error("Could not parse JSON from analyze_web_activity. Using empty fallback.")
            return {"threat_detected": False, "threat_score": 0}

        if isinstance(raw_result, str):
            parsed = LlmExecuterAnalysisAdapter._parse_json_object(raw_result)
            if parsed is not None:
                return parsed
            return {"response": raw_result}

        return {}

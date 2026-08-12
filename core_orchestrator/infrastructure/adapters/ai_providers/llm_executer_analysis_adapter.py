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

    async def ask_llm(
            self,
            ia_provider_client: AiProvider,
            prompt: str,
            allow_mcp: bool = True,
            max_steps: int = 5,
    ) -> Dict[str, Any]:
        """
        Asynchronously interacts with an LLM provider, execution loop for MCP tools,
        handling timeouts and exceptions cleanly.
        """
        try:
            # 1. Obtener herramientas de forma segura
            mcp_tools = await self.mcp_manager.get_tool_list() if allow_mcp else None
            tools_payload = mcp_tools.tools if mcp_tools else None

            messages: List[Dict[str, Any]] = [{"role": "user", "content": prompt}]
            raw_result = None

            for _ in range(max_steps):
                raw_result = await asyncio.wait_for(
                    ia_provider_client.call_model(
                        prompt=prompt,
                        messages=messages,
                        tools=tools_payload,
                    ),
                    timeout=_MCP_TOOL_TIMEOUT_S
                )

                # Verificar si el modelo solicitó llamar a alguna herramienta
                has_tool_calls = getattr(raw_result, "tool_calls", None) or (
                    raw_result.get("tool_calls") if isinstance(raw_result, dict) else None
                )

                if not allow_mcp or not has_tool_calls:
                    return self._parse_result(raw_result)

                # Agregar la respuesta del asistente al historial
                messages.append({
                    "role": "assistant",
                    "content": raw_result.get("content", ""),
                    "tool_calls": has_tool_calls
                })

                # Ejecutar cada llamada a herramienta indicada por el modelo
                for tool_call in has_tool_calls:
                    tool_name = tool_call["function"]["name"]
                    tool_args = tool_call["function"]["arguments"]

                    tool_result = await self.mcp_manager.call_tool(
                        tool_name=tool_name,
                        arguments=tool_args
                    )

                    # Formatear la respuesta a cadena de texto (string)
                    if hasattr(tool_result, "structuredContent") and tool_result.structuredContent:
                        content_str = json.dumps(tool_result.structuredContent)
                    elif isinstance(tool_result, dict) and "structuredContent" in tool_result:
                        content_str = json.dumps(tool_result["structuredContent"])
                    else:
                        content_str = str(tool_result)

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.get("id"),
                        "name": tool_name,
                        "content": content_str
                    })

            return self._parse_result(raw_result)

        except asyncio.TimeoutError:
            logger.error("Timeout calling LLM provider")
            return {
                "analysis": "Error: Timeout calling LLM provider.",
                "threat_level": "UNKNOWN",
                "summary": "LLM query timed out."
            }
        except Exception as exc:
            logger.exception("Error calling LLM provider: %s", exc)
            return {
                "analysis": f"Error calling LLM provider: {str(exc)}",
                "threat_level": "UNKNOWN",
                "summary": "LLM execution failed."
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

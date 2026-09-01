import json
import asyncio
import logging
import re
from typing import Any, Dict, List, Optional, Union, Type, TypeVar
from pydantic import BaseModel, ValidationError

from core_orchestrator.domain.ports import LlmAnalysisPort

logger = logging.getLogger(__name__)
_MCP_TOOL_TIMEOUT_S = 1800.0
T = TypeVar("T", bound=BaseModel)


class LlmExecuterAnalysisAdapter(LlmAnalysisPort):
    """
    Orquestador agnóstico de LLM.
    Mantiene el historial en formato genérico y coordina la ejecución de herramientas MCP.
    """

    def __init__(self, mcp_manager: Any):
        self.mcp_manager = mcp_manager

    async def ask_llm(
        self,
        ia_provider_client: Any,
        messages: list[Dict[str, Any]],
        allow_mcp: bool = True,
        max_steps: int = 5,
        response_format: Optional[Union[Type[BaseModel], Dict[str, Any]]] = None,
    ) -> Union[BaseModel, Dict[str, Any], str]:

        try:
            response: Optional[Any] = None

            # 1. Obtener herramientas si están permitidas
            tools_payload = None
            if allow_mcp:
                mcp_tools = await self.mcp_manager.get_tool_list()
                tools_payload = mcp_tools.tools


            for step in range(max_steps):
                response = await asyncio.wait_for(
                    ia_provider_client.call_model(
                        messages=messages,
                        tools=tools_payload,
                        response_format=response_format,
                    ),
                    timeout=_MCP_TOOL_TIMEOUT_S,
                )

                if response is None:
                    return {"error": "No response from LLM provider"}

                # Si el modelo terminó y no solicitó ejecutar herramientas
                if not response.has_tool_calls:
                    return self._parse_result(response.content, response_format=response_format)

                # 3. Registrar la intención del asistente en el historial
                assistant_msg = {
                    "role": "assistant",
                    "content": response.content or "",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "function": {"name": tc.name, "arguments": tc.arguments},
                            "raw_function_call": getattr(tc, "raw_function_call", None),
                            "thought_signature": getattr(tc, "thought_signature", None),
                        }
                        for tc in response.tool_calls
                    ],
                }

                if hasattr(response, "raw_response") and response.raw_response:
                    assistant_msg["raw_response"] = response.raw_response

                messages.append(assistant_msg)

                # 4. Ejecutar las herramientas e insertar resultados en el historial
                await self._process_tool_calls(response, messages)

            # Si alcanzó el número máximo de pasos
            if response is not None:
                return self._parse_result(response.content, response_format=response_format)

            return {}

        except asyncio.TimeoutError:
            logger.error("Timeout calling LLM provider")
            return {"error": "Timeout calling LLM provider."}
        except Exception as exc:
            logger.exception("Error executing LLM loop: %s", exc)
            return {"error": f"LLM execution failed: {str(exc)}"}

    async def _process_tool_calls(
        self,
        response: Any,
        messages: List[Dict[str, Any]],
    ) -> None:
        """Ejecuta las herramientas invocadas por el LLM y añade sus respuestas al historial."""
        for tool_call in response.tool_calls:
            logger.info(f"[MCP] Executing tool '{tool_call.name}' with args: {tool_call.arguments}")

            tool_result = await self.mcp_manager.call_tool(
                tool_name=tool_call.name,
                arguments=tool_call.arguments,
            )

            # Serializar la respuesta a un string
            if hasattr(tool_result, "structuredContent") and tool_result.structuredContent:
                content_str = json.dumps(tool_result.structuredContent)
            elif isinstance(tool_result, dict) and "structuredContent" in tool_result:
                content_str = json.dumps(tool_result["structuredContent"])
            else:
                content_str = str(tool_result)

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "name": tool_call.name,
                "content": content_str,
            })

    @staticmethod
    def _parse_json_object(text: str) -> Optional[Dict[str, Any]]:
        if not text:
            return None

        def _as_dict(c: str) -> Optional[Dict[str, Any]]:
            try:
                p = json.loads(c)
                return p if isinstance(p, dict) else None
            except json.JSONDecodeError:
                return None

        stripped = text.strip()

        if parsed := _as_dict(stripped):
            return parsed

        fenced_matches = re.findall(r"```(?:json)?\s*({[^{}]*})\s*```", stripped, flags=re.IGNORECASE | re.DOTALL)
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
    def _parse_result(
        raw_input: Any,
        response_format: Optional[Union[Type[BaseModel], Dict[str, Any]]] = None,
    ) -> Any:
        """
        Convierte cualquier tipo de entrada (string, dict, Pydantic) al formato final deseado.
        Si response_format es una subclase de BaseModel, garantiza que retorne una instancia Pydantic.
        """
        is_pydantic_target = (
            response_format is not None
            and isinstance(response_format, type)
            and issubclass(response_format, BaseModel)
        )

        # Caso 1: La entrada ya es una instancia Pydantic
        if isinstance(raw_input, BaseModel):
            if is_pydantic_target and not isinstance(raw_input, response_format):
                try:
                    return response_format.model_validate(raw_input.model_dump())
                except ValidationError as err:
                    logger.warning("Error re-validating Pydantic model: %s", err)
            return raw_input

        # Caso 2: La entrada es un diccionario
        if isinstance(raw_input, dict):
            if is_pydantic_target:
                try:
                    return response_format.model_validate(raw_input)
                except ValidationError as err:
                    logger.warning("Error validating Pydantic model from dict: %s", err)
            return raw_input

        # Caso 3: La entrada es un texto / string
        text_content = str(raw_input) if raw_input is not None else ""
        if not text_content:
            return {}

        parsed_dict = LlmExecuterAnalysisAdapter._parse_json_object(text_content)
        if parsed_dict is None:
            parsed_dict = {"response": text_content}

        if is_pydantic_target:
            try:
                return response_format.model_validate(parsed_dict)
            except ValidationError as err:
                logger.warning("Error validating Pydantic model from parsed JSON: %s", err)
                return parsed_dict

        return parsed_dict
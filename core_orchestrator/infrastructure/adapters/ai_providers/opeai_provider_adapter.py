import json
import logging
from typing import Optional, List, Dict, Any, Type, Union

from openai import AsyncOpenAI
from openai.types.chat import ChatCompletionSystemMessageParam, ChatCompletionUserMessageParam
from openai.types.shared_params import ResponseFormatJSONObject
from pydantic import BaseModel

from core_orchestrator.domain.entities.agent.agents import LLMResponse, ToolCall
from core_orchestrator.domain.exceptions.llm_exceptions import LLMException
from core_orchestrator.domain.ports.agent.ai_providers import AiProvider
from core_orchestrator.infrastructure.adapters.ai_providers.system_instructions import get_analysis_system_instructions


logger = logging.getLogger("core_orchestrator.adapters.ai_providers.opeai_provider_adapter")


class OpenAiProviderAdapter(AiProvider):
    """
    OpenAI adapter for the generic LLM framework.
    Compatible con Tool Calling (MCP) y respuesta estructurada (Pydantic).
    """

    _PROVIDER_NAME = "openai"

    def __init__(
            self,
            *,
            model_name: str,
            api_key: str,
            base_url: Optional[str] = None,
            max_output_tokens: Optional[int] = None,
            timeout: Optional[int] = None,
    ):
        super().__init__(model_name, api_key, max_output_tokens)
        self._api_key = api_key
        self._model_name = model_name or "gpt-4o-mini"
        self._max_tokens = max_output_tokens or 10000
        self._timeout = timeout or 60

        if not self._api_key:
            raise LLMException("OpenAI API key is required.")

        self._client = AsyncOpenAI(
            api_key=self._api_key,
            timeout=self._timeout
        )
        logger.info(f"OpenAIProvider initialized for model: {self._model_name}")

    async def call_model( self,
                         messages: Optional[List[Dict[str, Any]]] = None,
                         tools: Optional[List[Dict[str, Any]]] = None,
                         max_tokens: Optional[int] = 12000,
                         response_format: Optional[Union[Type[BaseModel], Dict[str, Any]]] = None)->LLMResponse:
        """
        Invoca el modelo de OpenAI procesando historial de mensajes, herramientas e instrucciones de salida.
        Devuelve un objeto unificado LLMResponse.
        """
        try:
            current_max_tokens = max_tokens or self._max_tokens

            # 1. Mapear mensajes al formato nativo de OpenAI
            formatted_messages = self._map_messages_to_openai(messages)

            # 2. Mapear herramientas MCP al formato exigido por OpenAI
            formatted_tools = self._map_tools_to_openai(tools) if tools else None

            # 3. Mapear formato de respuesta (Structured Outputs / JSON) si no hay herramientas activas
            parsed_response_format = None
            if response_format and not formatted_tools:
                parsed_response_format = self._map_response_format(response_format)

            kwargs: Dict[str, Any] = {
                "model": self._model_name,
                "messages": formatted_messages,
                "max_completion_tokens": current_max_tokens,
                "temperature": 0.1,
            }

            if formatted_tools:
                kwargs["tools"] = formatted_tools
                kwargs["tool_choice"] = "auto"

            if response_format:
                kwargs["response_format"] = self._map_response_format(response_format)

            logger.debug(f"Calling OpenAI model '{self._model_name}' with {len(formatted_messages)} messages")


            # 4. Ejecutar la llamada a la API de OpenAI
            response = await self._client.chat.completions.create(**kwargs)

            if not response.choices:
                logger.error("OpenAI returned an empty choices list")
                raise LLMException("Empty response from OpenAI API")

            message = response.choices[0].message
            content = message.content or ""

            # 5. Extraer llamadas a herramientas mapeando directamente a tu clase ToolCall
            tool_calls = []
            if message.tool_calls:
                for tc in message.tool_calls:
                    try:
                        args = json.loads(tc.function.arguments) if isinstance(tc.function.arguments,
                                                                               str) else tc.function.arguments
                    except json.JSONDecodeError:
                        args = {}

                    tool_calls.append(
                        ToolCall(
                            id=tc.id,
                            name=tc.function.name,
                            arguments=args
                        )
                    )

            # 6. Retornar la instancia de LLMResponse
            return LLMResponse(
                content=content,
                tool_calls=tool_calls,
                raw_response=response
            )

        except Exception as exc:
            logger.exception(f"Error in OpenAI API call: {str(exc)}", exc_info=True)
            raise LLMException(f"OpenAI API failure: {str(exc)}") from exc

    def _map_messages_to_openai(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Mapea el historial canónico del ejecutor al formato de mensajes de OpenAI."""
        formatted = []
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content", "")

            if role == "user":
                formatted.append({"role": "user", "content": content})

            elif role == "assistant":
                item: Dict[str, Any] = {"role": "assistant", "content": content or None}

                # Si en el historial había llamadas a herramientas registradas previamente
                if msg.get("tool_calls"):
                    item["tool_calls"] = [
                        {
                            "id": tc["id"],
                            "type": "function",
                            "function": {
                                "name": tc["function"]["name"],
                                "arguments": json.dumps(tc["function"]["arguments"])
                                if isinstance(tc["function"]["arguments"], dict)
                                else tc["function"]["arguments"],
                            },
                        }
                        for tc in msg["tool_calls"]
                    ]
                formatted.append(item)

            elif role == "tool":
                formatted.append({
                    "role": "tool",
                    "tool_call_id": msg.get("tool_call_id"),
                    "content": str(msg.get("content", "")),
                })

            elif role == "system":
                formatted.append({"role": "system", "content": content})

        return formatted

    def _map_tools_to_openai(self, tools: List[Any]) -> List[Dict[str, Any]]:
        """Mapea las herramientas entregadas por MCP al formato que espera OpenAI."""
        formatted_tools = []
        for tool in tools:
            if isinstance(tool, dict):
                name = tool.get("name")
                description = tool.get("description", "")
                parameters = tool.get("inputSchema", tool.get("parameters", {}))
            else:
                name = getattr(tool, "name", "")
                description = getattr(tool, "description", "")
                parameters = getattr(tool, "inputSchema", getattr(tool, "parameters", {}))

            formatted_tools.append({
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": parameters,
                },
            })
        return formatted_tools

    def _map_response_format(
            self, response_format: Union[Type[BaseModel], Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Genera el parámetro response_format adecuado para OpenAI."""
        if isinstance(response_format, type) and issubclass(response_format, BaseModel):
            schema = response_format.model_json_schema()

            # FIX 2: Strict JSON Schema requires additionalProperties = False
            schema["additionalProperties"] = False

            return {
                "type": "json_schema",
                "json_schema": {
                    "name": response_format.__name__,
                    "schema": schema,
                    "strict": True,
                },
            }
        elif isinstance(response_format, dict):
            return response_format

        return {"type": "json_object"}

    @property
    def provider_name(self) -> str:
        return self._PROVIDER_NAME

    @property
    def model_name(self) -> str:
        return self._model_name

    async def health_check(self) -> bool:
        """Comprueba la conectividad con OpenAI haciendo una llamada mínima."""
        try:
            logger.info("Running OpenAI health check")
            response = await self._client.chat.completions.create(
                model=self._model_name,
                messages=[{"role": "user", "content": "say ok"}],
                max_tokens=10,
                temperature=0.1
            )
            if response and response.choices and response.choices[0].message.content:
                logger.info("OpenAI health check successful")
                return True
            return False
        except Exception as exc:
            logger.exception(f"OpenAI health check failed: {str(exc)}")
            return False

    async def close(self):
        """Cierra el cliente asíncrono de OpenAI."""
        if self._client:
            await self._client.close()
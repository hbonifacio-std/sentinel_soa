import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Type, Union

from google.genai.errors import APIError
from pydantic import BaseModel

from google import genai
from google.genai import types

from core_orchestrator.domain.entities.agent.agents import LLMResponse, ToolCall
from core_orchestrator.domain.exceptions.llm_exceptions import LLMConfigurationException, LLMEmptyResponseException, \
    LLMLimitExceededException, LLMException
from core_orchestrator.domain.ports.agent.ai_providers import AiProvider
from core_orchestrator.infrastructure.adapters.ai_providers.system_instructions import get_analysis_system_instructions

logger = logging.getLogger(__name__)


class GeminiProviderAdapter(AiProvider):
    """Adaptador específico para la API de Gemini utilizando la SDK oficial google-genai.

    Absorbe toda la transformación de tipos y esquemas que requiere Gemini.
    """

    _PROVIDER_NAME = "gemini"

    def __init__(
        self,
        *,
        model_name: str,
        api_key: str,
        base_url: Optional[str] = None,
        max_output_tokens: Optional[int] = None,
        timeout: Optional[int] = None,
        **kwargs: Any,
    ):
        super().__init__(model_name, api_key, max_output_tokens)
        self._api_key = api_key
        self._model_name = model_name
        self._max_tokens = max_output_tokens or 4160
        self._max_retries = 2
        self._timeout = timeout or 180

        if not self._api_key:
            raise LLMConfigurationException("Gemini API key is required.")

        self._client = genai.Client(api_key=self._api_key)
        logger.info(
            f"GeminiProvider initialized (google-genai) for model: {self._model_name}"
        )

    @property
    def provider_name(self) -> str:
        return self._PROVIDER_NAME

    @property
    def model_name(self) -> str:
        return self._model_name

    async def health_check(self) -> bool:
        """Comprueba el estado de conexión con el servicio de Gemini."""
        try:
            logger.info("Running Gemini health check")
            response = await asyncio.wait_for(
                self._client.aio.models.generate_content(
                    model=self._model_name,
                    contents="ping",
                ),
                timeout=10.0,
            )
            if response and hasattr(response, "text") and response.text:
                logger.info("Gemini health check successful")
                return True
            logger.warning("Gemini health check: empty response")
            return False
        except Exception as exc:
            logger.exception(f"Gemini health check failed: {str(exc)}")
            return False

    async def call_model(
        self,
        messages: Optional[List[Dict[str, Any]]] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[
            Union[Type[BaseModel], Dict[str, Any]]
        ] = None,
    ) -> LLMResponse:
        safe_messages = messages or []
        contents = self._map_messages_to_gemini(safe_messages)
        effective_max_tokens = max_tokens or self._max_tokens
        system_instruction = get_analysis_system_instructions()

        response_mime_type = None
        response_schema = None

        if response_format:
            if not tools:
                response_mime_type = "application/json"
                if isinstance(response_format, type) and issubclass(
                    response_format, BaseModel
                ):
                    response_schema = response_format
            else:
                schema_hint = ""
                if isinstance(response_format, type) and issubclass(
                    response_format, BaseModel
                ):
                    schema_hint = json.dumps(
                        response_format.model_json_schema()
                    )
                elif isinstance(response_format, dict):
                    schema_hint = json.dumps(response_format)

                if schema_hint:
                    system_instruction += (
                        f"\n\nIMPORTANT: Respond strictly in valid JSON matching this schema:\n{schema_hint}"
                    )

        config = types.GenerateContentConfig(
            temperature=0.1,
            max_output_tokens=effective_max_tokens,
            system_instruction=system_instruction,
            response_mime_type=response_mime_type,
            response_schema=response_schema,
        )

        if tools:
            config.tools = self._format_tools_for_gemini(tools)

        last_exception = None
        for attempt in range(1, self._max_retries + 1):
            try:
                response = await asyncio.wait_for(
                    self._client.aio.models.generate_content(
                        model=self._model_name,
                        contents=contents,
                        config=config,
                    ),
                    timeout=float(self._timeout),
                )

                if not response:
                    raise LLMEmptyResponseException(
                        "Empty response from Gemini API"
                    )

                tool_calls = []
                if response.function_calls:
                    for idx, fc in enumerate(response.function_calls):
                        raw_args = dict(fc.args) if fc.args else {}
                        clean_args: Dict[str, Any] = {
                            str(k): v for k, v in raw_args.items()
                        }
                        raw_id = getattr(fc, "id", None)
                        call_id = (
                            raw_id
                            if raw_id is not None
                            else f"call_gemini_{idx}"
                        )

                        # Extraer thought_signature si viene presente en la respuesta
                        thought_sig = getattr(fc, "thought_signature", None) or getattr(
                            fc, "thought", None
                        )

                        tool_calls.append(
                            ToolCall(
                                id=str(call_id),
                                name=fc.name,
                                arguments=clean_args,
                                raw_function_call=fc,
                                thought_signature=thought_sig,
                            )
                        )

                # Extraer texto de forma segura
                content_text = ""
                if hasattr(response, "text") and response.text:
                    content_text = response.text
                elif (
                    response.candidates
                    and response.candidates[0].content
                    and response.candidates[0].content.parts
                ):
                    text_parts = [
                        part.text
                        for part in response.candidates[0].content.parts
                        if hasattr(part, "text") and part.text
                    ]
                    content_text = "".join(text_parts)

                return LLMResponse(
                    content=content_text,
                    tool_calls=tool_calls,
                    raw_response=response,  # Preserva el objeto Candidate / Content nativo
                )

            except APIError as exc:
                last_exception = exc
                if exc.code in (503, 429) and attempt < self._max_retries:
                    backoff = attempt * 2
                    logger.warning(
                        f"Gemini API status {exc.code}. Retrying attempt {attempt}/{self._max_retries} in {backoff}s..."
                    )
                    await asyncio.sleep(backoff)
                    continue
                break
            except asyncio.TimeoutError as exc:
                logger.error(f"Gemini call timed out after {self._timeout}s")
                raise LLMLimitExceededException(
                    f"Gemini API timed out after {self._timeout}s"
                ) from exc
            except Exception as exc:
                logger.exception(
                    f"Unexpected error in Gemini API call: {str(exc)}"
                )
                raise LLMException(f"Gemini API failure: {str(exc)}") from exc

        raise LLMException(f"Gemini API failed: {str(last_exception)}")

    # =========================================================================
    #  MÉTODOS PRIVADOS DE ADAPTACIÓN (EXCLUSIVOS DE GEMINI)
    # =========================================================================

    def _clean_mcp_schema(self, schema: Any) -> Any:
        """Remueve recursivamente los booleanos que el SDK de Gemini no soporta en JSON Schema."""
        if hasattr(schema, "model_dump"):
            schema = schema.model_dump(mode="json")
        elif hasattr(schema, "__dict__") and not isinstance(schema, type):
            schema = getattr(schema, "__dict__")

        if isinstance(schema, dict):
            cleaned = {}
            for k, v in schema.items():
                if k == "additionalProperties" and isinstance(v, bool):
                    continue
                cleaned[k] = self._clean_mcp_schema(v)
            return cleaned
        elif isinstance(schema, list):
            return [self._clean_mcp_schema(item) for item in schema]
        return schema

    def _format_tools_for_gemini(self, tools: List[Any]) -> List[types.Tool]:
        """Convierte herramientas MCP/OpenAI en instancias de types.Tool."""
        function_declarations = []

        for tool in tools:
            if hasattr(tool, "model_dump"):
                raw_tool = tool.model_dump(mode="json")
            elif isinstance(tool, dict):
                raw_tool = tool
            else:
                raw_tool = {
                    "name": getattr(tool, "name", None),
                    "description": getattr(tool, "description", ""),
                    "inputSchema": getattr(
                        tool,
                        "inputSchema",
                        getattr(tool, "parameters", None),
                    ),
                }

            cleaned_tool = self._clean_mcp_schema(raw_tool)

            name = cleaned_tool.get("name") or cleaned_tool.get(
                "function", {}
            ).get("name")
            description = cleaned_tool.get("description") or cleaned_tool.get(
                "function", {}
            ).get("description", "")
            parameters = (
                cleaned_tool.get("inputSchema")
                or cleaned_tool.get("parameters")
                or cleaned_tool.get("function", {}).get("parameters")
            )

            if name:
                function_declarations.append(
                    types.FunctionDeclaration(
                        name=name,
                        description=description,
                        parameters=parameters,
                    )
                )

        return (
            [types.Tool(function_declarations=function_declarations)]
            if function_declarations
            else []
        )

    def _map_messages_to_gemini(
        self, messages: List[Dict[str, Any]]
    ) -> List[types.Content]:
        """Convierte la lista genérica de mensajes al formato types.Content que consume Gemini.

        Garantiza la preservación del `thought_signature` e instancias nativas de `parts`.
        """
        formatted_contents = []

        for msg in messages:
            role = msg.get("role")
            content = msg.get("content", "")

            if role == "user":
                formatted_contents.append(
                    types.Content(
                        role="user", parts=[types.Part.from_text(text=content)]
                    )
                )

            elif role == "assistant":
                # 1. SI EXISTE EL raw_response ORIGINAL DE GEMINI, LO USAMOS DIRECTAMENTE.
                # Esto garantiza retener intactos el 'thought_signature', 'function_call' y metadatos.
                raw_response = msg.get("raw_response")
                if (
                    raw_response
                    and hasattr(raw_response, "candidates")
                    and raw_response.candidates
                ):
                    candidate_content = raw_response.candidates[0].content
                    if candidate_content:
                        formatted_contents.append(candidate_content)
                        continue

                # 2. Si vinieron partes crudas explícitas (raw_parts)
                raw_parts = msg.get("raw_parts")
                if raw_parts:
                    formatted_contents.append(
                        types.Content(role="model", parts=raw_parts)
                    )
                    continue

                # 3. Fallback de reconstrucción si el mensaje proviene de otro proveedor o fue sintetizado
                parts = []
                if content:
                    parts.append(types.Part.from_text(text=content))

                for tc in msg.get("tool_calls", []):
                    # Si la llamada conserva la instancia original de function_call
                    if hasattr(tc, "raw_function_call") and tc.raw_function_call:
                        parts.append(types.Part(function_call=tc.raw_function_call))
                    else:
                        func_data = (
                            tc.get("function", {})
                            if isinstance(tc, dict)
                            else getattr(tc, "function", {})
                        )
                        name = (
                            func_data.get("name")
                            if isinstance(func_data, dict)
                            else getattr(tc, "name", None)
                        )
                        args = (
                            func_data.get("arguments", {})
                            if isinstance(func_data, dict)
                            else getattr(tc, "arguments", {})
                        )
                        thought_signature = (
                            tc.get("thought_signature")
                            if isinstance(tc, dict)
                            else getattr(tc, "thought_signature", None)
                        )

                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except Exception:
                                args = {}

                        # Construir la llamada garantizando thought_signature
                        part_kwargs = {"name": name, "args": args}
                        if thought_signature:
                            part_kwargs["thought_signature"] = thought_signature

                        parts.append(
                            types.Part.from_function_call(**part_kwargs)
                        )

                formatted_contents.append(
                    types.Content(role="model", parts=parts)
                )

            elif role == "tool":
                tool_name = msg.get("name", "unknown")
                raw_content = msg.get("content", "")

                if isinstance(raw_content, str):
                    try:
                        response_dict = json.loads(raw_content)
                    except Exception:
                        response_dict = {"output": raw_content}
                elif isinstance(raw_content, dict):
                    response_dict = raw_content
                else:
                    response_dict = {"output": str(raw_content)}

                if not isinstance(response_dict, dict):
                    response_dict = {"result": response_dict}

                # En el SDK google-genai, la respuesta de una herramienta se envía bajo el rol 'user'
                # con la parte 'from_function_response'.
                formatted_contents.append(
                    types.Content(
                        role="user",
                        parts=[
                            types.Part.from_function_response(
                                name=tool_name,
                                response=response_dict,
                            )
                        ],
                    )
                )

        return formatted_contents


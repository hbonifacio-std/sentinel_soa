import json
import logging
from typing import Optional, List, Dict, Any, Union, Type

import httpx
from httpx import Timeout
from pydantic import BaseModel

from core_orchestrator.domain.entities.agent.agents import LLMResponse
from core_orchestrator.domain.exceptions.llm_exceptions import LLMException, LLMConfigurationException
from core_orchestrator.domain.ports.agent.ai_providers import AiProvider

logger = logging.getLogger("core_orchestrator.adapters.ai_providers.ollama_provider_adapter")
class OllamaProviderAdapter(AiProvider):
    """
        Ollama adapter for the generic LLM framework.

        Allows running local LLM entities (Mistral, Llama2, etc.) without
        external API dependencies, ideal for development and testing.

        Requires Ollama to be running (typically in Docker):
            docker run -d -p 11434:11434 ollama/ollama
            docker exec <container_id> ollama pull mistral
        """

    _PROVIDER_NAME = "ollama"
    _TIMEOUT_SECONDS = 1800
    _MAX_OUTPUT_TOKENS = 1000

    def __init__(self, api_key: str, *, model_name: str, base_url: str, timeout: Optional[int] = None, max_output_tokens: Optional[int] = None):
        """
        Initialize the Ollama provider with a specific configuration.

        Args:
            model_name: The specific Ollama model to use (e.g., 'mistral').
            base_url: The base URL of the Ollama server.
            timeout: Optional request timeout in seconds.
        """

        super().__init__(model_name, api_key,max_output_tokens=max_output_tokens)
        self._base_url = (base_url or "http://localhost:11434").rstrip("/")
        self._model_name = model_name or "mistral"
        self._timeout = timeout or self._TIMEOUT_SECONDS
        self._client = None

        if not self._model_name or not model_name.strip():
            raise LLMConfigurationException("Ollama model name is required.")

        if not base_url or not base_url.strip():
            raise LLMConfigurationException("Ollama base URL is required.")

        logger.info(f"OllamaProvider initialized for model: {self._model_name} at {self._base_url}")

    def _get_client(self) -> httpx.AsyncClient:
        """
        Get or create an asynchronous HTTP client for Ollama.

        Reuses a single client instance for the lifetime of the provider.

        Returns:
            httpx.AsyncClient: Client with configured timeout
        """
        if self._client is None:
            structured_timeout = Timeout(
                timeout=float(self._timeout),
                read=float(self._timeout),
                connect=10.0,
            )
            self._client = httpx.AsyncClient(timeout=structured_timeout)
        return self._client

    def _validate_and_format_tools(self, tools: Any) -> List[Dict[str, Any]]:
        """
        Garantiza que cualquier formato de tools (MCP SDK, dicts simples, etc.)
        sea convertido a un JSON Schema compatible con la API de Ollama.
        """
        if not tools:
            return []

        raw_tools = getattr(tools, "tools", tools)
        if not isinstance(raw_tools, list):
            raw_tools = [raw_tools]

        formatted_tools = []
        for tool in raw_tools:
            if isinstance(tool, dict) and "function" in tool:
                formatted_tools.append(tool)
            elif isinstance(tool, dict):
                formatted_tools.append({
                    "type": "function",
                    "function": {
                        "name": tool.get("name", ""),
                        "description": tool.get("description", ""),
                        "parameters": tool.get("parameters") or tool.get("inputSchema") or {"type": "object",
                                                                                            "properties": {}}
                    }
                })
            else:
                # Objeto Tool nativo de MCP SDK
                name = getattr(tool, "name", "")
                description = getattr(tool, "description", "")
                input_schema = getattr(tool, "inputSchema", {})

                if hasattr(input_schema, "model_dump"):
                    input_schema = input_schema.model_dump()
                elif hasattr(input_schema, "dict"):
                    input_schema = input_schema.dict()

                if name:
                    formatted_tools.append({
                        "type": "function",
                        "function": {
                            "name": name,
                            "description": description,
                            "parameters": input_schema or {"type": "object", "properties": {}}
                        }
                    })
        return formatted_tools

    async def call_model(self,
                         prompt: str,
                         messages: Optional[List[Dict[str, Any]]] = None,
                         tools: Optional[List[Dict[str, Any]]] = None,
                         max_tokens: Optional[int] = 12000,
                         response_format: Optional[Union[Type[BaseModel], Dict[str, Any]]] = None
                         ) -> LLMResponse:
        """
        Asynchronously sends a request to a language model to process the provided prompt
        and optional context, while supporting configurable behavior such as token limits
        and integration with external tools.

        Parameters:
            prompt: str
                A string input provided as the main prompt to the language model.
            messages: Optional[List[Dict[str, Any]]]
                A list of dictionaries representing prior conversation messages. Each
                dictionary typically includes keys such as "role" and "content".
                If not provided, and a prompt is specified, a default single-user message
                is crafted based on the prompt.
            tools: Optional[List[Dict[str, Any]]]
                An optional list of dictionaries representing external tools to be
                incorporated during the operation.
            max_tokens: Optional[int]
                The maximum number of tokens to be considered for the response.

        Returns:
            str
                The textual message returned by the language model after processing the
                request.

        Raises:
            LLMException
                Raised when the response is empty or any other issue occurs during
                the interaction with the language model.
        """
        client = self._get_client()
        url = f"{self._base_url}/api/chat"
        formatted_messages = messages or []
        if not formatted_messages and prompt:
            formatted_messages = [{"role": "user", "content": prompt}]

        formatted_tools = self._validate_and_format_tools(tools)
        if formatted_tools:
            system_instruction = (
                "SYSTEM INSTRUCTION: You have access to external tools. "
                "If you need more information to answer, you MUST invoke a tool using the native tool_calls structure. "
                "If you already have enough information or no further tool execution is required, respond directly with text."
            )

            if formatted_messages and formatted_messages[0].get("role") == "system":
                formatted_messages[0]["content"] += f"\n\n{system_instruction}"
            else:
                formatted_messages.insert(0, {"role": "system", "content": system_instruction})

        payload: Dict[str, Any] = {
            "model": self._model_name,
            "messages": formatted_messages,
            "stream": False,
        }

        # Si hay tools y no estamos en la llamada forzada de JSON final
        if formatted_tools:
            payload["tools"] = formatted_tools

            # Solo forzamos format json en la primera llamada si NO hay tools
        if not formatted_tools and response_format:
            payload["format"] = "json"

        if formatted_tools:
            payload["tools"] = formatted_tools

        try:
            logger.debug(f"Sending request to Ollama: {url}")
            logger.info(payload)
            response = await client.post(url, json=payload, timeout=self._timeout)
            response.raise_for_status()

            result = response.json()
            message = result.get("message", {})
            if not message:
                logger.error("Ollama returned empty message response")
                raise LLMException("Empty response from Ollama")

            has_tool_calls = message.get("tool_calls")

            if not has_tool_calls and message.get("content"):
                try:
                    content_json = json.loads(message["content"].strip())
                    # Verificamos si el contenido de texto tiene forma de tool call
                    if isinstance(content_json, dict) and "name" in content_json and "arguments" in content_json:
                        message["tool_calls"] = [{
                            "function": {
                                "name": content_json["name"],
                                "arguments": content_json["arguments"]
                            }
                        }]
                        has_tool_calls = message["tool_calls"]
                        logger.info(f"[OllamaAdapter] Extraído tool_call desde 'content': {content_json['name']}")
                except (json.JSONDecodeError, TypeError):
                    pass

            if not has_tool_calls and response_format:
                logger.info("[OllamaAdapter] No tool_calls detected. Executing internal format request call...")

                schema_str = ""
                if isinstance(response_format, type) and issubclass(response_format, BaseModel):
                    schema_str = json.dumps(response_format.model_json_schema(), indent=2)

                if message.get("content"):
                    formatted_messages.append({"role": "assistant", "content": message.get("content")})

                format_prompt = (
                    "Now, consolidate all findings and conversation context. "
                    "Provide your final output STRICTLY as a JSON object matching this schema:\n"
                    f"{schema_str if schema_str else 'Valid JSON object'}"
                )
                formatted_messages.append({"role": "user", "content": format_prompt})

                final_payload: Dict[str, Any] = {
                    "model": self._model_name,
                    "messages": formatted_messages,
                    "format": "json",
                    "stream": False,
                }

                logger.debug(f"[Ollama] Sending secondary JSON format request to {url}")
                format_response = await client.post(url, json=final_payload, timeout=self._timeout)
                format_response.raise_for_status()

                format_result = format_response.json()
                final_message = format_result.get("message", {})
                if final_message:
                    return final_message

            return message

        except httpx.HTTPError as http_err:
            logger.exception(f"HTTP error in Ollama: {str(http_err)}")
            raise LLMException(f"HTTP error in Ollama: {str(http_err)}") from http_err

        except Exception as exc:
            logger.exception(f"Error in Ollama call: {str(exc)}", exc_info=True)
            raise LLMException(f"Ollama failure: {str(exc)}") from exc

    @property
    def provider_name(self) -> str:
        """Returns 'ollama' as the unique provider identifier."""
        return self._PROVIDER_NAME

    @property
    def model_name(self) -> str:
        """Returns the name of the Ollama model being used."""
        return self._model_name

    async def health_check(self) -> bool:
        """
              Verify Ollama availability.

              Makes a call to the /api/tags endpoint to verify that the service
              is available and that the model is downloaded.

              Returns:
                  bool: True if Ollama is available and the model exists, False otherwise
              """
        client = self._get_client()
        url = f"{self._base_url}/api/tags"

        try:
            logger.info("Running Ollama health check")

            response = await client.get(url)
            response.raise_for_status()

            data = response.json()
            models = [m.get("name", "") for m in data.get("entities", [])]

            # Verify that the model exists
            model_found = any(self._model_name in m for m in models)

            if model_found:
                logger.info(f"Health check OK: model {self._model_name} available in Ollama")
                return True
            else:
                logger.warning(f"Health check: model {self._model_name} not found. Available entities: {models}")
                return False

        except Exception as exc:
            logger.exception(f"Ollama health check failed: {str(exc)}")
            return False

    async def close(self):
        """Close connection with Ollama."""
        if self._client:
            await self._client.aclose()
            self._client = None


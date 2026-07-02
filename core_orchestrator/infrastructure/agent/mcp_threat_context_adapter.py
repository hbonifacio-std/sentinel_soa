import json
import logging
from typing import Any, Dict

from core_orchestrator.domain.ports.telemetry.threat_context_port import ThreatContextPort
from core_orchestrator.infrastructure.agent.mcp_client import MCPClientManager

logger = logging.getLogger(__name__)


class MCPThreatContextAdapter(ThreatContextPort):
    """MCP-backed adapter for historical threat context retrieval."""

    def __init__(self, mcp_manager: MCPClientManager):
        self.mcp_manager = mcp_manager

    async def get_threat_context(self, source_ip: str, limit: int = 5) -> Dict[str, Any]:
        raw_result = await self.mcp_manager.call_tool(
            tool_name="get_threat_context",
            arguments={"source_ip": source_ip, "limit": limit},
        )
        return self._parse_result(raw_result)

    def _parse_result(self, raw_result: Any) -> Dict[str, Any]:
        if hasattr(raw_result, "content") and raw_result.content:
            try:
                return json.loads(raw_result.content[0].text)
            except (json.JSONDecodeError, IndexError, AttributeError):
                logger.warning("Could not parse JSON from get_threat_context. Using empty fallback.")
                return {"history": []}
        return raw_result if isinstance(raw_result, dict) else {}

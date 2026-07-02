import json
import logging
from typing import Any, Dict

from core_orchestrator.domain.ports.shared.llm_analysis_port import LlmAnalysisPort
from core_orchestrator.infrastructure.agent.mcp_client import MCPClientManager

logger = logging.getLogger(__name__)


class MCPLlmAnalysisAdapter(LlmAnalysisPort):
    """MCP-backed adapter for telemetry threat analysis."""

    def __init__(self, mcp_manager: MCPClientManager):
        self.mcp_manager = mcp_manager

    async def analyze_web_activity(self, telemetry_payload: Dict[str, Any]) -> Dict[str, Any]:
        raw_result = await self.mcp_manager.call_tool(
            tool_name="analyze_web_activity",
            arguments=telemetry_payload,
        )
        return self._parse_result(raw_result)

    def _parse_result(self, raw_result: Any) -> Dict[str, Any]:
        if hasattr(raw_result, "content") and raw_result.content:
            try:
                return json.loads(raw_result.content[0].text)
            except (json.JSONDecodeError, IndexError, AttributeError):
                logger.error("Could not parse JSON from analyze_web_activity. Using empty fallback.")
                return {"threat_detected": False, "threat_score": 0}
        return raw_result if isinstance(raw_result, dict) else {}

import json
import asyncio
import logging
from typing import Any, Dict

from core_orchestrator.domain.ports.shared.llm_analysis_port import LlmAnalysisPort
from core_orchestrator.infrastructure.agent.mcp_client import MCPClientManager

logger = logging.getLogger(__name__)
_MCP_TOOL_TIMEOUT_S = 300.0


class MCPLlmAnalysisAdapter(LlmAnalysisPort):
    """MCP-backed adapter for telemetry threat analysis."""

    def __init__(self, mcp_manager: MCPClientManager):
        self.mcp_manager = mcp_manager

    async def analyze_web_activity(self, telemetry_payload: Dict[str, Any]) -> Dict[str, Any]:
        source_ip = telemetry_payload.get("source_ip") or telemetry_payload.get("ip", "UNKNOWN")
        logger.info(f"MCP tool 'analyze_web_activity' invoked for IP: {source_ip}")
        try:
            raw_result = await asyncio.wait_for(
                self.mcp_manager.call_tool(
                    tool_name="analyze_web_activity",
                    arguments=telemetry_payload,
                ),
                timeout=_MCP_TOOL_TIMEOUT_S,
            )
            logger.info(f"MCP tool 'analyze_web_activity' completed for IP: {source_ip}")
            return self._parse_result(raw_result)
        except asyncio.TimeoutError:
            logger.error(
                "MCP tool 'analyze_web_activity' timed out after %ss for IP: %s",
                _MCP_TOOL_TIMEOUT_S,
                source_ip,
            )
            return {
                "source_ip": source_ip,
                "threat_detected": False,
                "threat_score": 0,
                "error": "MCP analysis timed out",
            }
        except Exception as exc:
            logger.error(
                "MCP tool 'analyze_web_activity' failed for IP %s: %s",
                source_ip,
                exc,
                exc_info=True,
            )
            return {
                "source_ip": source_ip,
                "threat_detected": False,
                "threat_score": 0,
                "error": str(exc),
            }

    def _parse_result(self, raw_result: Any) -> Dict[str, Any]:
        if hasattr(raw_result, "content") and raw_result.content:
            try:
                return json.loads(raw_result.content[0].text)
            except (json.JSONDecodeError, IndexError, AttributeError):
                logger.error("Could not parse JSON from analyze_web_activity. Using empty fallback.")
                return {"threat_detected": False, "threat_score": 0}
        return raw_result if isinstance(raw_result, dict) else {}

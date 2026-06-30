"""
Service responsible for enriching analysis results with historical threat context.
"""
import logging
import json
from typing import Dict, Any

from core_orchestrator.agent.mcp_client import MCPClientManager
from core_orchestrator.domain.ports.threat_context_service_port import ThreatContextServicePort

logger = logging.getLogger(__name__)


class ThreatContextService(ThreatContextServicePort):
    def __init__(self, mcp_manager: MCPClientManager):
        self.mcp_manager = mcp_manager

    async def get_historical_context(self, source_ip: str) -> Dict[str, Any]:
        """
        Retrieves historical threat context for a given source IP.
        """
        logger.info(f"Requesting historical context for {source_ip}")
        raw_context_result = await self.mcp_manager.call_tool(
            tool_name="get_threat_context", arguments={"source_ip": source_ip, "limit": 5}
        )

        context_result: Dict[str, Any] = {}
        if hasattr(raw_context_result, "content") and raw_context_result.content:
            try:
                context_result = json.loads(raw_context_result.content[0].text)
            except (json.JSONDecodeError, IndexError, AttributeError):
                context_result = {"history": []}
        else:
            context_result = raw_context_result if isinstance(raw_context_result, dict) else {}

        history = context_result.get("history", [])
        logger.info(f"Historical context added: {len(history)} previous alerts for {source_ip}")
        return {"threat_history": history}


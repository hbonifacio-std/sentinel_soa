import json
import logging
from typing import Any, Optional

from core_orchestrator.domain.ports.forensic import ForensicIntelligencePort
from core_orchestrator.infrastructure.adapters.mpc_server.mcp_client_adapter import MCPClientManagerAdapter

logger = logging.getLogger(__name__)


class MCPForensicIntelligenceAdapter(ForensicIntelligencePort):
    """MCP-backed adapter for forensic NLQ planning and report generation."""

    def __init__(self, mcp_manager: MCPClientManagerAdapter):
        self.mcp_manager = mcp_manager

    async def generate_mongo_query_from_nl(
        self,
        query: str,
        source_id: Optional[str],
        provider_override: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        args = {"query": query, "source_id": source_id}
        if provider_override:
            args["provider_override"] = provider_override
        raw_result = await self.mcp_manager.call_tool(
            tool_name="generate_mongo_query_from_nl",
            arguments=args,
        )
        parsed = self._parse_result(raw_result)
        return parsed if isinstance(parsed.get("mongo_filter"), dict) else {"mongo_filter": {}}

    async def generate_forensic_report_from_logs(
        self,
        query: str,
        source_id: Optional[str],
        total_matches: int,
        rows: list[dict[str, Any]],
        provider_override: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        args = {
            "query": query,
            "source_id": source_id,
            "total_matches": total_matches,
            "rows": rows,
        }
        if provider_override:
            args["provider_override"] = provider_override
        raw_result = await self.mcp_manager.call_tool(
            tool_name="generate_forensic_report_from_logs",
            arguments=args,
        )
        return self._parse_result(raw_result)

    @staticmethod
    def _parse_result(raw_result: Any) -> dict[str, Any]:
        if hasattr(raw_result, "content") and raw_result.content:
            try:
                return json.loads(raw_result.content[0].text)
            except (json.JSONDecodeError, IndexError, AttributeError):
                logger.warning("Could not parse JSON from MCP forensic tool response. Using empty fallback.")
                return {}
        return raw_result if isinstance(raw_result, dict) else {}


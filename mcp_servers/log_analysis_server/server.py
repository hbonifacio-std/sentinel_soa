"""FastMCP server exposing read-only MongoDB telemetry/threat tools."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import Any, Dict, Optional

from fastmcp.server import FastMCP
from starlette.middleware import Middleware

from mcp_servers.log_analysis_server.auth_middleware import InternalBearerAuthMiddleware
from mcp_servers.log_analysis_server.config import server_settings
from mcp_servers.log_analysis_server.security import get_internal_token
from mcp_servers.log_analysis_server.tool_access_control import require_tool_permission
from mcp_servers.log_analysis_server.tools.threat_intelligence import (
    execute_analyze_potential_threat,
    execute_get_mongo_access_scope,
    execute_get_raw_telemetry_events,
    execute_get_source_threat_timeline,
    execute_get_threat_reports,
    mongo_db_manager,
)

if logging.root.handlers:
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    force=True,
)
logger = logging.getLogger(__name__)

server = FastMCP("log-analysis-server")


@server.tool()
@require_tool_permission("get_mongo_access_scope")
async def get_mongo_access_scope() -> Dict[str, Any]:
    """
    Return strict MongoDB access scope of this MCP server.

    This tool is used for governance and transparency. It always returns
    the exact database and collection whitelist enforced by the server:
    database `sentinel_soa`, collections `raw_telemetry` and `reports`.
    """
    return execute_get_mongo_access_scope()


@server.tool()
@require_tool_permission("get_raw_telemetry_events")
async def get_raw_telemetry_events(
    source_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    window_id: Optional[str] = None,
    client_id: Optional[str] = None,
    from_utc: Optional[str] = None,
    to_utc: Optional[str] = None,
    status_code: Optional[int] = None,
    http_method: Optional[str] = None,
    path_contains: Optional[str] = None,
    query_text: Optional[str] = None,
    only_suspicious: bool = False,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Retrieve raw telemetry evidence from MongoDB (`sentinel_soa.raw_telemetry`).

    Use this for forensic evidence extraction during incident triage. Filters are
    strictly validated and mapped to safe query keys to prevent operator injection.
    """
    return await execute_get_raw_telemetry_events(
        {
            "source_id": source_id,
            "source_ip": source_ip,
            "window_id": window_id,
            "client_id": client_id,
            "from_utc": from_utc,
            "to_utc": to_utc,
            "status_code": status_code,
            "http_method": http_method,
            "path_contains": path_contains,
            "query_text": query_text,
            "only_suspicious": only_suspicious,
            "limit": min(limit, server_settings.max_query_limit),
        }
    )


@server.tool()
@require_tool_permission("get_threat_reports")
async def get_threat_reports(
    source_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    window_id: Optional[str] = None,
    client_id: Optional[str] = None,
    threat_level: Optional[str] = None,
    reviewed: Optional[bool] = None,
    resolved: Optional[bool] = None,
    threat_detected: Optional[bool] = None,
    min_threat_score: Optional[int] = None,
    max_threat_score: Optional[int] = None,
    query_text: Optional[str] = None,
    from_utc: Optional[str] = None,
    to_utc: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Retrieve analytical reports from MongoDB (`sentinel_soa.reports`).

    Supports operational filters (severity, reviewed, resolved and score threshold)
    to prioritize active or high-risk incidents without invoking any AI provider.
    """
    return await execute_get_threat_reports(
        {
            "source_id": source_id,
            "source_ip": source_ip,
            "window_id": window_id,
            "client_id": client_id,
            "threat_level": threat_level,
            "reviewed": reviewed,
            "resolved": resolved,
            "threat_detected": threat_detected,
            "min_threat_score": min_threat_score,
            "max_threat_score": max_threat_score,
            "query_text": query_text,
            "from_utc": from_utc,
            "to_utc": to_utc,
            "limit": min(limit, server_settings.max_query_limit),
        }
    )


@server.tool()
@require_tool_permission("get_source_threat_timeline")
async def get_source_threat_timeline(
    source_ip: str,
    source_id: Optional[str] = None,
    window_id: Optional[str] = None,
    client_id: Optional[str] = None,
    query_text: Optional[str] = None,
    from_utc: Optional[str] = None,
    to_utc: Optional[str] = None,
    limit_raw_events: int = 120,
    limit_reports: int = 60,
) -> Dict[str, Any]:
    """
    Build a correlated timeline for one source IP using both raw telemetry and reports.

    Designed for analysts who need immediate cross-collection context before deciding
    containment or escalation actions.
    """
    return await execute_get_source_threat_timeline(
        {
            "source_ip": source_ip,
            "source_id": source_id,
            "window_id": window_id,
            "client_id": client_id,
            "query_text": query_text,
            "from_utc": from_utc,
            "to_utc": to_utc,
            "limit_raw_events": min(limit_raw_events, server_settings.max_query_limit),
            "limit_reports": min(limit_reports, server_settings.max_query_limit),
        }
    )


@server.tool()
@require_tool_permission("analyze_potential_threat")
async def analyze_potential_threat(
    source_ip: str,
    source_id: Optional[str] = None,
    window_id: Optional[str] = None,
    client_id: Optional[str] = None,
    query_text: Optional[str] = None,
    from_utc: Optional[str] = None,
    to_utc: Optional[str] = None,
    limit_raw_events: int = 300,
    limit_reports: int = 120,
) -> Dict[str, Any]:
    """
    Produce a complete deterministic threat analysis when a potential threat is detected.

    The result includes threat score, severity, indicators, recommendations, and full
    evidence from both authorized Mongo collections. This analysis is rule-based and
    does not use prompts, LLMs, or external AI providers.
    """
    return await execute_analyze_potential_threat(
        {
            "source_ip": source_ip,
            "source_id": source_id,
            "window_id": window_id,
            "client_id": client_id,
            "query_text": query_text,
            "from_utc": from_utc,
            "to_utc": to_utc,
            "limit_raw_events": min(limit_raw_events, server_settings.max_query_limit),
            "limit_reports": min(limit_reports, server_settings.max_query_limit),
        }
    )


async def main() -> None:
    """Initialize Mongo dependency and run FastMCP over selected transport."""
    transport_mode = os.getenv("MCP_TRANSPORT", "sse").lower()

    await mongo_db_manager.connect()
    try:
        if transport_mode == "stdio":
            if not get_internal_token():
                logger.error("MCP_INTERNAL_SIGNING_TOKEN/MCP_INTERNAL_TOKEN is required. Refusing to start.")
                sys.exit(1)
            await server.run_async(transport="stdio")
            return

        if transport_mode == "sse":
            host = os.getenv("MCP_SERVER_HOST", "0.0.0.0")
            port = int(os.getenv("MCP_SERVER_PORT", "8080"))
            if not get_internal_token():
                logger.error("MCP_INTERNAL_TOKEN is required for SSE transport. Refusing to start.")
                sys.exit(1)
            middleware = [Middleware(InternalBearerAuthMiddleware)]
            await server.run_http_async(
                transport="sse",
                host=host,
                port=port,
                middleware=middleware,
            )
            return

        logger.error("Invalid MCP_TRANSPORT: '%s'. Use 'stdio' or 'sse'.", transport_mode)
        sys.exit(1)
    finally:
        await mongo_db_manager.disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("MCP Server interrupted and shutting down.")
    except Exception as exc:
        logger.error("MCP Server failed to start: %s", exc, exc_info=True)

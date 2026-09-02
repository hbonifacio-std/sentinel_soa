"""FastMCP server exposing read-only MongoDB + Neo4j telemetry/threat tools."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
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
from mcp_servers.log_analysis_server.tools.forensic_tools import (
    execute_check_data_exfiltration_evidence,
    execute_find_pivot_blast_radius,
    execute_get_attacker_chronological_timeline,
    execute_get_threat_dashboard_summary,
    execute_summarize_window_telemetry,
    mongo_db_manager,
    neo4j_db_manager,
)
from mcp_servers.log_analysis_server.models.threat_tools import (
    AttackerChronologicalTimelineOutput,
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

# Suppress verbose logs from Neo4j
logging.getLogger("neo4j.bolt").setLevel(logging.WARNING)
logging.getLogger("neo4j.io").setLevel(logging.WARNING)
logging.getLogger("neo4j").setLevel(logging.WARNING)
logging.getLogger("neo4j.api_core").setLevel(logging.ERROR)

logger = logging.getLogger(__name__)

server = FastMCP("log-analysis-server")


@server.tool()
@require_tool_permission("get_threat_dashboard_summary")
async def get_threat_dashboard_summary(
    client_id: str,
    time_window_hours: int = 24,
    min_threat_level: str = "LOW",
) -> Dict[str, Any]:
    """
    Get a high-level overview of the security posture, global alert metrics, and top attacking IPs.

    Use this tool to get macro/triage context. DO NOT use this for step-by-step investigation or raw log inspection.

    Inputs:
    - client_id (str, REQUIRED): Tenant unique ID
    - time_window_hours (int, OPTIONAL, default=24): Lookback period in hours
    - min_threat_level (str, OPTIONAL, default="LOW"): Minimum threat filter ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    Output includes:
    - total_alerts (int)
    - latest_alert_timestamp_utc (str | None): Timestamp of the most recent alert in UTC
    - severity_counts (dict[str, int])
    - top_threat_types (list[str]): Top 5 alert categories or threat types detected
    - top_attacking_ips (list[dict]: {"ip": str, "reports_count": int})
    - affected_sources (list[str])
    - active_windows (list[str])
    """
    return await execute_get_threat_dashboard_summary(client_id, time_window_hours, min_threat_level)


@server.tool()
@require_tool_permission("summarize_window_telemetry")
async def summarize_window_telemetry(
    client_id: str,
    window_id: str,
) -> Dict[str, Any]:
    """
    Statistically analyze a batch/window of telemetry logs without retrieving individual events.

    Returns HTTP status code distributions, top User-Agents, and traffic summaries for a window_id.

    Inputs:
    - client_id (str, REQUIRED): Tenant unique ID
    - window_id (str, REQUIRED): UUID of the telemetry window to summarize

    Output includes:
    - window_id (str)
    - total_events (int)
    - unique_ips (int)
    - status_code_distribution (dict[str, int])
    - top_user_agents (list[str])
    """
    return await execute_summarize_window_telemetry(client_id, window_id)


@server.tool()
@require_tool_permission("get_attacker_chronological_timeline")
async def get_attacker_chronological_timeline(
    client_id: str,
    source_ip: Optional[str] = None,
    window_id: Optional[str] = None,
    only_suspicious: bool = True,
    limit: int = 30,
) -> AttackerChronologicalTimelineOutput:
    """
    reconstruct_attack_timeline
    Reconstruct the exact step-by-step chronological sequence of an attacker or specific IP address.

    Returns event logs ordered by timestamp for forensic analysis, including targeted microservices, query parameters, and detection reasons.

    Inputs:
    - client_id (str, REQUIRED): Tenant unique ID
    - source_ip (str, OPTIONAL): Attacker IP address to filter
    - window_id (str, OPTIONAL): Window ID constraint
    - only_suspicious (bool, OPTIONAL, default=True): If True, filters only flagged suspicious events
    - limit (int, OPTIONAL, default=30, max=50): Event return cap

    Output includes:
    - timeline_events (list[dict]): List of chronological forensic events:
        - timestamp_utc (str): Event timestamp in UTC ISO format
        - source_ip (str): Origin IP address
        - target_service (str): Targeted microservice or host ID (e.g., "api-core-005")
        - method (str): HTTP method (e.g., "GET", "POST")
        - path (str): Target URI path
        - query_params (str | None): Request query string parameters, if present
        - status_code (int | None): HTTP response status code (e.g., 200, 404)
        - response_size_bytes (int): HTTP response body payload size in bytes
        - user_agent (str): User-Agent header string (e.g., "gobuster/3.1.0")
        - suspicious_reason (str | None): Flag or explanation of why the event was flagged as suspicious
    """
    limit = min(limit, 50)
    result = await execute_get_attacker_chronological_timeline(
        client_id, source_ip, window_id, only_suspicious, limit
    )
    return AttackerChronologicalTimelineOutput(**result)


@server.tool()
@require_tool_permission("check_data_exfiltration_evidence")
async def check_data_exfiltration_evidence(
    client_id: str,
    source_ip: str,
    window_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    check_data_exfiltration_evidence
Determine whether an IP address successfully extracted sensitive information or attempted unauthorized downloads.

Analyzes successful HTTP requests (200/206), failed download attempts (401/403/404), total byte volume transferred, access to sensitive file paths, and sampled endpoints.

Inputs:
- client_id (str, REQUIRED): Tenant unique ID
- source_ip (str, REQUIRED): Suspect attacker IP address to investigate
- window_id (str, OPTIONAL): Specific telemetry window constraint

Output includes:
- source_ip (str): Investigated IP address
- evaluated_window_id (str | None): Window ID evaluated, if provided
- total_bytes_downloaded (int): Total volume of data transferred in successful HTTP responses (bytes)
- successful_downloads_count (int): Number of successful requests (HTTP 200/206)
- failed_download_attempts (int): Number of failed or unauthorized attempts (HTTP 401/403/404)
- sensitive_paths_accessed (list[dict]): List of sensitive paths accessed: [{"path": str, "status_code": int, "bytes": int}]
- sample_paths_accessed (list[str]): Sample of up to 5 non-sensitive endpoints accessed
- exfiltration_risk (str): Evaluated risk level ("NONE" | "LOW" | "MEDIUM" | "HIGH")
    """
    return await execute_check_data_exfiltration_evidence(client_id, source_ip, window_id)


@server.tool()
@require_tool_permission("find_pivot_blast_radius")
async def find_pivot_blast_radius(
    client_id: str,
    source_ip: str,
) -> Dict[str, Any]:
    """
    Discover the blast radius, targeted endpoints, and threat context of an attacking IP.

    Identifies affected microservices (source_id), HTTP paths/endpoints probed, User-Agents, and associated MITRE ATT&CK tactics and techniques.

    Inputs:
    - client_id (str, REQUIRED): Tenant unique ID
    - source_ip (str, REQUIRED): IP address to investigate

    Output includes:
    - affected_sources (list[str])
    - user_agents_used (list[str])
    - targeted_paths (list[str])
    - mitre_tactics_observed (list[str])
    - mitre_techniques_observed (list[str])
    """
    return await execute_find_pivot_blast_radius(client_id, source_ip)


async def main() -> None:
    """Initialize Mongo dependency and run FastMCP over selected transport."""
    transport_mode = os.getenv("MCP_TRANSPORT", "sse").lower()

    await mongo_db_manager.connect()
    await neo4j_db_manager.connect()
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
        await neo4j_db_manager.disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("MCP Server interrupted and shutting down.")
    except Exception as exc:
        logger.error("MCP Server failed to start: %s", exc, exc_info=True)

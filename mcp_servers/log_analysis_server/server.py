# mcp_servers/log_analysis_server/server.py

import os
import sys
import logging
import asyncio
from typing import Dict, Any, List, Optional

from fastmcp.server import FastMCP

# Import the real analysis functions with heuristics
from mcp_servers.log_analysis_server.config import server_settings
from mcp_servers.log_analysis_server.tools.analyze_activity import execute_analyze_web_activity
from mcp_servers.log_analysis_server.tools.forensic_nlq import build_forensic_mongo_query, generate_forensic_report
from mcp_servers.log_analysis_server.tools.threat_context import ThreatContextRequest, execute_get_threat_context
from mcp_servers.log_analysis_server.tools.error_responses import (
    build_analyze_web_activity_error,
    build_threat_context_error,
)

# --- Production-Grade Logging Configuration ---
if logging.root.handlers:
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format=log_format,
    force=True
)
logger = logging.getLogger(__name__)

# --- Initialize server ---
server = FastMCP("log-analysis-server")

# --- System Tools ---

@server.tool()
async def get_available_models() -> Dict[str, Any]:
    """Returns a dictionary of available models from the server configuration."""
    models = {
        model_id: {
            "provider": model_def.provider,
            "model_name": model_def.model_name
        }
        for model_id, model_def in server_settings.available_models.items()
    }
    return {
        "default_model_id": server_settings.default_model_id,
        "available_models": models
    }

# --- Register real tools with heuristics ---
# pylint: disable=too-many-arguments
@server.tool()
async def analyze_web_activity(  # noqa: PLR0913
        window_id: str,
        source_id: str,
        source_ip: str,
        window_start_utc: str,
        window_end_utc: str,
        total_requests: int,
        unique_uris_requested: List[str],
        user_agents_observed: List[str],
        requests_per_second_avg: float,
        http_methods_distribution: Optional[Dict[str, int]] = None,
        response_codes_distribution: Optional[Dict[str, int]] = None,
        critical_payload_features: Optional[List[str]] = None,
        attempted_usernames: Optional[List[str]] = None,
        invalid_token_requests_count: int = 0,
        max_response_size_bytes: int = 0,
        suspicious_samples: Optional[List[Dict[str, Any]]] = None,
        infra_context: Optional[Dict[str, Any]] = None,
        security_state_features: Optional[Dict[str, Any]] = None,
        rules_bundle: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Analyzes web telemetry to detect threats using heuristics + LLM.

    Args:
        window_id: Window identifier.
        source_id: Telemetry source ID.
        source_ip: Source IP under analysis.
        window_start_utc: Start timestamp.
        window_end_utc: End timestamp.
        total_requests: Total requests.
        unique_uris_requested: List of requested URIs.
        http_methods_distribution: HTTP method distribution.
        response_codes_distribution: Response code distribution.
        user_agents_observed: List of observed User-Agents.
        requests_per_second_avg: Average requests per second.
        critical_payload_features: Sanitized suspicious payload fragments extracted by the backend.
        attempted_usernames: Distinct usernames observed in authentication attempts.
        invalid_token_requests_count: Number of requests with invalid/expired authentication tokens.
        max_response_size_bytes: Maximum response size observed in the window.
        model_id: The identifier for the analysis model to use.
        suspicious_samples: Sanitized suspicious request samples for context.
        infra_context: Compact infrastructure summary (environment, process, ports, proxy metadata).
        security_state_features: Session/authentication state features for account-compromise correlation.
        rules_bundle: Active rules bundle injected by core orchestrator.
    """
    # Rebuild the 'arguments' dictionary expected by execute_analyze_web_activity
    payload = {
        "window_id": window_id,
        "source_id": source_id,
        "source_ip": source_ip,
        "window_start_utc": window_start_utc,
        "window_end_utc": window_end_utc,
        "total_requests": total_requests,
        "unique_uris_requested": unique_uris_requested,
        "http_methods_distribution": http_methods_distribution or {},
        "response_codes_distribution": response_codes_distribution or {},
        "user_agents_observed": user_agents_observed,
        "requests_per_second_avg": requests_per_second_avg,
        "critical_payload_features": critical_payload_features or [],
        "attempted_usernames": attempted_usernames or [],
        "invalid_token_requests_count": invalid_token_requests_count,
        "max_response_size_bytes": max_response_size_bytes,
        "suspicious_samples": suspicious_samples or [],
        "infra_context": infra_context or {},
        "security_state_features": security_state_features or {},
        "rules_bundle": rules_bundle,
    }

    logger.info(f"MCP tool 'analyze_web_activity' invoked successfully for IP: {source_ip}")

    try:
        # Send it cleanly to the internal function without touching any core code
        return await execute_analyze_web_activity(payload)
    except Exception as e:
        logger.error(f"Error executing tool: {str(e)}", exc_info=True)
        return build_analyze_web_activity_error(
            window_id=window_id,
            source_id=source_id,
            source_ip=source_ip,
            unique_uris_requested=unique_uris_requested,
            error=str(e),
        )

@server.tool()
async def generate_mongo_query_from_nl(query: str, source_id: Optional[str] = None) -> Dict[str, Any]:
    """Translate a natural-language forensic question into a safe Mongo filter plan.

    This tool receives an analyst-style query (for example: "show failed login bursts from
    10.0.0.7 in admin endpoints") and produces a deterministic Mongo filter using bounded
    parsing rules for IPs, status codes, URI patterns, and keywords.

    Args:
        query: Natural-language forensic intent from SOC analysts.
        source_id: Optional telemetry source scope. When present, the resulting filter is
            constrained to that specific source.

    Returns:
        A dictionary containing the generated `mongo_filter` and extracted intelligence terms.
    """
    return await build_forensic_mongo_query({"query": query, "source_id": source_id})


@server.tool()
async def generate_forensic_report_from_logs(
    query: str,
    total_matches: int,
    rows: List[Dict[str, Any]],
    source_id: Optional[str] = None,
    model_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate structured forensic insights and markdown from queried telemetry rows.

    The tool transforms raw log samples into analyst-friendly output that includes prioritized
    highlights, risk estimation, and an evidence section with normalized event excerpts.

    Args:
        query: Original analyst query used to gather telemetry.
        total_matches: Total number of matching records for the query.
        rows: Telemetry samples returned by the orchestrator repository.
        source_id: Optional source identifier used for filtering.
        model_id: The identifier for the analysis model to use.

    Returns:
        A dictionary with `highlights`, `markdown_report`, and risk metadata.
    """
    
    final_model_id = model_id or server_settings.default_model_id

    return await generate_forensic_report(
        {
            "query": query,
            "source_id": source_id,
            "total_matches": total_matches,
            "rows": rows,
            "model_id": final_model_id,
        }
    )


@server.tool()
async def get_threat_context(source_ip: str = "N/A", limit: int = 5) -> Dict[str, Any]:
    """
    Retrieves the threat history for a specific IP.
    """
    logger.info(f"MCP tool 'get_threat_context' invoked for IP: {source_ip}")
    try:
        request_payload = ThreatContextRequest(source_ip=source_ip, limit=limit)
        return await execute_get_threat_context(request_payload)
    except Exception as e:
        logger.error(f"Error in get_threat_context: {str(e)}", exc_info=True)
        return build_threat_context_error(source_ip=source_ip, error=str(e))

# --- Server Startup Logic ---
async def main():
    """
    Initializes and runs the MCP server, selecting the transport
    based on the MCP_TRANSPORT environment variable.
    """
    transport_mode = os.getenv('MCP_TRANSPORT', 'http').lower()
    
    logger.info("Tools 'analyze_web_activity' and 'get_threat_context' registered.")

    try:
        if transport_mode == 'stdio':
            logger.info("Starting FastMCP Log Analysis Server over stdio channel...")
            await server.run_async(transport='stdio')

        elif transport_mode == 'http':
            host = os.getenv('MCP_SERVER_HOST', '0.0.0.0')
            port = int(os.getenv('MCP_SERVER_PORT', '8080'))
            logger.info(f"Starting FastMCP Log Analysis Server on HTTP at {host}:{port}...")
            await server.run_async(transport='http', host=host, port=port)
            
        else:
            logger.error(f"Invalid MCP_TRANSPORT: '{transport_mode}'. Use 'stdio' or 'http'.")
            sys.exit(1)

    finally:
        # Ensure all LLM provider clients are closed on shutdown
        try:
            from mcp_servers.log_analysis_server.llm_providers import close_all_providers
            logger.info("Shutting down: closing LLM providers...")
            await close_all_providers()
        except Exception:
            logger.exception("Error while closing LLM providers during shutdown")

if __name__ == "__main__":
    try:
        # This initial log is safe because logging is already forced to stderr.
        logger.info("MCP Server process starting.")
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("MCP Server shutting down.")
    except Exception as e:
        logger.error(f"MCP Server failed to start: {e}", exc_info=True)

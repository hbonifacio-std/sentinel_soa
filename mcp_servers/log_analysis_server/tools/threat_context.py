"""
MCP tool module for retrieving historical threat context.

This file contains the implementation of the 'get_threat_context' tool,
which exposes to the LLM agent the history of previous alerts associated with an IP
to identify recurrence and persistent attack patterns.
"""

import logging
from typing import Dict, Any, List

from pydantic import BaseModel, Field

from mcp_servers.log_analysis_server.store.alert_store import alert_store

# Local logger configuration
logger = logging.getLogger(__name__)


class ThreatContextRequest(BaseModel):
    """Validated request contract for historical threat context retrieval."""

    source_ip: str = Field(min_length=1, max_length=64)
    limit: int = Field(default=10, ge=1, le=100)


async def execute_get_threat_context(arguments: ThreatContextRequest) -> Dict[str, Any]:
    """
    Retrieves previous alerts for a specific source IP from the in-memory store.

    Args:
        arguments (ThreatContextRequest): Validated input contract for the tool.

    Returns:
        Dict[str, Any]: A container with the list of previous alerts formatted
            as structured dictionaries, ready for the agent's tool_result cycle.

    Raises:
        ValueError: If required parameters are missing or invalid.
    """
    try:
        source_ip = arguments.source_ip.strip()
        limit = arguments.limit

        if not source_ip:
            raise ValueError("Required parameter 'source_ip' was not provided.")

        logger.info(f"Executing 'get_threat_context' for IP: {source_ip} (Limit: {limit})")

        # 2. Query the thread-safe in-memory store
        historical_alerts = alert_store.get_history_by_ip(source_ip, limit=limit)
        
        # 3. Clean formatting and serialization of structured objects to native types
        formatted_alerts: List[Dict[str, Any]] = [
            alert.model_dump() for alert in historical_alerts
        ]

        logger.debug(f"Returning {len(formatted_alerts)} historical alerts found for {source_ip}.")

        # Wrap the result in a native JSON payload dictated by MCP
        return {
            "source_ip": source_ip,
            "alerts_found": len(formatted_alerts),
            "history": formatted_alerts
        }

    except ValueError as val_err:
        logger.error(f"Parameter error in 'get_threat_context': {str(val_err)}")
        raise ValueError(f"Invalid arguments for the tool: {str(val_err)}") from val_err
        
    except Exception as exc:
        logger.critical(f"Unexpected failure retrieving threat context: {str(exc)}")
        raise Exception(f"Internal error in context tool execution: {str(exc)}") from exc

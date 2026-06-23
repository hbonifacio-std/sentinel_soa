"""
MCP tool module for retrieving historical threat context.

This file contains the implementation of the 'get_threat_context' tool,
which exposes to the LLM agent the history of previous alerts associated with an IP
to identify recurrence and persistent attack patterns.
"""

import logging
from typing import Dict, Any, List

from mcp_servers.log_analysis_server.store.alert_store import alert_store

# Local logger configuration
logger = logging.getLogger(__name__)


async def execute_get_threat_context(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Retrieves previous alerts for a specific source IP from the in-memory store.

    Args:
        arguments (Dict[str, Any]): Tool arguments provided by the LLM.
            Expected as a dictionary with the required key 'source_ip' and optional 'limit'.

    Returns:
        Dict[str, Any]: A container with the list of previous alerts formatted
            as structured dictionaries, ready for the agent's tool_result cycle.

    Raises:
        ValueError: If required parameters are missing or invalid.
    """
    try:
        # 1. Quick manual validation of required parameters (MCP contract)
        if "source_ip" not in arguments:
            raise ValueError("Required parameter 'source_ip' was not provided.")
        
        source_ip: str = str(arguments["source_ip"])
        limit: int = int(arguments.get("limit", 10))

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

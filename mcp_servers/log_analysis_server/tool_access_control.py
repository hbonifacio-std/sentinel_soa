"""
Decorator for tool access control in MCP servers.

Provides a simple decorator to enforce RBAC on MCP tools.
"""

import functools
import inspect
import logging
from typing import Callable, Any

from mcp_servers.log_analysis_server.security import check_tool_permission, get_user_role

logger = logging.getLogger(__name__)


def _enforce_tool_permission(tool_name: str) -> None:
    """Validate that the current request context is authenticated and authorized for a tool."""
    user_role = get_user_role()
    if not user_role:
        error_msg = f"Access denied: missing authenticated role for tool '{tool_name}'"
        logger.error(error_msg)
        raise PermissionError(error_msg)

    if not check_tool_permission(tool_name, user_role):
        error_msg = (
            f"Access denied: User role '{user_role}' not permitted "
            f"to access tool '{tool_name}'"
        )
        logger.error(error_msg)
        raise PermissionError(error_msg)

    logger.info("Tool access granted: %s for role %s", tool_name, user_role)


def require_tool_permission(tool_name: str) -> Callable:
    """
    Decorator to enforce tool access control on MCP tools.
    
    Usage:
        @app.tool()
        @require_tool_permission("analyze_web_activity")
        async def analyze_web_activity(logs: str) -> str:
            # Implementation
            return analysis
    
    Args:
        tool_name: Name of the tool (must be in TOOL_PERMISSIONS)
    
    Raises:
        PermissionError: If user doesn't have permission
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            _enforce_tool_permission(tool_name)
            return await func(*args, **kwargs)
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            _enforce_tool_permission(tool_name)
            return func(*args, **kwargs)
        
        # Check if function is async
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator

"""Security utilities for MCP server authentication and message integrity."""

import contextvars
import hashlib
import hmac
import json
import logging
import os
from typing import Any, Dict, Optional, Set, List
from enum import Enum

logger = logging.getLogger(__name__)

# Context variable to pass auth header from HTTP layer to tools
_auth_header_context: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    'auth_header', default=None
)

# Context variable for user role/permissions
_user_role_context: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    'user_role', default=None
)


class UserRole(str, Enum):
    """User roles with granular tool permissions."""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# ============================================================================
# TOOL ACCESS CONTROL - Role-Based Access to Tools
# ============================================================================

TOOL_PERMISSIONS: Dict[str, Set[UserRole]] = {
    "get_mongo_access_scope": {UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER},
    "get_raw_telemetry_events": {UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER},
    "get_threat_reports": {UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER},
    "get_source_threat_timeline": {UserRole.ADMIN, UserRole.ANALYST},
    "analyze_potential_threat": {UserRole.ADMIN, UserRole.ANALYST},
}


def set_user_role(role: Optional[str]) -> None:
    """Set the current user role in context."""
    _user_role_context.set(role)


def get_user_role() -> Optional[str]:
    """Get the current user role from context."""
    return _user_role_context.get()


def check_tool_permission(tool_name: str, user_role: Optional[str] = None) -> bool:
    """
    Check if user has permission to access a tool.
    
    Args:
        tool_name: Name of the tool to check
        user_role: User role (if None, uses context)
    
    Returns:
        True if user has permission, False otherwise
    """
    if user_role is None:
        user_role = get_user_role()
    
    if not user_role:
        logger.warning(f"No user role set for tool access check: {tool_name}")
        return False
    
    # Get allowed roles for this tool
    allowed_roles = TOOL_PERMISSIONS.get(tool_name, set())
    
    if not allowed_roles:
        logger.warning(f"Tool not registered in TOOL_PERMISSIONS: {tool_name}")
        return False
    
    # Check if user role is in allowed roles
    try:
        user_role_enum = UserRole(user_role.lower())
        is_allowed = user_role_enum in allowed_roles
        
        if not is_allowed:
            logger.warning(
                f"Access denied: user role '{user_role}' not in {allowed_roles} "
                f"for tool '{tool_name}'"
            )
        return is_allowed
    except ValueError:
        logger.error(f"Invalid user role: {user_role}")
        return False


def list_available_tools(user_role: Optional[str] = None) -> List[str]:
    """
    List tools available to the user based on their role.
    
    Args:
        user_role: User role (if None, uses context)
    
    Returns:
        List of tool names the user can access
    """
    if user_role is None:
        user_role = get_user_role()
    
    if not user_role:
        return []
    
    try:
        user_role_enum = UserRole(user_role.lower())
        return [
            tool for tool, allowed_roles in TOOL_PERMISSIONS.items()
            if user_role_enum in allowed_roles
        ]
    except ValueError:
        return []


def get_internal_token() -> Optional[str]:
    """Retrieve the signing token used for rules-bundle integrity."""
    signing_token = (os.getenv("MCP_INTERNAL_SIGNING_TOKEN") or "").strip()
    if signing_token:
        return signing_token

    fallback_token = (os.getenv("MCP_INTERNAL_TOKEN") or "").strip()
    return fallback_token or None


def _parse_token_list(raw_value: Optional[str]) -> Set[str]:
    """Parse a comma-separated token list into a deduplicated non-empty set."""
    if not raw_value:
        return set()
    return {token.strip() for token in raw_value.split(",") if token.strip()}


def _role_tokens_from_env(role: UserRole) -> Set[str]:
    """Load role-bound internal bearer tokens from environment variables."""
    role_name = role.value.upper()
    explicit = _parse_token_list(os.getenv(f"MCP_INTERNAL_TOKEN_{role_name}"))
    list_based = _parse_token_list(os.getenv(f"MCP_INTERNAL_TOKENS_{role_name}"))
    return explicit | list_based


def get_bearer_tokens_by_role() -> Dict[UserRole, Set[str]]:
    """Resolve all configured bearer tokens grouped by role.

    Backward compatibility:
    - ``MCP_INTERNAL_TOKEN`` is treated as an ``analyst`` token.
    - ``MCP_INTERNAL_TOKENS`` (CSV) are treated as ``analyst`` tokens to allow zero-downtime rotation.
    """
    role_tokens: Dict[UserRole, Set[str]] = {
        UserRole.ADMIN: _role_tokens_from_env(UserRole.ADMIN),
        UserRole.ANALYST: _role_tokens_from_env(UserRole.ANALYST),
        UserRole.VIEWER: _role_tokens_from_env(UserRole.VIEWER),
    }

    role_tokens[UserRole.ANALYST] |= _parse_token_list(os.getenv("MCP_INTERNAL_TOKENS"))
    role_tokens[UserRole.ANALYST] |= _parse_token_list(os.getenv("MCP_INTERNAL_TOKEN"))
    return role_tokens


def set_auth_header(header: Optional[str]) -> None:
    """Set the current Authorization header in context."""
    _auth_header_context.set(header)


def get_auth_header() -> Optional[str]:
    """Get the current Authorization header from context."""
    return _auth_header_context.get()


def extract_role_from_token(token_claims: Dict[str, Any]) -> Optional[str]:
    """
    Extract user role from JWT token claims.
    
    Args:
        token_claims: Decoded JWT claims dictionary
    
    Returns:
        User role string or None if not found
    """
    role = token_claims.get("role")
    if role:
        set_user_role(role)
        logger.info(f"User role set from token: {role}")
    return role


def validate_bearer_token_with_role(
    auth_header: Optional[str],
    token_claims: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Validate Bearer token and extract user role.
    
    Args:
        auth_header: The Authorization header value (e.g., "Bearer <token>")
        token_claims: Decoded JWT claims (optional, for role extraction)
    
    Returns:
        True if token is valid, False otherwise.
    """
    if not auth_header:
        logger.warning("Missing Authorization header")
        return False
    
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        logger.warning("Invalid Authorization header format")
        return False
    
    token = parts[1]
    role_tokens = get_bearer_tokens_by_role()

    if not any(role_tokens.values()):
        logger.error("No MCP internal bearer tokens configured")
        return False

    for role, tokens in role_tokens.items():
        for expected_token in tokens:
            if hmac.compare_digest(token, expected_token):
                set_user_role(role.value)
                if token_claims:
                    extract_role_from_token(token_claims)
                return True

    logger.warning("Invalid MCP bearer token received")
    return False


def sign_rules_bundle(rules_bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Sign rules_bundle with HMAC to ensure integrity.
    
    Args:
        rules_bundle: The rules bundle dictionary to sign
    
    Returns:
        A new dict with added '__signature__' field.
    """
    token = get_internal_token()
    if not token:
        logger.error("Cannot sign rules_bundle: MCP_INTERNAL_TOKEN not configured")
        return rules_bundle
    
    bundle_str = json.dumps(rules_bundle, sort_keys=True)
    signature = hmac.new(
        token.encode(),
        bundle_str.encode(),
        hashlib.sha256
    ).hexdigest()
    
    signed_bundle = dict(rules_bundle)
    signed_bundle["__signature__"] = signature
    return signed_bundle


def verify_rules_bundle_signature(rules_bundle: Dict[str, Any]) -> bool:
    """Verify HMAC signature of rules_bundle.
    
    Args:
        rules_bundle: The rules bundle with expected '__signature__' field
    
    Returns:
        True if signature is valid, False otherwise.
    """
    if not isinstance(rules_bundle, dict):
        logger.warning("rules_bundle is not a dictionary")
        return False
    
    signature = rules_bundle.get("__signature__")
    if not signature:
        logger.warning("rules_bundle missing __signature__ field")
        return False
    
    token = get_internal_token()
    if not token:
        logger.error("Cannot verify signature: MCP_INTERNAL_TOKEN not configured")
        return False
    
    bundle_copy = {k: v for k, v in rules_bundle.items() if k != "__signature__"}
    bundle_str = json.dumps(bundle_copy, sort_keys=True)
    expected_signature = hmac.new(
        token.encode(),
        bundle_str.encode(),
        hashlib.sha256
    ).hexdigest()
    
    is_valid = hmac.compare_digest(signature, expected_signature)
    if not is_valid:
        logger.warning("rules_bundle signature verification failed")
    
    return is_valid

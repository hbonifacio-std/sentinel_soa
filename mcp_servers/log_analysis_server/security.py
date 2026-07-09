"""Security utilities for MCP server authentication and message integrity."""

import contextvars
import hashlib
import hmac
import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Context variable to pass auth header from HTTP layer to tools
_auth_header_context: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    'auth_header', default=None
)


def get_internal_token() -> Optional[str]:
    """Retrieve MCP_INTERNAL_TOKEN from environment."""
    return os.getenv("MCP_INTERNAL_TOKEN")


def set_auth_header(header: Optional[str]) -> None:
    """Set the current Authorization header in context."""
    _auth_header_context.set(header)


def get_auth_header() -> Optional[str]:
    """Get the current Authorization header from context."""
    return _auth_header_context.get()


def validate_bearer_token(auth_header: Optional[str]) -> bool:
    """Validate Bearer token from Authorization header.
    
    Args:
        auth_header: The Authorization header value (e.g., "Bearer <token>")
    
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
    expected_token = get_internal_token()
    
    if not expected_token:
        logger.error("MCP_INTERNAL_TOKEN not configured")
        return False
    
    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(token, expected_token)


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


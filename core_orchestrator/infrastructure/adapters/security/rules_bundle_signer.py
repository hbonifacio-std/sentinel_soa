"""Rules bundle signing and verification utilities.

Provides HMAC-SHA256 signing and verification for rules bundles to ensure
integrity and authenticity when exchanged with external systems (MCP servers).
"""

import hashlib
import hmac
import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def get_internal_token() -> Optional[str]:
    """
    Retrieve the internal token from the environment variables.

    This function attempts to fetch the value of the environment variable
    'MCP_INTERNAL_TOKEN'. If the variable is not set, the function returns
    None.

    Returns:
        Optional[str]: The value of the 'MCP_INTERNAL_TOKEN' environment
        variable, or None if it is not set.
    """
    return os.getenv("MCP_INTERNAL_TOKEN")


def sign_rules_bundle(rules_bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Sign rules_bundle with HMAC-SHA256 to ensure integrity.
    
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
    """
    Verifies the HMAC signature of a rule bundle to ensure its integrity.

    This function checks if the provided rules bundle contains a valid HMAC signature
    that matches the expected one based on the internal token and content of the rule
    bundle. If the bundle is not a dictionary, lacks a signature field, or the signature
    fails validation, appropriate warnings or errors are logged, and the function returns
    False.

    Parameters:
        rules_bundle (Dict[str, Any]): The rule bundle to verify. Must be a dictionary
            containing a "__signature__" field alongside other content.

    Returns:
        bool: True if the signature is valid, False otherwise.

    Raises:
        This function does not raise any exceptions. Any issues are logged internally.
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

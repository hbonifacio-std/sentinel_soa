"""
Provides utility functions for sanitizing and redacting sensitive data
from logs and API responses.
"""
from typing import Any, Dict, List, Union

DEFAULT_SENSITIVE_KEYS = [
    "password", "token", "authorization", "apikey", "secret",
    "access_token", "refresh_token", "client_secret", "signature",
    "jwt", "auth", "cookie", "set-cookie"
]
REDACTION_MASK = "[REDACTED]"

def redact_sensitive_data(
    data: Union[Dict[str, Any], List[Any]],
    sensitive_keys: List[str] = None,
    inplace: bool = False
) -> Union[Dict[str, Any], List[Any]]:
    """
    Recursively traverses a dictionary or list and redacts values for keys
    that are considered sensitive.

    Args:
        data: The dictionary or list to sanitize.
        sensitive_keys: A list of keys to treat as sensitive. Defaults to
                        a predefined list.
        inplace: If True, modifies the original dict/list. Otherwise, returns
                 a deep copy.

    Returns:
        The sanitized dictionary or list.
    """
    if sensitive_keys is None:
        sensitive_keys_lower = {key.lower() for key in DEFAULT_SENSITIVE_KEYS}
    else:
        sensitive_keys_lower = {key.lower() for key in sensitive_keys}

    if not inplace:
        # Simple deep copy for JSON-serializable structures
        import json
        data = json.loads(json.dumps(data, default=str))

    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in sensitive_keys_lower:
                data[key] = REDACTION_MASK
            elif isinstance(value, (dict, list)):
                redact_sensitive_data(value, sensitive_keys_lower, inplace=True)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, (dict, list)):
                redact_sensitive_data(item, sensitive_keys_lower, inplace=True)

    return data

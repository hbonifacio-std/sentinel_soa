"""
Provides utility functions for sanitizing and redacting sensitive data
from logs and API responses.
"""
import copy
from typing import Any, Dict, List, Sequence, Union

_DEFAULT_SENSITIVE_KEYS: frozenset[str] = frozenset({
    "password", "token", "authorization", "apikey", "secret",
    "access_token", "refresh_token", "client_secret", "signature",
    "jwt", "auth", "cookie", "set-cookie", "jti"
})
REDACTION_MASK = "[REDACTED]"


def _sanitize_element(element: Any, keys: set[str]) -> Any:
    """
    Sanitizes an element by recursively removing specified keys if the element
    is a dictionary or a list. If the element is neither, it is returned unchanged.

    Parameters:
    element (Any): The input element to sanitize. It may be a dictionary, a list,
    or any other data type.

    Keys (set[str]): A set of keys to remove from dictionaries within the element.

    Returns:
    Any: The sanitized element with specified keys removed from dictionaries, or
    the element itself if it is not a dictionary or list.
    """
    if isinstance(element, dict):
        return _sanitize_dict(element, keys)
    if isinstance(element, list):
        return [_sanitize_element(item, keys) for item in element]
    return element


def _sanitize_dict(data: dict[str, Any], keys: set[str]) -> dict[str, Any]:
    """
    Sanitizes a dictionary by masking sensitive data based on a set of specified keys.

    This function iterates through the given dictionary and checks if each key,
    when converted to lowercase, matches any value in the provided set of keys. If
    a match is found, the corresponding value in the dictionary is replaced with a
    redaction mask. For keys not in the provided set, the function recursively
    sanitizes their values.

    Parameters:
    data: dict[str, Any]
        The dictionary to be sanitized. It may contain nested structures that
        require recursive processing.
    keys: set[str]
        A set of keys, specified in the lowercase, used to determine which dictionary
        entries should have their values masked.

    Returns:
    dict[str, Any]
        A new dictionary with sensitive values replaced by a redaction mask while
        retaining all other content in its original structure.
    """
    sanitized: dict[str, Any] = {}
    for key, value in data.items():
        if str(key).lower() in keys:
            sanitized[key] = REDACTION_MASK
        else:
            sanitized[key] = _sanitize_element(value, keys)
    return sanitized


def redact_sensitive_data(
    data: Union[Dict[str, Any], List[Any]],
    sensitive_keys: Sequence[str] | None = None,
    inplace: bool = False
) -> Union[Dict[str, Any], List[Any]]:
    """
    Redacts sensitive data from a dictionary or list by replacing values of specified keys
    with sanitized values.

    Parameters:
    data (Union[Dict[str, Any], List[Any]]): The input data structure, which can be a dictionary
        or a list, that might contain sensitive information to be redacted.
    Sensitive_keys (Sequence[str] | None): A sequence of keys to be treated as sensitive. If not
        provided, a default set of sensitive keys is used.
    Inplace (bool): Determines whether the function modifies the input data in-place or operates
        on a copy. Defaults to False.

    Returns:
    Union[Dict[str, Any], List[Any]]: The data structure with sensitive information redacted.

    Raises:
    ValueError: If the data is not a dictionary, list, or a supported data structure.

    """
    if sensitive_keys is None:
        keys_set = set(_DEFAULT_SENSITIVE_KEYS)
    else:
        keys_set = {k.lower() for k in sensitive_keys}

    target = data if inplace else copy.deepcopy(data)

    if isinstance(target, dict):
        result = _sanitize_dict(target, keys_set)
        if inplace:
            target.clear()
            target.update(result)
            return target
        return result

    if isinstance(target, list):
        result = [_sanitize_element(item, keys_set) for item in target]
        if inplace:
            target[:] = result
            return target
        return result

    return target

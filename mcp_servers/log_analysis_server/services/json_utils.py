"""Shared JSON extraction utilities for LLM response parsing."""

from __future__ import annotations

import json
import re
from typing import Any

_JSON_FENCE_PATTERN = re.compile(
    r"```(?:json)?\s*(\{.*\})\s*```",
    re.DOTALL | re.IGNORECASE,
)


def extract_json_object(raw_text: str, *, strict: bool = True) -> dict[str, Any]:
    """Extract a JSON object from raw LLM text.

    Handles plain JSON, markdown fences, and substring brace blocks.

    Args:
        raw_text: Raw model output string.
        strict: When True, raises ``json.JSONDecodeError`` on failure.
            When False, returns an empty dict on failure or non-dict payloads.

    Returns:
        Parsed JSON object as a dictionary.
    """
    stripped = str(raw_text or "").strip()
    if not stripped:
        if strict:
            raise json.JSONDecodeError("Empty input", stripped, 0)
        return {}

    candidates: list[str] = [stripped]

    fence_match = _JSON_FENCE_PATTERN.search(stripped)
    if fence_match:
        candidates.insert(0, fence_match.group(1).strip())

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start >= 0 and end > start:
        candidates.append(stripped[start : end + 1])

    last_error: json.JSONDecodeError | None = None
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
            if not strict:
                return {}
        except json.JSONDecodeError as exc:
            last_error = exc
            continue

    if strict:
        raise last_error or json.JSONDecodeError(
            "Could not extract a valid JSON object",
            stripped,
            0,
        )
    return {}

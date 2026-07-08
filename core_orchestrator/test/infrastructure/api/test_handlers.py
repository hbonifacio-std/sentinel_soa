"""Tests for infrastructure exception and rate-limit handlers."""
import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from core_orchestrator.infrastructure.handlers.exceptions import validation_exception_handler


def _make_request(path: str = "/test") -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [],
        "query_string": b"",
    }
    return Request(scope)


@pytest.mark.asyncio
async def test_validation_exception_handler_returns_422():
    """validation_exception_handler should return a 422 JSONResponse."""
    request = _make_request("/api/v1/test")

    # Build a minimal RequestValidationError
    raw_errors = [
        {
            "loc": ("body", "field_x"),
            "msg": "field required",
            "type": "missing",
            "input": {},
            "url": "https://errors.pydantic.dev/...",
        }
    ]

    exc = MagicMock(spec=RequestValidationError)
    exc.errors.return_value = raw_errors

    response = await validation_exception_handler(request, exc)

    assert isinstance(response, JSONResponse)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_validation_exception_handler_multiple_errors():
    """Handler should process multiple validation errors without raising."""
    request = _make_request("/api/v1/telemetry")

    raw_errors = [
        {"loc": ("body", "source_id"), "msg": "field required", "type": "missing", "input": {}, "url": ""},
        {"loc": ("body", "timestamp_utc"), "msg": "invalid datetime", "type": "value_error", "input": {}, "url": ""},
    ]
    exc = MagicMock(spec=RequestValidationError)
    exc.errors.return_value = raw_errors

    response = await validation_exception_handler(request, exc)

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_validation_exception_handler_empty_errors():
    """Handler should work even with an empty error list."""
    request = _make_request("/api/v1/rules")

    exc = MagicMock(spec=RequestValidationError)
    exc.errors.return_value = []

    response = await validation_exception_handler(request, exc)

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_validation_exception_handler_loc_formatting():
    """Handler builds loc string correctly for nested locations."""
    request = _make_request("/api/v1/telemetry/batch")

    raw_errors = [
        {"loc": ("body", 0, "network", "client_ip"), "msg": "field required", "type": "missing", "input": {}, "url": ""},
    ]
    exc = MagicMock(spec=RequestValidationError)
    exc.errors.return_value = raw_errors

    # Should not raise
    response = await validation_exception_handler(request, exc)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_custom_rate_limit_handler():
    """custom_rate_limit_handler should return 429 JSONResponse."""
    from core_orchestrator.infrastructure.handlers.rate_limits import custom_rate_limit_handler

    request = _make_request("/api/v1/rules")
    exc = MagicMock()
    exc.detail = "5 per 1 minute"

    response = await custom_rate_limit_handler(request, exc)

    assert isinstance(response, JSONResponse)
    assert response.status_code == 429
    
    import json
    content = json.loads(response.body.decode())
    assert content["status"] == "error"
    assert content["code"] == "TOO_MANY_REQUESTS"
    assert "5 per 1 minute" in content["detail"]
    assert response.headers["Retry-After"] == "60"

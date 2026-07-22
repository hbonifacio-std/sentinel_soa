"""HTTP middleware for enforcing internal Bearer auth on MCP transport endpoints."""

from __future__ import annotations

import logging
from typing import Iterable, Tuple

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from mcp_servers.log_analysis_server.security import (
    set_auth_header,
    set_user_role,
    validate_bearer_token_with_role,
)

logger = logging.getLogger(__name__)


def _extract_header(headers: Iterable[Tuple[bytes, bytes]], key: str) -> str | None:
    """Return the first matching header value (case-insensitive) from raw ASGI headers."""
    expected = key.lower()
    for raw_name, raw_value in headers:
        if raw_name.decode("latin-1").lower() == expected:
            return raw_value.decode("latin-1")
    return None


class InternalBearerAuthMiddleware:
    """Protect MCP HTTP transport endpoints with MCP_INTERNAL_TOKEN bearer validation.

    This middleware is transport-level protection for SSE/HTTP endpoints. It enforces that
    every HTTP request carries ``Authorization: Bearer <MCP_INTERNAL_TOKEN>``. Requests that
    fail validation are rejected with 401 before reaching MCP routes.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = scope.get("headers", [])
        auth_header = _extract_header(headers, "authorization")
        set_user_role(None)
        set_auth_header(auth_header)

        try:
            if not validate_bearer_token_with_role(auth_header):
                logger.warning("Rejected unauthorized MCP HTTP request path=%s", scope.get("path"))
                response = JSONResponse(
                    status_code=401,
                    content={
                        "error": "unauthorized",
                        "message": "Missing or invalid Authorization Bearer token.",
                    },
                )
                await response(scope, receive, send)
                return

            await self.app(scope, receive, send)
        finally:
            set_auth_header(None)
            set_user_role(None)

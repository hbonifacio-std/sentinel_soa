"""
Security Headers Middleware for FastAPI.

Implements comprehensive security headers to prevent common web vulnerabilities:
- X-Frame-Options: Prevent clickjacking
- X-Content-Type-Options: Prevent MIME-sniffing
- Content-Security-Policy: Control resource loading
- Strict-Transport-Security: Force HTTPS
- X-XSS-Protection: XSS protection (legacy)
- Referrer-Policy: Control referrer information
"""

import logging
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response
from fastapi import Request
from core_orchestrator.infrastructure.config.config import orchestrator_settings_deprecated

logger = logging.getLogger("core_orchestrator.security_headers")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds comprehensive security headers to all HTTP responses.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """
        Add security headers to response.
        """
        response = await call_next(request)

        # ========================================================================
        # CLICKJACKING PREVENTION
        # ========================================================================
        response.headers["X-Frame-Options"] = "DENY"

        # ========================================================================
        # MIME-TYPE SNIFFING PREVENTION
        # ========================================================================
        response.headers["X-Content-Type-Options"] = "nosniff"

        # ========================================================================
        # XSS PROTECTION (Legacy but recommended)
        # ========================================================================
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # ========================================================================
        # CONTENT SECURITY POLICY (CSP)
        # ========================================================================
        csp_directives = [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self' data:",
            f"connect-src 'self' {' '.join(orchestrator_settings_deprecated.get_cors_origins())}",
            "frame-ancestors 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

        # ========================================================================
        # HTTPS ENFORCEMENT (HSTS)
        # ========================================================================
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

        # ========================================================================
        # REFERRER POLICY
        # ========================================================================
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # ========================================================================
        # PERMISSIONS POLICY
        # ========================================================================
        permissions_policy = [
            "accelerometer=()",
            "ambient-light-sensor=()",
            "camera=()",
            "geolocation=()",
            "gyroscope=()",
            "magnetometer=()",
            "microphone=()",
            "payment=()",
            "usb=()",
        ]
        response.headers["Permissions-Policy"] = ", ".join(permissions_policy)

        # ========================================================================
        # CROSS-ORIGIN POLICIES
        # ========================================================================
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        return response

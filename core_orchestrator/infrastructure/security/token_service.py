"""
Concrete JWT token service adapter for the application layer.
"""

from datetime import timedelta
from typing import Optional

from core_orchestrator.domain.ports.auth.token_service import TokenServicePort
from core_orchestrator.infrastructure.security.jwt_utils import create_access_token, get_token_jti


class JwtTokenService(TokenServicePort):
    """JWT-based implementation of the token service port."""

    def create_access_token(
        self,
        user_id: str,
        username: str,
        role: str,
        expires_delta: Optional[timedelta] = None,
    ) -> tuple[str, str]:
        return create_access_token(
            user_id=user_id,
            username=username,
            role=role,
            expires_delta=expires_delta,
        )

    def get_token_jti(self, token: str) -> Optional[str]:
        return get_token_jti(token)


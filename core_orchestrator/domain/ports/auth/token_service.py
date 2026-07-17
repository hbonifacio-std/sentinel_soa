"""
Port for JWT issuance and token inspection.

Allows application services to issue tokens and extract revocation data
without depending on infrastructure JWT helpers.
"""

from abc import ABC, abstractmethod
from datetime import timedelta
from typing import Optional, Dict, Any


class TokenServicePort(ABC):
    """Contract for JWT creation and token metadata extraction."""

    @abstractmethod
    def create_access_token(
        self,
        user_id: str,
        username: str,
        role: str,
        expires_delta: Optional[timedelta] = None,
    ) -> tuple[str, str]:
        """Create an access token and return the encoded token plus its JTI."""
        raise NotImplementedError

    @abstractmethod
    def create_refresh_token(
        self,
        user_id: str,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Create a refresh token (longer-lived than access token)."""
        raise NotImplementedError

    @abstractmethod
    def verify_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify refresh token and return payload if valid, None otherwise."""
        raise NotImplementedError

    @abstractmethod
    def get_token_jti(self, token: str) -> Optional[str]:
        """Extract the JTI from a token if it can be decoded safely."""
        raise NotImplementedError


"""
Port for JWT issuance and token inspection.

Allows application services to issue tokens and extract revocation data
without depending on infrastructure JWT helpers.
"""

from abc import ABC, abstractmethod
from datetime import timedelta
from typing import Optional


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
    def get_token_jti(self, token: str) -> Optional[str]:
        """Extract the JTI from a token if it can be decoded safely."""
        raise NotImplementedError


"""
Port for password hashing and verification.

Keeps authentication logic independent from the concrete hashing algorithm.
"""

from abc import ABC, abstractmethod


class PasswordHasherPort(ABC):
    """Contract for hashing and verifying passwords."""

    @abstractmethod
    def hash_password(self, password: str) -> str:
        """Hash a plain-text password."""
        raise NotImplementedError

    @abstractmethod
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a plain-text password against a stored hash."""
        raise NotImplementedError


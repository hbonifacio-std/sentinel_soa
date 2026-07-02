"""
Concrete password hasher adapter for the application layer.
"""

from core_orchestrator.domain.ports.auth.password_hasher import PasswordHasherPort
from core_orchestrator.infrastructure.security.password import hash_password, verify_password


class BcryptPasswordHasher(PasswordHasherPort):
    """Bcrypt-based implementation of the password hasher port."""

    def hash_password(self, password: str) -> str:
        return hash_password(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return verify_password(plain_password, hashed_password)


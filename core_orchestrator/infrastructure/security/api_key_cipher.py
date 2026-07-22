from typing import Optional
from cryptography.fernet import Fernet
from core_orchestrator.domain.ports.auth.api_key_cipher import ApiKeyCipherPort


class ApiKeyCipher(ApiKeyCipherPort):
    """Fernet-based cipher for securing third-party AI provider API keys per tenant."""

    def __init__(self, encryption_key: str):
        if not encryption_key:
            raise ValueError("Encryption key must not be empty.")
        # Key must be 32 url-safe base64-encoded bytes
        self._fernet = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypts a plaintext string (e.g. raw API key) and returns base64 ciphertext string."""
        if not plaintext:
            return ""
        return self._fernet.encrypt(plaintext.encode('utf-8')).decode('utf-8')

    def decrypt(self, ciphertext: str) -> str:
        """Decrypts a ciphertext string and returns the original plaintext API key."""
        if not ciphertext:
            return ""
        return self._fernet.decrypt(ciphertext.encode('utf-8')).decode('utf-8')

    @staticmethod
    def generate_key() -> str:
        """Generates a new Fernet key string for configuration/testing."""
        return Fernet.generate_key().decode('utf-8')

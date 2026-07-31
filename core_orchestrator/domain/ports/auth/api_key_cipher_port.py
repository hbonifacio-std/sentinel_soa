"""Port interface for API key encryption cipher."""

from abc import ABC, abstractmethod


class ApiKeyCipherPort(ABC):
    """Contract for encrypting and decrypting tenant API keys."""

    @abstractmethod
    def encrypt(self, plaintext: str) -> str:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: str) -> str:
        pass

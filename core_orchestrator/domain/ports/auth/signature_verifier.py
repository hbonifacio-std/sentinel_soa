"""
Port for verifying telemetry request signatures.

Keeps HMAC validation logic out of application services.
"""

from abc import ABC, abstractmethod


class SignatureVerifierPort(ABC):
    """Contract for validating signed telemetry payloads."""

    @abstractmethod
    def verify_hmac_signature(
        self,
        body: bytes,
        signature: str,
        public_key: str,
        timestamp: int,
        secret: str,
    ) -> bool:
        """Return True when the provided signature matches the payload."""
        raise NotImplementedError


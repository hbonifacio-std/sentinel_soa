"""
Concrete HMAC signature verifier adapter for telemetry clients.
"""

from core_orchestrator.domain.ports.auth.signature_verifier import SignatureVerifierPort
from core_orchestrator.infrastructure.security.jwt_utils import verify_hmac_signature


class HmacSignatureVerifier(SignatureVerifierPort):
    """Adapter that delegates HMAC checks to the technical JWT utilities."""

    def verify_hmac_signature(
        self,
        body: bytes,
        signature: str,
        public_key: str,
        timestamp: int,
        secret: str,
    ) -> bool:
        return verify_hmac_signature(
            body=body,
            signature=signature,
            public_key=public_key,
            timestamp=timestamp,
            redis_secrets={public_key: secret},
        )
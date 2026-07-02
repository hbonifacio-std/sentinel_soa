from unittest.mock import AsyncMock, Mock

import pytest

from core_orchestrator.application.modules.auth_clients.services.telemetry_client_service import TelemetryClientService
from core_orchestrator.domain.models.auth.telemetry_client import TelemetryClientInDB


def _build_client() -> TelemetryClientInDB:
    return TelemetryClientInDB(
        client_id="collector-1",
        source_id="victim-api",
        display_name="Victim Collector",
        api_key="1234567890abcdef",
        hmac_public_key="pub-key-1",
        hmac_secret="abcdef1234567890",
        is_active=True,
    )


@pytest.mark.asyncio
async def test_authorize_hmac_returns_auth_context_when_signature_is_valid() -> None:
    repository = AsyncMock()
    signature_verifier = Mock()
    service = TelemetryClientService(repository, signature_verifier)
    client = _build_client()

    repository.get_by_public_key.return_value = client
    signature_verifier.verify_hmac_signature.return_value = True

    auth_context = await service.authorize_hmac(
        public_key="pub-key-1",
        signature="sig-1",
        timestamp=1700000000,
        body=b'{"event": "ok"}',
    )

    assert auth_context is not None
    assert auth_context.client_id == "collector-1"
    signature_verifier.verify_hmac_signature.assert_called_once_with(
        body=b'{"event": "ok"}',
        signature="sig-1",
        public_key="pub-key-1",
        timestamp=1700000000,
        secret="abcdef1234567890",
    )


@pytest.mark.asyncio
async def test_authorize_hmac_returns_none_when_signature_is_invalid() -> None:
    repository = AsyncMock()
    signature_verifier = Mock()
    service = TelemetryClientService(repository, signature_verifier)
    client = _build_client()

    repository.get_by_public_key.return_value = client
    signature_verifier.verify_hmac_signature.return_value = False

    auth_context = await service.authorize_hmac(
        public_key="pub-key-1",
        signature="invalid",
        timestamp=1700000000,
        body=b"{}",
    )

    assert auth_context is None


"""
Tests for:
  - sanitizer.redact_sensitive_data
  - JwtTokenService (token_manager_port.py)
  - HmacSignatureVerifier (signature_verifier.py)
  - API dependency provider functions (general_dependencies.py)
"""
import pytest
from unittest.mock import MagicMock

# ===========================================================================
# sanitizer_utility.py
# ===========================================================================
from core_orchestrator.infrastructure.adapters.temeletry.sanitizer_utility import redact_sensitive_data, REDACTION_MASK


class TestRedactSensitiveData:
    def test_redacts_known_keys(self):
        data = {"username": "alice", "password": "secret123", "token": "tok"}
        result = redact_sensitive_data(data)
        assert result["password"] == REDACTION_MASK
        assert result["token"] == REDACTION_MASK
        assert result["username"] == "alice"

    def test_does_not_mutate_original_by_default(self):
        data = {"password": "secret"}
        result = redact_sensitive_data(data, inplace=False)
        assert data["password"] == "secret"
        assert result["password"] == REDACTION_MASK

    def test_inplace_mutates_original(self):
        data = {"token": "abc"}
        redact_sensitive_data(data, inplace=True)
        assert data["token"] == REDACTION_MASK

    def test_redacts_nested_dict(self):
        data = {"user": {"password": "nested-secret", "name": "bob"}}
        result = redact_sensitive_data(data)
        assert result["user"]["password"] == REDACTION_MASK
        assert result["user"]["name"] == "bob"

    def test_redacts_inside_list(self):
        data = [{"authorization": "Bearer tok"}, {"safe": "value"}]
        result = redact_sensitive_data(data)
        assert result[0]["authorization"] == REDACTION_MASK
        assert result[1]["safe"] == "value"

    def test_case_insensitive_key_matching(self):
        data = {"Authorization": "Bearer xyz", "TOKEN": "abc"}
        result = redact_sensitive_data(data)
        assert result["Authorization"] == REDACTION_MASK
        assert result["TOKEN"] == REDACTION_MASK

    def test_custom_sensitive_keys(self):
        data = {"email": "test@example.com", "public_info": "visible"}
        result = redact_sensitive_data(data, sensitive_keys=["email"])
        assert result["email"] == REDACTION_MASK
        assert result["public_info"] == "visible"

    def test_empty_dict_returns_empty(self):
        assert redact_sensitive_data({}) == {}

    def test_empty_list_returns_empty(self):
        assert redact_sensitive_data([]) == []

    def test_non_sensitive_keys_unchanged(self):
        data = {"name": "Alice", "age": 30}
        result = redact_sensitive_data(data)
        assert result == {"name": "Alice", "age": 30}


# ===========================================================================
# token_manager_port.py — JwtTokenService
# ===========================================================================
class TestJwtTokenService:
    @pytest.fixture
    def token_service(self):
        from core_orchestrator.infrastructure.adapters.security.jwt_token_provider_adapter import JwtTokenProviderAdapter
        return JwtTokenProviderAdapter()

    def test_create_access_token_returns_token_and_jti(self, token_service):
        token, jti = token_service.create_access_token(
            user_id="u1", username="alice", role="admin"
        )
        assert isinstance(token, str)
        assert len(token) > 0
        assert isinstance(jti, str)
        assert len(jti) > 0

    def test_get_token_jti_returns_jti(self, token_service):
        token, original_jti = token_service.create_access_token(
            user_id="u2", username="bob", role="viewer"
        )
        extracted_jti = token_service.get_token_jti(token)
        assert extracted_jti == original_jti

    def test_get_token_jti_invalid_token_returns_none(self, token_service):
        result = token_service.get_token_jti("not.a.valid.token")
        assert result is None


# ===========================================================================
# signature_verifier.py — HmacSignatureVerifier
# ===========================================================================
class TestHmacSignatureVerifier:
    @pytest.fixture
    def verifier(self):
        from core_orchestrator.infrastructure.security.signature_verifier import HmacSignatureVerifier
        return HmacSignatureVerifier()

    def _make_valid_signature(self, body: bytes, public_key: str, secret: str, timestamp: int) -> str:
        import hmac, hashlib
        message = f"{timestamp}:{body.decode('utf-8')}".encode("utf-8")
        return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()

    def test_valid_hmac_returns_true(self, verifier):
        from datetime import datetime, timezone
        body = b"test-payload"
        timestamp = int(datetime.now(timezone.utc).timestamp())
        secret = "my-secret"
        pub_key = "key-1"
        sig = self._make_valid_signature(body, pub_key, secret, timestamp)
        assert verifier.verify_hmac_signature(body, sig, pub_key, timestamp, secret) is True

    def test_invalid_signature_returns_false(self, verifier):
        from datetime import datetime, timezone
        body = b"test-payload"
        timestamp = int(datetime.now(timezone.utc).timestamp())
        assert verifier.verify_hmac_signature(body, "bad-sig", "key-1", timestamp, "secret") is False


# ===========================================================================
# general_dependencies.py — Provider functions
# ===========================================================================
class TestApiDependencies:
    @pytest.fixture
    def mock_container(self):
        container = MagicMock()
        container.db_manager = MagicMock()
        container.analytics_service = MagicMock()
        container.auth_service = MagicMock()
        container.rule_service = MagicMock()
        container.rules_engine_service = MagicMock()
        container.rule_validator = MagicMock()
        container.telemetry_client_service = MagicMock()
        container.telemetry_service = MagicMock()
        container.telemetry_processing_service = MagicMock()
        container.user_service = MagicMock()
        container.forensic_service = MagicMock()
        container.agent_runner = MagicMock()
        container.limiter = MagicMock()
        return container

    def test_get_db_manager(self, mock_container):
        from core_orchestrator.infrastructure.api.dependencies import get_db_manager
        result = get_db_manager(mock_container)
        assert result is mock_container.db_manager

    def test_get_analytics_service(self, mock_container):
        from core_orchestrator.infrastructure.api.dependencies import get_analytics_service
        assert get_analytics_service(mock_container) is mock_container.analytics_service

    def test_get_auth_service(self, mock_container):
        from core_orchestrator.infrastructure.api.dependencies import get_auth_service
        assert get_auth_service(mock_container) is mock_container.auth_service

    def test_get_rule_service(self, mock_container):
        from core_orchestrator.infrastructure.api.dependencies import get_rule_service
        assert get_rule_service(mock_container) is mock_container.rule_service

    def test_get_rules_engine_service(self, mock_container):
        from core_orchestrator.infrastructure.api.dependencies import get_rules_engine_service
        assert get_rules_engine_service(mock_container) is mock_container.rules_engine_service

    def test_get_rule_validator(self, mock_container):
        from core_orchestrator.infrastructure.api.dependencies import get_rule_validator
        assert get_rule_validator(mock_container) is mock_container.rule_validator

    def test_get_telemetry_client_service(self, mock_container):
        from core_orchestrator.infrastructure.api.dependencies import get_telemetry_client_service
        assert get_telemetry_client_service(mock_container) is mock_container.telemetry_client_service

    def test_get_telemetry_service(self, mock_container):
        from core_orchestrator.infrastructure.api.dependencies import get_telemetry_service
        assert get_telemetry_service(mock_container) is mock_container.telemetry_service

    def test_get_telemetry_processing_service(self, mock_container):
        from core_orchestrator.infrastructure.api.dependencies import get_telemetry_processing_service
        assert get_telemetry_processing_service(mock_container) is mock_container.telemetry_processing_service

    def test_get_user_service(self, mock_container):
        from core_orchestrator.infrastructure.api.dependencies import get_user_service
        assert get_user_service(mock_container) is mock_container.user_service

    def test_get_forensic_service(self, mock_container):
        from core_orchestrator.infrastructure.api.dependencies import get_forensic_service
        assert get_forensic_service(mock_container) is mock_container.forensic_service

    def test_get_agent_runner(self, mock_container):
        from core_orchestrator.infrastructure.api.dependencies import get_agent_runner
        assert get_agent_runner(mock_container) is mock_container.agent_runner

    def test_get_limiter(self, mock_container):
        from core_orchestrator.infrastructure.api.dependencies import get_limiter
        assert get_limiter(mock_container) is mock_container.limiter

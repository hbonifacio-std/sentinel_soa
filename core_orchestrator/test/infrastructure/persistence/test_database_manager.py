"""
Tests for DatabaseManager (config/database_manager.py).
Mocks pymongo and redis to avoid real connections.
"""
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
@pytest.fixture
def db_manager():
    """Return a DatabaseManager with no real external connections."""
    from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
    return DatabaseManager()


# ---------------------------------------------------------------------------
# __init__ defaults
# ---------------------------------------------------------------------------
class TestDatabaseManagerInit:
    def test_defaults_when_env_vars_absent(self, monkeypatch):
        monkeypatch.delenv("MONGO_DB_NAME", raising=False)
        monkeypatch.delenv("AUTH_MONGO_DB_NAME", raising=False)
        monkeypatch.delenv("RULES_MONGO_DB_NAME", raising=False)
        from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
        dm = DatabaseManager()
        assert dm.telemetry_mongo_db_name == "sentinel_soa"
        assert dm.auth_mongo_db_name == "auth"
        assert dm.rules_mongo_db_name == "heuristic"
        assert dm.mongo_client is None
        assert dm.redis_client_window_telemetry is None

    def test_env_vars_override_defaults(self, monkeypatch):
        monkeypatch.setenv("MONGO_DB_NAME", "custom_db")
        monkeypatch.setenv("AUTH_MONGO_DB_NAME", "custom_auth")
        monkeypatch.setenv("RULES_MONGO_DB_NAME", "custom_rules")
        from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
        dm = DatabaseManager()
        assert dm.telemetry_mongo_db_name == "custom_db"
        assert dm.auth_mongo_db_name == "custom_auth"
        assert dm.rules_mongo_db_name == "custom_rules"


# ---------------------------------------------------------------------------
# connect / disconnect
# ---------------------------------------------------------------------------
class TestDatabaseManagerConnect:
    @patch("core_orchestrator.infrastructure.config.database.AsyncMongoClient")
    @patch("core_orchestrator.infrastructure.config.database.Redis")
    def test_connect_initialises_both_clients(self, mock_redis_cls, mock_mongo_cls):
        from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
        dm = DatabaseManager()
        dm.connect()
        mock_mongo_cls.assert_called_once()
        assert mock_redis_cls.call_count >= 1
        assert dm.mongo_client is not None
        assert dm.redis_client_window_telemetry is not None

    @patch("core_orchestrator.infrastructure.config.database.AsyncMongoClient")
    @patch("core_orchestrator.infrastructure.config.database.Redis")
    def test_connect_with_credentials_builds_auth_uri(
        self, mock_redis_cls, mock_mongo_cls, monkeypatch
    ):
        monkeypatch.setenv("MONGO_USER", "user1")
        monkeypatch.setenv("MONGO_PASSWORD", "pass1")
        monkeypatch.setenv("MONGO_HOST", "myhost")
        monkeypatch.setenv("MONGO_PORT", "27017")
        from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
        dm = DatabaseManager()
        dm.connect()
        call_uri = mock_mongo_cls.call_args[0][0]
        assert "user1" in call_uri
        assert "pass1" in call_uri
        assert "myhost" in call_uri

    @patch("core_orchestrator.infrastructure.config.database.AsyncMongoClient")
    @patch("core_orchestrator.infrastructure.config.database.Redis")
    def test_connect_without_credentials_no_auth_uri(
        self, mock_redis_cls, mock_mongo_cls, monkeypatch
    ):
        monkeypatch.setenv("MONGO_USER", "")
        monkeypatch.setenv("MONGO_PASSWORD", "")
        from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
        dm = DatabaseManager()
        dm.connect()
        call_uri = mock_mongo_cls.call_args[0][0]
        assert "@" not in call_uri

    def test_disconnect_closes_clients(self):
        from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
        dm = DatabaseManager()
        mock_mongo = MagicMock()
        mock_redis = MagicMock()
        dm.mongo_client = mock_mongo
        dm.redis_client_window_telemetry = mock_redis
        dm.disconnect()
        mock_mongo.close.assert_called_once()
        mock_redis.close.assert_called()

    def test_disconnect_when_no_clients_is_safe(self):
        from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
        dm = DatabaseManager()
        # Should not raise
        dm.disconnect()


# ---------------------------------------------------------------------------
# get_* methods
# ---------------------------------------------------------------------------
class TestDatabaseManagerGetters:
    def test_get_rules_db_raises_when_not_connected(self, db_manager):
        with pytest.raises(RuntimeError, match="not connected"):
            db_manager.get_rules_db()

    def test_get_telemetry_db_raises_when_not_connected(self, db_manager):
        with pytest.raises(RuntimeError, match="not connected"):
            db_manager.get_telemetry_db()

    def test_get_sentinel_db_raises_when_not_connected(self, db_manager):
        with pytest.raises(RuntimeError, match="not connected"):
            db_manager.get_sentinel_db()

    def test_get_auth_db_raises_when_not_connected(self, db_manager):
        with pytest.raises(RuntimeError, match="not connected"):
            db_manager.get_auth_db()

    def test_get_rules_db_returns_correct_db(self, db_manager):
        mock_client = MagicMock()
        db_manager.mongo_client = mock_client
        db_manager.rules_mongo_db_name = "heuristic"
        db_manager.get_rules_db()
        mock_client.__getitem__.assert_called_once_with("heuristic")

    def test_get_telemetry_db_returns_app_db(self, db_manager):
        mock_client = MagicMock()
        db_manager.mongo_client = mock_client
        db_manager.telemetry_mongo_db_name = "sentinel_soa"
        db_manager.get_telemetry_db()
        mock_client.__getitem__.assert_called_once_with("sentinel_soa")

    def test_get_auth_db_returns_auth_db(self, db_manager):
        mock_client = MagicMock()
        db_manager.mongo_client = mock_client
        db_manager.auth_mongo_db_name = "auth"
        db_manager.get_auth_db()
        mock_client.__getitem__.assert_called_once_with("auth")

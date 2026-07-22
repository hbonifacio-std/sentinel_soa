"""
Tests for MongoAuditRepository.
Uses mocked MongoDB collection (motor-like AsyncMock).
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_collection():
    col = MagicMock()
    # find() returns a cursor mock
    cursor = MagicMock()
    cursor.sort.return_value = cursor
    cursor.skip.return_value = cursor
    cursor.limit.return_value = cursor
    cursor.to_list = AsyncMock(return_value=[])
    col.find.return_value = cursor
    col.insert_one = AsyncMock(return_value=MagicMock(inserted_id="abc123"))
    return col


@pytest.fixture
def audit_repo(mock_collection):
    mock_db = MagicMock()
    mock_db.__getitem__.return_value = mock_collection

    mock_db_manager = MagicMock()
    mock_db_manager.get_rules_db.return_value = mock_db

    from core_orchestrator.infrastructure.persistence.mongo_audit_repository import MongoAuditRepository
    repo = MongoAuditRepository(mock_db_manager)
    return repo, mock_collection


# ---------------------------------------------------------------------------
# get_logs
# ---------------------------------------------------------------------------
class TestGetLogs:
    @pytest.mark.asyncio
    async def test_get_logs_no_filter(self, audit_repo):
        repo, col = audit_repo
        col.find.return_value.to_list.return_value = [{"action": "create"}]
        col.find.return_value.sort.return_value.skip.return_value.limit.return_value.to_list = AsyncMock(
            return_value=[{"action": "create"}]
        )
        results = await repo.get_logs(client_id="client-1")
        col.find.assert_called_once_with({"client_id": "client-1"})
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_get_logs_with_rule_id_filter(self, audit_repo):
        repo, col = audit_repo
        cursor = col.find.return_value
        cursor.sort.return_value = cursor
        cursor.skip.return_value = cursor
        cursor.limit.return_value = cursor
        cursor.to_list = AsyncMock(return_value=[{"rule_id": "r1"}])

        results = await repo.get_logs(client_id="client-1", rule_id="r1")
        col.find.assert_called_once_with({"client_id": "client-1", "rule_id": "r1"})

    @pytest.mark.asyncio
    async def test_get_logs_respects_limit_and_offset(self, audit_repo):
        repo, col = audit_repo
        cursor = col.find.return_value
        cursor.sort.return_value = cursor
        cursor.skip.return_value = cursor
        cursor.limit.return_value = cursor
        cursor.to_list = AsyncMock(return_value=[])

        await repo.get_logs(client_id="client-1", limit=10, offset=5)
        cursor.sort.return_value.skip.assert_called_once_with(5)
        cursor.sort.return_value.skip.return_value.limit.assert_called_once_with(10)


# ---------------------------------------------------------------------------
# log_action
# ---------------------------------------------------------------------------
class TestLogAction:
    @pytest.mark.asyncio
    async def test_log_action_inserts_document(self, audit_repo):
        repo, col = audit_repo
        await repo.log_action(
            action="create",
            rule_id="rule-1",
            user="admin",
            changes={"name": "new-rule"},
            reason="testing",
            ip_address="127.0.0.1",
            client_id="client-1",
        )
        col.insert_one.assert_awaited_once()
        inserted_doc = col.insert_one.call_args[0][0]
        assert inserted_doc["action"] == "create"
        assert inserted_doc["rule_id"] == "rule-1"
        assert inserted_doc["user"] == "admin"
        assert inserted_doc["client_id"] == "client-1"
        assert inserted_doc["ip_address"] == "127.0.0.1"
        assert "timestamp" in inserted_doc
        assert inserted_doc["timestamp"].tzinfo is not None  # UTC-aware

    @pytest.mark.asyncio
    async def test_log_action_timestamp_is_utc(self, audit_repo):
        repo, col = audit_repo
        await repo.log_action("delete", "r2", "user1", {}, "cleanup", "10.0.0.1", "client-2")
        doc = col.insert_one.call_args[0][0]
        assert doc["timestamp"].tzinfo == timezone.utc

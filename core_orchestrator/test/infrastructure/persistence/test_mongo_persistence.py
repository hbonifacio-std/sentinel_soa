"""Tests for Mongo persistence adapters (Analytics, Rules, Forensic Analysis)."""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone
import uuid
from bson import ObjectId
from pydantic import BaseModel

from core_orchestrator.infrastructure.persistence.mongo_analytics_repository import MongoAnalyticsRepository
from core_orchestrator.infrastructure.persistence.mongo_rule_repository import MongoRuleRepository
from core_orchestrator.infrastructure.persistence.mongo_forensic_analysis_repository import MongoForensicAnalysisRepository
from core_orchestrator.domain.models.rule_engine.rules import HeuristicRule, RuleVersion, RuleContent, RuleMetadata
from core_orchestrator.domain.models.forensic.forensic_analysis import (
    ForensicAnalyzeRequest,
    ForensicAnalysisRecord,
    ForensicHistoryQuery,
)


@pytest.fixture
def mock_db_manager():
    manager = MagicMock()
    db = MagicMock()
    
    # Store references to collections dynamically
    collections = {}
    def get_collection(name):
        if name not in collections:
            mock_col = AsyncMock()
            mock_col.find = MagicMock()
            # Also mock find return value to be a cursor mock
            cursor = MagicMock()
            cursor.sort.return_value = cursor
            cursor.skip.return_value = cursor
            cursor.limit.return_value = cursor
            cursor.to_list = AsyncMock(return_value=[])
            mock_col.find.return_value = cursor
            collections[name] = mock_col
        return collections[name]

    db.__getitem__.side_effect = get_collection
    db.client = AsyncMock()
    
    # Pre-populate known collections so they are accessible before repository instantiation
    for name in ["analysis_reports", "raw_telemetry", "heuristic_rules", "rule_versions", "rule_audit_log", "forensic_analysis", "authorized_telemetry_clients"]:
        get_collection(name)
    
    manager.get_telemetry_db.return_value = db
    manager.get_rules_db.return_value = db
    manager.get_auth_db.return_value = db
    return manager, db, collections


# ──────────────────────────────────────────────────────────────────────────────
# MongoAnalyticsRepository Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mongo_analytics_repository_stats(mock_db_manager):
    manager, db, collections = mock_db_manager
    collection = collections["analysis_reports"]

    # Configure cursor mock for aggregates
    cursor1 = AsyncMock()
    cursor1.to_list.return_value = [{"_id": "high", "count": 5}]
    cursor2 = AsyncMock()
    cursor2.to_list.return_value = [{"_id": "initial", "count": 2}]
    cursor3 = AsyncMock()
    cursor3.to_list.return_value = [{"_id": "192.168.1.1", "count": 10}]
    cursor4 = AsyncMock()
    cursor4.to_list.return_value = [{"_id": "recon", "count": 3}]

    collection.aggregate.side_effect = [cursor1, cursor2, cursor3, cursor4]

    repo = MongoAnalyticsRepository(manager)
    stats = await repo.get_summary_stats()

    assert stats["threat_levels"] == [{"level": "high", "count": 5}]
    assert stats["kill_chain_phases"] == [{"phase": "initial", "count": 2}]
    assert stats["top_attackers"] == [{"attacker": "192.168.1.1", "count": 10}]
    assert stats["mitre_tactics"] == [{"phase": "recon", "count": 3}]


@pytest.mark.asyncio
async def test_mongo_analytics_repository_get_paginated_reports(mock_db_manager):
    manager, db, collections = mock_db_manager
    collection = collections["analysis_reports"]

    # Mock find_paginated output
    doc_id = ObjectId()
    collection.find.return_value.to_list.return_value = [{"_id": doc_id, "data": "val"}]
    collection.count_documents.return_value = 1

    repo = MongoAnalyticsRepository(manager)
    res = await repo.get_paginated_reports({}, 1, 10)
    assert res["results"][0]["id"] == str(doc_id)


@pytest.mark.asyncio
async def test_mongo_analytics_repository_get_report_by_id(mock_db_manager):
    manager, db, collections = mock_db_manager
    collection = collections["analysis_reports"]

    repo = MongoAnalyticsRepository(manager)
    client_id = "client-1"

    # Invalid ID
    assert await repo.get_report_by_id("invalid-id", client_id) is None

    # Valid ID found
    doc_id = ObjectId()
    collection.find_one.return_value = {"_id": doc_id, "status": "analyzed"}
    res = await repo.get_report_by_id(str(doc_id), client_id)
    assert res is not None
    assert res["id"] == str(doc_id)

    # Valid ID not found
    collection.find_one.return_value = None
    assert await repo.get_report_by_id(str(doc_id), client_id) is None


@pytest.mark.asyncio
async def test_mongo_analytics_repository_update_report(mock_db_manager):
    manager, db, collections = mock_db_manager
    collection = collections["analysis_reports"]

    repo = MongoAnalyticsRepository(manager)
    client_id = "client-1"

    # Invalid ID
    assert await repo.update_report("invalid", client_id, {}) is False

    # Valid update
    doc_id = ObjectId()
    collection.update_one.return_value = MagicMock(modified_count=1)
    res = await repo.update_report(str(doc_id), client_id, {"status": "done"})
    assert res is True


@pytest.mark.asyncio
async def test_mongo_analytics_repository_add_action_to_report(mock_db_manager):
    manager, db, collections = mock_db_manager
    collection = collections["analysis_reports"]

    repo = MongoAnalyticsRepository(manager)
    client_id = "client-1"

    # Invalid ID
    assert await repo.add_action_to_report("invalid", client_id, {}) is False

    # Valid add action
    doc_id = ObjectId()
    collection.update_one.return_value = MagicMock(modified_count=1)
    res = await repo.add_action_to_report(str(doc_id), client_id, {"type": "block"})
    assert res is True


@pytest.mark.asyncio
async def test_mongo_analytics_repository_distinct_and_aggregated_stats(mock_db_manager):
    manager, db, collections = mock_db_manager
    collection = collections["analysis_reports"]

    repo = MongoAnalyticsRepository(manager)

    collection.distinct.return_value = ["src-1", "src-2"]
    distinct = await repo.get_distinct_source_ids("client-1")
    assert distinct == ["src-1", "src-2"]

    cursor = AsyncMock()
    cursor.to_list.return_value = [{"_id": "test", "nested": [{"_id": ObjectId()}]}]
    collection.aggregate.return_value = cursor
    stats = await repo.get_aggregated_stats([])
    assert len(stats) == 1


@pytest.mark.asyncio
async def test_mongo_analytics_repository_get_paginated_logs(mock_db_manager):
    manager, db, collections = mock_db_manager
    logs_collection = collections["raw_telemetry"]

    doc_id = ObjectId()
    logs_collection.find.return_value.to_list.return_value = [{"_id": doc_id, "data": "log"}]
    logs_collection.count_documents.return_value = 1

    repo = MongoAnalyticsRepository(manager)
    res = await repo.get_paginated_logs({}, 1, 10)
    assert res["info"]["total_records"] == 1
    assert res["results"][0]["_id"] == str(doc_id)


@pytest.mark.asyncio
async def test_mongo_analytics_repository_get_debug_reports(mock_db_manager):
    manager, db, collections = mock_db_manager
    collection = collections["analysis_reports"]

    doc_id = ObjectId()
    collection.find.return_value.to_list.return_value = [{"_id": doc_id}]

    repo = MongoAnalyticsRepository(manager)
    reports = await repo.get_debug_reports("client-1", 5)
    assert reports[0]["_id"] == str(doc_id)


@pytest.mark.asyncio
async def test_mongo_analytics_repository_create_report(mock_db_manager):
    manager, db, collections = mock_db_manager
    collection = collections["analysis_reports"]

    repo = MongoAnalyticsRepository(manager)
    collection.insert_one.return_value = MagicMock(inserted_id="inserted-1")

    class DummyModel(BaseModel):
        val: str

    res = await repo.create_report(DummyModel(val="x"))
    assert res == "inserted-1"


@pytest.mark.asyncio
async def test_mongo_analytics_repository_accepts_string_report_ids(mock_db_manager):
    manager, db, collections = mock_db_manager
    collection = collections["analysis_reports"]

    repo = MongoAnalyticsRepository(manager)
    client_id = "client-1"
    report_id = str(uuid.uuid4())
    collection.find_one.return_value = {"_id": report_id, "source_ip": "10.0.0.1"}
    collection.update_one.return_value = MagicMock(modified_count=1)

    report = await repo.get_report_by_id(report_id, client_id)
    assert report is not None
    assert report["id"] == report_id

    updated = await repo.update_report(report_id, client_id, {"reviewed": True})
    assert updated is True

    action_added = await repo.add_action_to_report(report_id, client_id, {"type": "block"})
    assert action_added is True


# ──────────────────────────────────────────────────────────────────────────────
# MongoRuleRepository Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def dummy_rule():
    return HeuristicRule(
        rule_id="rule-test",
        rule_type="keyword_mapping",
        category="uri",
        version=1,
        is_active=True,
        description="A test rule",
        content=RuleContent(type="keyword_mapping", data={"test": 10}),
        metadata=RuleMetadata(source="test", changed_by="admin", change_reason="init")
    )


@pytest.mark.asyncio
async def test_mongo_rule_repository_crud(mock_db_manager, dummy_rule):
    manager, db, collections = mock_db_manager
    collection = collections["heuristic_rules"]

    repo = MongoRuleRepository(manager)

    collection.find_one.return_value = dummy_rule.model_dump(mode="json")
    rule = await repo.get_by_id("rule-test", "client-1")
    assert rule.rule_id == "rule-test"

    # get_all
    collection.find.return_value.to_list.return_value = [dummy_rule.model_dump(mode="json")]
    collection.count_documents.return_value = 1
    all_rules = await repo.get_all(include_inactive=False, client_id="client-1")
    assert len(all_rules) == 1

    # get_by_ids
    collection.find.return_value.to_list.return_value = [dummy_rule.model_dump(mode="json")]
    by_ids = await repo.get_by_ids(["rule-test"], "client-1")
    assert len(by_ids) == 1
    assert await repo.get_by_ids([], "client-1") == []

    # rule_exists
    collection.count_documents.return_value = 1
    assert await repo.rule_exists("rule-test", "client-1") is True

    # update_rule
    collection.update_one.return_value = MagicMock(modified_count=1)
    assert await repo.update_rule("rule-test", "client-1", {"description": "new"}) is True

    # create_rule
    collection.insert_one.return_value = MagicMock()
    created = await repo.create_rule(dummy_rule)
    assert created.rule_id == "rule-test"

    # delete_rule
    assert await repo.delete_rule("rule-test", "client-1") is True


@pytest.mark.asyncio
async def test_mongo_rule_repository_versions(mock_db_manager):
    manager, db, collections = mock_db_manager
    versions_collection = collections["rule_versions"]

    repo = MongoRuleRepository(manager)

    version = RuleVersion(
        version_hash="vhash-1",
        client_id="client-1",
        created_at=datetime.now(timezone.utc),
        rules_included=["rule-1"],
    )

    # create_version
    versions_collection.insert_one.return_value = MagicMock()
    created = await repo.create_version(version)
    assert created.version_hash == "vhash-1"

    # get_version
    versions_collection.find_one.return_value = version.model_dump(mode="json")
    v = await repo.get_version("vhash-1", "client-1")
    assert v.version_hash == "vhash-1"
    versions_collection.find_one.return_value = None
    assert await repo.get_version("vhash-2", "client-1") is None

    # get_active_version
    versions_collection.find_one.return_value = version.model_dump(mode="json")
    v_act = await repo.get_active_version("client-1")
    assert v_act.version_hash == "vhash-1"

    # list_versions
    cursor = versions_collection.find.return_value

    async def _async_iter(*args, **kwargs):
        yield version.model_dump(mode="json")

    cursor.__aiter__ = _async_iter

    versions = await repo.list_versions("client-1", 50)
    assert len(versions) == 1
    assert versions[0].version_hash == "vhash-1"


@pytest.mark.asyncio
async def test_mongo_rule_repository_activate_version_success(mock_db_manager):
    manager, db, collections = mock_db_manager
    versions_collection = collections["rule_versions"]

    client = AsyncMock()
    session = AsyncMock()
    client.start_session.return_value = session
    
    # Mock async context manager for session.start_transaction
    session.start_transaction = MagicMock()
    tx_ctx = AsyncMock()
    session.start_transaction.return_value = tx_ctx
    tx_ctx.__aenter__ = AsyncMock(return_value=session)
    tx_ctx.__aexit__ = AsyncMock(return_value=False)
    
    db.client = client

    versions_collection.update_many = AsyncMock()
    versions_collection.update_one = AsyncMock(return_value=MagicMock(modified_count=1))

    repo = MongoRuleRepository(manager)
    res = await repo.activate_version("vhash-1", "client-1")
    assert res is True
    session.end_session.assert_called_once()


@pytest.mark.asyncio
async def test_mongo_rule_repository_activate_version_fail(mock_db_manager):
    manager, db, collections = mock_db_manager
    versions_collection = collections["rule_versions"]

    client = AsyncMock()
    session = AsyncMock()
    client.start_session.return_value = session
    
    session.start_transaction = MagicMock()
    tx_ctx = AsyncMock()
    session.start_transaction.return_value = tx_ctx
    tx_ctx.__aenter__ = AsyncMock(return_value=session)
    tx_ctx.__aexit__ = AsyncMock(return_value=False)
    
    db.client = client

    # Return modified_count = 0 to trigger value error and rollback
    versions_collection.update_one = AsyncMock(return_value=MagicMock(modified_count=0))

    repo = MongoRuleRepository(manager)
    res = await repo.activate_version("vhash-1", "client-1")
    assert res is False
    session.end_session.assert_called_once()


# ──────────────────────────────────────────────────────────────────────────────
# MongoForensicAnalysisRepository Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mongo_forensic_repository_query_telemetry(mock_db_manager):
    manager, db, collections = mock_db_manager
    raw_collection = collections["raw_telemetry"]

    doc_id = ObjectId()
    raw_collection.find.return_value.to_list.return_value = [{"_id": doc_id, "user_agent": "curl"}]
    raw_collection.count_documents.return_value = 1

    repo = MongoForensicAnalysisRepository(manager)

    request = ForensicAnalyzeRequest(
        query="curl",
        source_id="src-1",
        limit=10,
        page=1
    )

    docs, total = await repo.query_telemetry(request)
    assert total == 1
    assert docs[0]["id"] == str(doc_id)
    assert docs[0]["user_agent"] == "curl"


@pytest.mark.asyncio
async def test_mongo_forensic_repository_save_and_get_analysis(mock_db_manager):
    manager, db, collections = mock_db_manager
    analysis_collection = collections["forensic_analysis"]

    repo = MongoForensicAnalysisRepository(manager)

    # Save
    doc_id = ObjectId()
    analysis_collection.insert_one.return_value = MagicMock(inserted_id=doc_id)
    record = ForensicAnalysisRecord(
        analysis_id="any-id",
        query="test",
        source_id="src-1",
        client_id="client-1",
        total_matches=10,
        markdown_report="some report",
    )
    analysis_id = await repo.save_analysis(record)
    assert analysis_id == str(doc_id)

    # Get by ID (using analysis_id first)
    analysis_collection.find_one.side_effect = [
        record.model_dump(mode="json"),  # first call in _find_analysis_document
    ]
    res = await repo.get_analysis_by_id(analysis_id, "client-1")
    assert res is not None
    assert res.source_id == "src-1"

    # Get by ID (fallback to _id)
    analysis_collection.find_one.side_effect = [
        None,  # not found by analysis_id
        {"_id": doc_id, "analysis_id": str(doc_id), "source_id": "src-1", "query": "test", "total_matches": 10, "markdown_report": "some report"},
    ]
    res = await repo.get_analysis_by_id(analysis_id, "client-1")
    assert res is not None

    # Get by ID not found at all
    analysis_collection.find_one.side_effect = [None, None]
    assert await repo.get_analysis_by_id(analysis_id, "client-1") is None

    # Get by ID invalid ObjectId fallback
    analysis_collection.find_one.side_effect = [None]
    assert await repo.get_analysis_by_id("invalid-obj-id", "client-1") is None


@pytest.mark.asyncio
async def test_mongo_forensic_repository_history(mock_db_manager):
    manager, db, collections = mock_db_manager
    analysis_collection = collections["forensic_analysis"]

    doc_id = ObjectId()
    analysis_collection.find.return_value.to_list.return_value = [
        {"_id": doc_id, "analysis_id": str(doc_id), "source_id": "src-1", "query": "test", "total_matches": 10, "markdown_report": "some report"}
    ]
    analysis_collection.count_documents.return_value = 1

    repo = MongoForensicAnalysisRepository(manager)

    query = ForensicHistoryQuery(source_id="src-1", client_id="client-1", limit=10, page=1)
    res = await repo.get_history(query)
    assert res["info"]["total_records"] == 1
    assert res["results"][0].source_id == "src-1"


# ──────────────────────────────────────────────────────────────────────────────
# MongoTelemetryClientRepository Tests
# ──────────────────────────────────────────────────────────────────────────────
from core_orchestrator.infrastructure.persistence.mongo_telemetry_client_repository import MongoTelemetryClientRepository
from core_orchestrator.domain.models.auth.telemetry_client import TelemetryClientCreate, TelemetryClientInDB

def _make_telemetry_client_payload() -> TelemetryClientCreate:
    return TelemetryClientCreate(
        client_id="client-1",
        source_id="src-1",
        display_name="Client 1",
        api_key="api-key-key-key-key",
        hmac_public_key="pubkey-1",
        hmac_secret="secret-secret-secret",
        is_active=True
    )

@pytest.mark.asyncio
async def test_mongo_telemetry_client_repository_get_by_various(mock_db_manager):
    manager, db, collections = mock_db_manager
    collection = collections["authorized_telemetry_clients"]
    repo = MongoTelemetryClientRepository(manager)

    client_data = _make_telemetry_client_payload().model_dump()
    client_data["created_at"] = datetime.now(timezone.utc)
    client_data["updated_at"] = datetime.now(timezone.utc)

    # get
    collection.find_one.return_value = client_data
    res = await repo.get("client-1")
    assert res.client_id == "client-1"
    
    collection.find_one.return_value = None
    assert await repo.get("client-2") is None

    # get_by_public_key
    collection.find_one.return_value = client_data
    res = await repo.get_by_public_key("pubkey-1")
    assert res.client_id == "client-1"

    # get_by_client_id
    collection.find_one.return_value = client_data
    res = await repo.get_by_client_id("client-1", include_inactive=True)
    assert res.client_id == "client-1"


@pytest.mark.asyncio
async def test_mongo_telemetry_client_repository_create_and_list(mock_db_manager):
    manager, db, collections = mock_db_manager
    collection = collections["authorized_telemetry_clients"]
    repo = MongoTelemetryClientRepository(manager)

    payload = _make_telemetry_client_payload()
    collection.insert_one.return_value = MagicMock()

    client = await repo.create(payload)
    assert client.client_id == "client-1"

    # list_all
    client_data = payload.model_dump()
    client_data["created_at"] = datetime.now(timezone.utc)
    client_data["updated_at"] = datetime.now(timezone.utc)
    collection.find.return_value.to_list.return_value = [client_data]

    clients = await repo.list_all(include_inactive=True)
    assert len(clients) == 1
    assert clients[0].client_id == "client-1"


@pytest.mark.asyncio
async def test_mongo_telemetry_client_repository_upsert(mock_db_manager):
    manager, db, collections = mock_db_manager
    collection = collections["authorized_telemetry_clients"]
    repo = MongoTelemetryClientRepository(manager)

    payload = _make_telemetry_client_payload()

    # Case 1: Existing, no overwrite
    existing_data = payload.model_dump()
    existing_data["created_at"] = datetime.now(timezone.utc)
    existing_data["updated_at"] = datetime.now(timezone.utc)
    collection.find_one.return_value = existing_data

    client, created, updated = await repo.upsert(payload, overwrite_existing=False)
    assert created is False
    assert updated is False
    assert client.client_id == "client-1"

    # Case 2: Existing, with overwrite
    collection.find_one.return_value = existing_data
    collection.update_one.return_value = MagicMock()
    client, created, updated = await repo.upsert(payload, overwrite_existing=True)
    assert created is False
    assert updated is True

    # Case 3: Brand new client
    collection.find_one.return_value = None
    collection.insert_one.return_value = MagicMock()
    client, created, updated = await repo.upsert(payload, overwrite_existing=False)
    assert created is True
    assert updated is False


@pytest.mark.asyncio
async def test_mongo_telemetry_client_repository_indexes(mock_db_manager):
    manager, db, collections = mock_db_manager
    collection = collections["authorized_telemetry_clients"]
    repo = MongoTelemetryClientRepository(manager)

    collection.create_index = AsyncMock()
    await repo.ensure_indexes()
    assert collection.create_index.call_count == 4


# ──────────────────────────────────────────────────────────────────────────────
# MongoTelemetryRepository Tests
# ──────────────────────────────────────────────────────────────────────────────
from core_orchestrator.infrastructure.persistence.mongo_telemetry_repository import MongoTelemetryRepository
from core_orchestrator.domain.models.telemetry.log_event import LogEvent
from core_orchestrator.domain.models.analysis import AnalysisReportResponse

def _make_log_event() -> LogEvent:
    return LogEvent(
        source_id="src-1",
        source_ip="1.2.3.4",
        timestamp_utc=datetime.now(timezone.utc),
        network={"client_ip": "1.2.3.4", "client_port": 1234},
        http={"method": "GET", "path": "/test", "status_code": 200, "user_agent": "curl"},
        rule_evaluations=[]
    )

@pytest.mark.asyncio
async def test_mongo_telemetry_repository(mock_db_manager):
    manager, db, collections = mock_db_manager
    collection = collections["raw_telemetry"]
    reports_collection = collections["analysis_reports"]
    repo = MongoTelemetryRepository(manager)

    # insert_log_event
    collection.insert_one.return_value = MagicMock(inserted_id="ins-log")
    log_id = await repo.insert_log_event(_make_log_event())
    assert log_id == "ins-log"

    # bulk_insert_log_events
    collection.bulk_write.return_value = MagicMock(inserted_count=2)
    cnt = await repo.bulk_insert_log_events([_make_log_event(), _make_log_event()])
    assert cnt == 2

    # get_logs_paginated
    collection.count_documents.return_value = 1
    log_data = _make_log_event().model_dump()
    log_data["timestamp_utc"] = datetime.now(timezone.utc)
    collection.find.return_value.to_list.return_value = [log_data]
    res = await repo.get_logs_paginated({}, 1, 10)
    assert res["info"]["total_records"] == 1
    assert len(res["results"]) == 1

    # insert_analysis_report
    reports_collection.insert_one.return_value = MagicMock(inserted_id="report-id")
    dummy_report = AnalysisReportResponse(
        report_id="report-id",
        source_id="src-1",
        timestamp=datetime.now(timezone.utc),
        threat_level="high",
        confidence_score=0.9,
        rule_evaluations=[],
        recommendations=[]
    )
    rep_id = await repo.insert_analysis_report(dummy_report)
    assert rep_id == "report-id"

    # get_analysis_reports_paginated
    reports_collection.count_documents.return_value = 1
    rep_data = dummy_report.model_dump()
    rep_data["timestamp"] = datetime.now(timezone.utc)
    reports_collection.find.return_value.to_list.return_value = [rep_data]
    reports = await repo.get_analysis_reports_paginated({}, 1, 10)
    assert len(reports) == 1
    assert reports[0].report_id == "report-id"

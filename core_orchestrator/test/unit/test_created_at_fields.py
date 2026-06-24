import os
from datetime import datetime, timezone

from bson import ObjectId
from starlette.requests import Request

# Evita validaciones de GEMINI_API_KEY al importar el orquestador en test
os.environ.setdefault("LLM_PROVIDER", "ollama")

from core_orchestrator.agent.orchestrator import ensure_created_at_utc
from core_orchestrator.api.v1.endpoints.analytics import resolve_report_created_at


def test_ensure_created_at_utc_falls_back_to_now_for_empty_value():
    created_at = ensure_created_at_utc(None)

    assert isinstance(created_at, datetime)
    assert created_at.tzinfo is not None


def test_ensure_created_at_utc_parses_iso_string():
    created_at = ensure_created_at_utc("2026-06-19T12:34:56+00:00")

    assert created_at == datetime(2026, 6, 19, 12, 34, 56, tzinfo=timezone.utc)


def test_resolve_report_created_at_uses_object_id_fallback_for_legacy_docs():
    object_id = ObjectId()
    report = {
        "_id": str(object_id),
        "created_at_utc": None,
    }

    created_at = resolve_report_created_at(report)

    assert created_at == object_id.generation_time.isoformat()


import pytest

@pytest.mark.anyio
async def test_get_reports_resolved_at_utc_handling(monkeypatch):
    # Mock collection and reports
    mock_reports = [
        # Report 1: Unresolved, missing resolved_at_utc key
        {
            "_id": ObjectId(),
            "source_id": "test-app",
            "created_at_utc": datetime(2026, 6, 21, 10, 0, 0, tzinfo=timezone.utc),
            "reviewed": False,
            "resolved": False,
        },
        # Report 2: Resolved, has resolved_at_utc key
        {
            "_id": ObjectId(),
            "source_id": "test-app",
            "created_at_utc": datetime(2026, 6, 21, 10, 0, 0, tzinfo=timezone.utc),
            "reviewed": True,
            "resolved": True,
            "resolved_at_utc": datetime(2026, 6, 21, 11, 0, 0, tzinfo=timezone.utc),
        }
    ]
    
    class MockCursor:
        def sort(self, *args, **kwargs):
            return self
        def skip(self, *args, **kwargs):
            return self
        def limit(self, *args, **kwargs):
            return self
        async def to_list(self, length):
            return mock_reports
            
    class MockCollection:
        def find(self, *args, **kwargs):
            return MockCursor()
        async def count_documents(self, *args, **kwargs):
            return len(mock_reports)
            
    monkeypatch.setattr(
        "core_orchestrator.api.v1.endpoints.analytics.get_reports_collection",
        lambda: MockCollection()
    )
    
    from core_orchestrator.api.v1.endpoints.analytics import get_reports

    request = Request({"type": "http", "method": "GET", "path": "/api/v1/analytics/reports", "headers": []})
    res = await get_reports.__wrapped__(request=request, source_id="test-app", page=1, limit=10)
    rows = res["results"]
    
    assert len(rows) == 2
    assert res["info"]["total_records"] == 2
    
    # Check first report (unresolved)
    assert rows[0]["resolved"] is False
    assert rows[0]["resolved_at_utc"] is None
    
    # Check second report (resolved)
    assert rows[1]["resolved"] is True
    assert rows[1]["resolved_at_utc"] == "2026-06-21T11:00:00+00:00"



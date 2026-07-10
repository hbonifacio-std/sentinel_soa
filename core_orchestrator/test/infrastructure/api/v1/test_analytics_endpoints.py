import pytest
from unittest.mock import AsyncMock
from fastapi import FastAPI
from fastapi.testclient import TestClient
from core_orchestrator.infrastructure.api.v1.endpoints.analytics import router
from core_orchestrator.infrastructure.api.dependencies import get_analytics_service
from core_orchestrator.infrastructure.security.dependencies import get_analyst_user_with_client
from core_orchestrator.domain.models.auth.user import UserInDB

# Create dummy user to bypass authentication dependencies
dummy_analyst = UserInDB(
    user_id="u-analyst",
    username="analyst",
    email="analyst@example.com",
    role="analyst",
    is_active=True,
    client_id="client-1",
    hashed_password="hashed_pwd"
)

@pytest.fixture
def mock_analytics_service():
    service = AsyncMock()
    return service

@pytest.fixture
def client(mock_analytics_service):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_analytics_service] = lambda: mock_analytics_service
    app.dependency_overrides[get_analyst_user_with_client] = lambda: dummy_analyst
    yield TestClient(app)
    app.dependency_overrides.clear()

def test_get_logs_row_telemetry(client, mock_analytics_service):
    mock_analytics_service.get_paginated_logs.return_value = {
        "info": {"total_records": 15},
        "results": [{"id": "1", "data": "test"}]
    }
    
    response = client.get("/analytics/logs_row_telemetry?source_id=test-src&page=1&limit=10")
    assert response.status_code == 200
    data = response.json()
    assert data["info"]["total_records"] == 15
    assert len(data["results"]) == 1
    mock_analytics_service.get_paginated_logs.assert_called_once_with(
        page=1, limit=10, client_id="client-1", query={"source_id": "test-src"}
    )

def test_mark_report_reviewed(client, mock_analytics_service):
    mock_analytics_service.mark_report_as_reviewed.return_value = {"id": "rep-1", "reviewed": True}
    response = client.patch("/analytics/reports/rep-1/review")
    assert response.status_code == 200
    assert response.json()["id"] == "rep-1"
    
    # Not found case
    mock_analytics_service.mark_report_as_reviewed.return_value = None
    response = client.patch("/analytics/reports/rep-2/review")
    assert response.status_code == 404
    mock_analytics_service.mark_report_as_reviewed.assert_any_call("rep-1", "client-1")

def test_add_report_action(client, mock_analytics_service):
    mock_analytics_service.add_action_to_report.return_value = {"id": "rep-1", "actions": [{"comment": "checked"}]}
    
    response = client.post("/analytics/reports/rep-1/actions", json={"comment": "checked"})
    assert response.status_code == 200
    mock_analytics_service.add_action_to_report.assert_any_call(
        "rep-1",
        "client-1",
        {"comment": "checked"},
    )
    
    # Not found case
    mock_analytics_service.add_action_to_report.return_value = None
    response = client.post("/analytics/reports/rep-2/actions", json={"comment": "checked"})
    assert response.status_code == 404
    
    # Value error (conflict)
    mock_analytics_service.add_action_to_report.side_effect = ValueError("invalid transition")
    response = client.post("/analytics/reports/rep-1/actions", json={"comment": "checked"})
    assert response.status_code == 409

def test_mark_report_resolved(client, mock_analytics_service):
    mock_analytics_service.mark_report_as_resolved.return_value = {"id": "rep-1", "resolved": True}
    response = client.patch("/analytics/reports/rep-1/resolve")
    assert response.status_code == 200
    
    # Not found case
    mock_analytics_service.mark_report_as_resolved.return_value = None
    response = client.patch("/analytics/reports/rep-2/resolve")
    assert response.status_code == 404
    mock_analytics_service.mark_report_as_resolved.assert_any_call("rep-1", "client-1")

def test_get_source_ids(client, mock_analytics_service):
    mock_analytics_service.get_distinct_source_ids.return_value = ["src-1", "src-2"]
    response = client.get("/analytics/source_ids")
    assert response.status_code == 200
    assert response.json() == ["src-1", "src-2"]
    mock_analytics_service.get_distinct_source_ids.assert_called_once_with("client-1")

def test_get_reports(client, mock_analytics_service):
    mock_analytics_service.get_paginated_reports.return_value = {
        "info": {"total_records": 5},
        "results": [{"id": "rep-1"}]
    }
    response = client.get("/analytics/reports?source_id=src-1&page=1&limit=5")
    assert response.status_code == 200
    data = response.json()
    assert data["info"]["total_records"] == 5
    assert len(data["results"]) == 1
    mock_analytics_service.get_paginated_reports.assert_called_once_with(
        page=1,
        limit=5,
        source_id="src-1",
        client_id="client-1",
    )

def test_get_stats(client, mock_analytics_service):
    mock_analytics_service.get_aggregated_stats.return_value = {"alerts": 10}
    response = client.get("/analytics/stats?source_id=src-1")
    assert response.status_code == 200
    assert response.json() == {"alerts": 10}
    mock_analytics_service.get_aggregated_stats.assert_called_once_with(
        client_id="client-1",
        source_id="src-1",
    )

def test_debug_reports(client, mock_analytics_service):
    mock_analytics_service.get_debug_reports.return_value = [{"id": "debug-1"}]
    response = client.get("/analytics/debug_reports")
    assert response.status_code == 200
    assert response.json() == [{"id": "debug-1"}]
    mock_analytics_service.get_debug_reports.assert_called_once_with("client-1")

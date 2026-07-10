import pytest
from unittest.mock import AsyncMock
from fastapi import FastAPI
from fastapi.testclient import TestClient
from core_orchestrator.infrastructure.api.v1.endpoints.forensic import router
from core_orchestrator.infrastructure.api.dependencies import get_forensic_service
from core_orchestrator.infrastructure.security.dependencies import get_analyst_user_with_client
from core_orchestrator.domain.models.auth.user import UserInDB
from core_orchestrator.domain.models.forensic.forensic_analysis import ForensicAnalysisRecord, ForensicAnalyzeRequest, ForensicHistoryResponse

dummy_analyst = UserInDB(
    user_id="u-analyst",
    username="analyst",
    email="analyst@example.com",
    role="analyst",
    is_active=True,
    client_id="client-1",
    hashed_password="hashed_pwd"
)

dummy_record = ForensicAnalysisRecord(
    analysis_id="an-1",
    query="SELECT foo",
    source_id="src-1",
    client_id="client-1",
    total_matches=0,
    highlights=[],
    markdown_report="looks good",
    sample_results=[]
)

@pytest.fixture
def mock_forensic_service():
    service = AsyncMock()
    return service

@pytest.fixture
def client(mock_forensic_service):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_forensic_service] = lambda: mock_forensic_service
    app.dependency_overrides[get_analyst_user_with_client] = lambda: dummy_analyst
    yield TestClient(app)
    app.dependency_overrides.clear()

def test_run_forensic_analysis(client, mock_forensic_service):
    mock_forensic_service.analyze_activity.return_value = dummy_record
    
    payload = {
        "query": "SELECT foo",
        "source_id": "src-1"
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 201
    assert response.json()["analysis_id"] == "an-1"
    request_arg = mock_forensic_service.analyze_activity.await_args.args[0]
    assert request_arg.client_id == "client-1"

def test_get_forensic_history(client, mock_forensic_service):
    mock_forensic_service.get_analysis_history.return_value = ForensicHistoryResponse(
        info={"total_records": 10, "page": 1, "limit": 10, "next_page": None, "prev_page": None},
        results=[dummy_record]
    )
    
    response = client.get("/history?source_id=src-1&page=1&limit=10")
    assert response.status_code == 200
    data = response.json()
    assert len(data["results"]) == 1
    assert data["results"][0]["analysis_id"] == "an-1"

def test_get_forensic_report_success(client, mock_forensic_service):
    mock_forensic_service.get_analysis_by_id.return_value = dummy_record
    
    response = client.get("/history/an-1")
    assert response.status_code == 200
    assert response.json()["analysis_id"] == "an-1"
    mock_forensic_service.get_analysis_by_id.assert_called_once_with("an-1", "client-1")

def test_get_forensic_report_not_found(client, mock_forensic_service):
    mock_forensic_service.get_analysis_by_id.return_value = None
    
    response = client.get("/history/an-2")
    assert response.status_code == 404
    assert response.json()["detail"] == "Forensic report not found"
    mock_forensic_service.get_analysis_by_id.assert_called_once_with("an-2", "client-1")

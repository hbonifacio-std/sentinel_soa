import pytest
from unittest.mock import AsyncMock, Mock
import json
from datetime import datetime, timezone
from fastapi import FastAPI, BackgroundTasks
from fastapi.testclient import TestClient
from core_orchestrator.infrastructure.api.v1.endpoints.telemetry import router
from core_orchestrator.infrastructure.api.dependencies import (
    get_telemetry_service,
    get_telemetry_processing_service,
    get_agent_runner,
)
from core_orchestrator.infrastructure.security.dependencies import verify_api_key_header
from core_orchestrator.domain.models.auth.telemetry_client import TelemetryClientAuthContext
from core_orchestrator.domain.models.telemetry.log_event import LogEvent

dummy_auth_context = TelemetryClientAuthContext(
    client_id="client-1",
    source_id="src-1",
    display_name="Client One"
)

dummy_event = LogEvent(
    source_id="src-1",
    source_ip="127.0.0.1",
    timestamp_utc=datetime.now(timezone.utc),
    network={"client_ip": "127.0.0.1"},
    http={"method": "GET", "path": "/", "status_code": 200}
)

@pytest.fixture
def mock_telemetry_service():
    return AsyncMock()

@pytest.fixture
def mock_processing_service():
    return AsyncMock()

@pytest.fixture
def mock_agent_runner():
    runner = AsyncMock()
    runner.cache_service = Mock()
    return runner

@pytest.fixture
def client(mock_telemetry_service, mock_processing_service, mock_agent_runner):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_telemetry_service] = lambda: mock_telemetry_service
    app.dependency_overrides[get_telemetry_processing_service] = lambda: mock_processing_service
    app.dependency_overrides[get_agent_runner] = lambda: mock_agent_runner
    app.dependency_overrides[verify_api_key_header] = lambda: dummy_auth_context
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()


batch_headers = {
    "X-Sentinel-SOURCE-ID": "src-1",
    "X-Sentinel-Client-ID": "client-1",
}

def test_ingest_single_event(client, mock_telemetry_service, mock_processing_service):
    payload = dummy_event.model_dump(mode="json")
    response = client.post("/", json=payload)
    assert response.status_code == 202
    assert response.json()["status"] == "accepted"
    mock_processing_service.add_log_event.assert_called_once()

def test_ingest_batch_events_success(client, mock_telemetry_service, mock_processing_service):
    payload = [dummy_event.model_dump(mode="json")]
    response = client.post("/ingest/batch", json=payload, headers=batch_headers)
    assert response.status_code == 202
    assert response.json()["processed_records"] == 1
    mock_processing_service.add_multiple_logs_events.assert_called_once()

    buffered_event = mock_processing_service.add_multiple_logs_events.await_args.args[0][0]
    assert buffered_event.client_id == "client-1"
    assert buffered_event.source_id == "src-1"

def test_ingest_batch_events_empty(client):
    response = client.post("/ingest/batch", json=[], headers=batch_headers)
    assert response.status_code == 400

def test_ingest_batch_events_different_source_ids(client):
    payload = [
        dummy_event.model_dump(mode="json"),
        {**dummy_event.model_dump(mode="json"), "source_id": "src-2"}
    ]
    response = client.post("/ingest/batch", json=payload, headers=batch_headers)
    assert response.status_code == 202
    assert response.json()["processed_records"] == 2

def test_ingest_batch_events_unauthorized_source_id(client):
    payload = [
        {**dummy_event.model_dump(mode="json"), "source_id": "src-other"}
    ]
    headers = dict(batch_headers)
    headers["X-Sentinel-Client-ID"] = "client-other"
    response = client.post("/ingest/batch", json=payload, headers=headers)
    assert response.status_code == 403

def test_flush_windows_success(client, mock_processing_service, mock_agent_runner):
    mock_processing_service.get_active_windows.return_value = [b"win-key"]
    
    mock_lock = AsyncMock()
    mock_lock.acquire.return_value = True
    mock_agent_runner.cache_service.lock.return_value = mock_lock
    
    mock_window = Mock()
    mock_window.model_dump.return_value = {"win": "data"}
    mock_processing_service.process_window.return_value = mock_window
    
    response = client.post("/flush")
    assert response.status_code == 200
    assert response.json()["processed_windows"] == 1

def test_flush_windows_empty(client, mock_processing_service):
    mock_processing_service.get_active_windows.return_value = []
    response = client.post("/flush")
    assert response.status_code == 200
    assert response.json()["processed_windows"] == 0

def test_flush_windows_lock_fail(client, mock_processing_service, mock_agent_runner):
    mock_processing_service.get_active_windows.return_value = [b"win-key"]
    
    mock_lock = AsyncMock()
    mock_lock.acquire.return_value = False
    mock_agent_runner.cache_service.lock.return_value = mock_lock
    
    response = client.post("/flush")
    assert response.status_code == 200
    assert response.json()["processed_windows"] == 0

def test_flush_windows_error(client, mock_processing_service):
    mock_processing_service.get_active_windows.side_effect = Exception("db connection error")
    response = client.post("/flush")
    assert response.status_code == 500

def test_flush_windows_process_none(client, mock_processing_service, mock_agent_runner):
    mock_processing_service.get_active_windows.return_value = [b"win-key"]
    
    mock_lock = AsyncMock()
    mock_lock.acquire.return_value = True
    mock_agent_runner.cache_service.lock.return_value = mock_lock
    
    mock_processing_service.process_window.return_value = None
    
    response = client.post("/flush")
    assert response.status_code == 200
    assert response.json()["processed_windows"] == 0

def test_flush_windows_gather_exception(client, mock_processing_service, mock_agent_runner):
    mock_processing_service.get_active_windows.return_value = [b"win-key"]
    
    mock_lock = AsyncMock()
    mock_lock.acquire.return_value = True
    mock_agent_runner.cache_service.lock.return_value = mock_lock
    
    mock_processing_service.process_window.side_effect = RuntimeError("gather error")
    
    response = client.post("/flush")
    assert response.status_code == 500
    assert "gather error" in response.json()["detail"]

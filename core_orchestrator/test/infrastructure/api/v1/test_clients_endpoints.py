import pytest
from unittest.mock import AsyncMock
from fastapi import FastAPI
from fastapi.testclient import TestClient
from core_orchestrator.infrastructure.api.v1.endpoints.clients import router
from core_orchestrator.infrastructure.api.dependencies import get_telemetry_client_service
from core_orchestrator.infrastructure.api.dependencies.user_auth import get_admin_user
from core_orchestrator.domain.entities.auth.user import UserInDB
from core_orchestrator.domain.entities.auth.telemetry_client import TelemetryClientInDB

dummy_admin = UserInDB(
    user_id="u-admin",
    username="admin",
    email="admin@example.com",
    role="admin",
    is_active=True,
    hashed_password="hashed_pwd"
)

dummy_client = TelemetryClientInDB(
    client_id="client-1",
    source_id="src-1",
    display_name="Client One",
    api_key_hash="api-key-key-key-key",
    hmac_public_key="pubkey-1",
    hmac_secret="secret-secret-secret",
    is_active=True
)

@pytest.fixture
def mock_telemetry_client_service():
    service = AsyncMock()
    return service

@pytest.fixture
def client(mock_telemetry_client_service):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_telemetry_client_service] = lambda: mock_telemetry_client_service
    app.dependency_overrides[get_admin_user] = lambda: dummy_admin
    yield TestClient(app)
    app.dependency_overrides.clear()

def test_list_authorized_clients(client, mock_telemetry_client_service):
    mock_telemetry_client_service.list_clients.return_value = [dummy_client]
    
    response = client.get("/clients?include_inactive=true")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["client_id"] == "client-1"
    mock_telemetry_client_service.list_clients.assert_called_once_with(include_inactive=True)

def test_create_authorized_client_success(client, mock_telemetry_client_service):
    mock_telemetry_client_service.get_client_by_client_id.return_value = None
    mock_telemetry_client_service.upsert_client.return_value = (dummy_client, True, False)
    
    payload = {
        "client_id": "client-1",
        "source_id": "src-1",
        "display_name": "Client One",
        "api_key": "raw-api-key-key-key",
        "hmac_public_key": "pubkey-1",
        "hmac_secret": "raw-secret-secret-secret"
    }
    response = client.post("/clients", json=payload)
    assert response.status_code == 201
    assert response.json()["client_id"] == "client-1"

def test_create_authorized_client_already_exists(client, mock_telemetry_client_service):
    mock_telemetry_client_service.get_client_by_client_id.return_value = dummy_client
    
    payload = {
        "client_id": "client-1",
        "source_id": "src-1",
        "display_name": "Client One",
        "api_key": "raw-api-key-key-key",
        "hmac_public_key": "pubkey-1",
        "hmac_secret": "raw-secret-secret-secret"
    }
    response = client.post("/clients", json=payload)
    assert response.status_code == 409
    assert "already exists" in response.json()["detail"]

import pytest
from unittest.mock import AsyncMock
from fastapi import FastAPI
from fastapi.testclient import TestClient
from core_orchestrator.infrastructure.api.v1.endpoints.auth import router
from core_orchestrator.infrastructure.api.dependencies import get_auth_service
from core_orchestrator.infrastructure.security.dependencies import get_current_user
from core_orchestrator.domain.models.auth.user import UserInDB, TokenResponse, UserResponse

dummy_user = UserInDB(
    user_id="u-1",
    username="alice",
    email="alice@example.com",
    role="admin",
    is_active=True,
    hashed_password="hashed_pwd"
)

@pytest.fixture
def mock_auth_service():
    service = AsyncMock()
    return service

@pytest.fixture
def client(mock_auth_service):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_auth_service] = lambda: mock_auth_service
    app.dependency_overrides[get_current_user] = lambda: dummy_user
    yield TestClient(app)
    app.dependency_overrides.clear()

def test_login_for_access_token_success(client, mock_auth_service):
    mock_auth_service.login.return_value = (dummy_user, "test-access-token")
    
    response = client.post("/token", data={"username": "alice", "password": "password"})
    assert response.status_code == 200
    data = response.json()
    assert data["access_token"] == "test-access-token"
    assert data["user"]["username"] == "alice"

def test_login_for_access_token_failed(client, mock_auth_service):
    mock_auth_service.login.return_value = None
    
    response = client.post("/token", data={"username": "alice", "password": "wrongpassword"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"

def test_get_current_user_info(client):
    response = client.get("/me")
    assert response.status_code == 200
    assert response.json()["username"] == "alice"

def test_logout_success(client, mock_auth_service):
    mock_auth_service.logout.return_value = None
    response = client.post("/logout", headers={"Authorization": "Bearer test-access-token"})
    assert response.status_code == 200
    assert response.json() == {"message": "Logged out successfully"}
    mock_auth_service.logout.assert_called_once_with("test-access-token")

def test_logout_invalid_header(client):
    # Missing authorization header
    response = client.post("/logout")
    assert response.status_code == 401
    
    # Invalid header format
    response = client.post("/logout", headers={"Authorization": "InvalidHeader"})
    assert response.status_code == 401

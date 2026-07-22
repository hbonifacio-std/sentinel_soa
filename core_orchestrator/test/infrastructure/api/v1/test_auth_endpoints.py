import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import FastAPI
from fastapi.testclient import TestClient
from core_orchestrator.infrastructure.security.jwt_utils import create_refresh_token
from core_orchestrator.infrastructure.api.v1.endpoints.auth import router
from core_orchestrator.infrastructure.api.dependencies import get_auth_service, get_db_manager
from core_orchestrator.infrastructure.security.dependencies import get_current_user
from core_orchestrator.domain.models.auth.user import UserInDB, TokenResponse, UserResponse

dummy_user = UserInDB(
    user_id="u-1",
    username="alice",
    email="alice@example.com",
    role="admin",
    is_active=True,
    client_id="client-1",
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

    # Mock the find_one method to be async and conditional
    async def mock_find_one(filter_dict, *args, **kwargs):
        # If client_id is non-existent, return None
        if filter_dict.get("client_id") == "non-existent-client":
            return None
        # Otherwise return the valid tenant
        return {
            "client_id": "client-1",
            "is_active": True,
            "api_key": "client-api-key",
        }

    async def mock_user_find_one(filter_dict, *args, **kwargs):
        if filter_dict.get("user_id") == "u-1":
            return {
                "user_id": "u-1",
                "username": "alice",
                "email": "alice@example.com",
                "role": "admin",
                "is_active": True,
                "client_id": "client-1",
                "created_at": dummy_user.created_at,
                "updated_at": dummy_user.updated_at,
            }
        return None
    
    authorized_clients = MagicMock()
    authorized_clients.find_one = mock_find_one
    users = MagicMock()
    users.find_one = mock_user_find_one
    auth_db = MagicMock()
    auth_db.authorized_telemetry_clients = authorized_clients
    auth_db.users = users
    db_manager = MagicMock()
    db_manager.mongo_client = object()
    db_manager.get_auth_db.return_value = auth_db

    app.dependency_overrides[get_auth_service] = lambda: mock_auth_service
    app.dependency_overrides[get_db_manager] = lambda: db_manager
    app.dependency_overrides[get_current_user] = lambda: dummy_user
    yield TestClient(app)
    app.dependency_overrides.clear()

def test_login_for_access_token_success(client, mock_auth_service):
    mock_auth_service.login.return_value = (dummy_user, "test-access-token", "test-refresh-token")
    
    response = client.post("/token", data={"username": "alice", "password": "password"})
    assert response.status_code == 200
    data = response.json()
    assert data["access_token"] == "test-access-token"
    assert data["user"]["username"] == "alice"
    assert data["client_api_key"] == "client-api-key"
    # Verify refresh_token is in HttpOnly cookie
    assert "refresh_token" not in data  # HttpOnly cookie, not in body

def test_login_for_access_token_failed(client, mock_auth_service):
    mock_auth_service.login.return_value = None
    
    response = client.post("/token", data={"username": "alice", "password": "wrongpassword"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"


def test_login_for_access_token_missing_client_id(client, mock_auth_service):
    user_without_client = UserInDB(
        user_id="u-2",
        username="bob",
        email="bob@example.com",
        role="analyst",
        is_active=True,
        client_id=None,
        hashed_password="hashed_pwd",
    )
    mock_auth_service.login.return_value = (user_without_client, "test-access-token", "test-refresh-token")

    response = client.post("/token", data={"username": "bob", "password": "password"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication error"


def test_login_for_access_token_invalid_client_id(client, mock_auth_service):
    user_invalid_client = UserInDB(
        user_id="u-3",
        username="eve",
        email="eve@example.com",
        role="analyst",
        is_active=True,
        client_id="non-existent-client",
        hashed_password="hashed_pwd",
    )
    mock_auth_service.login.return_value = (user_invalid_client, "test-access-token", "test-refresh-token")

    app = client.app
    db_manager = app.dependency_overrides[get_db_manager]()
    db_manager.get_auth_db.return_value.authorized_telemetry_clients.find_one.return_value = None

    response = client.post("/token", data={"username": "eve", "password": "password"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication error"

def test_get_current_user_info(client):
    response = client.get("/me")
    assert response.status_code == 200
    assert response.json()["username"] == "alice"
    assert response.json()["client_id"] == "client-1"

def test_logout_success(client, mock_auth_service):
    mock_auth_service.logout.return_value = None
    mock_auth_service.revoke_refresh_token.return_value = None
    response = client.post("/logout", headers={"Authorization": "Bearer test-access-token"})
    assert response.status_code == 200
    assert response.json() == {"message": "Logged out successfully"}
    mock_auth_service.logout.assert_called_once_with("test-access-token")
    assert "refresh_token=" in response.headers.get("set-cookie", "")

def test_logout_without_authorization_header(client, mock_auth_service):
    mock_auth_service.revoke_refresh_token.return_value = None
    response = client.post("/logout")
    assert response.status_code == 200
    assert response.json() == {"message": "Logged out successfully"}
    mock_auth_service.logout.assert_not_called()


def test_logout_revokes_refresh_cookie(client, mock_auth_service):
    refresh_token = create_refresh_token("u-1")
    mock_auth_service.revoke_refresh_token.return_value = None
    response = client.post("/logout", cookies={"refresh_token": refresh_token})
    assert response.status_code == 200
    mock_auth_service.revoke_refresh_token.assert_called_once_with(refresh_token)
    assert "refresh_token=" in response.headers.get("set-cookie", "")


def test_logout_invalid_header_does_not_fail(client, mock_auth_service):
    mock_auth_service.revoke_refresh_token.return_value = None
    response = client.post("/logout", headers={"Authorization": "InvalidHeader"})
    assert response.status_code == 200
    mock_auth_service.logout.assert_not_called()


def test_refresh_access_token_success(client, mock_auth_service):
    refresh_token = create_refresh_token("u-1")
    mock_auth_service.refresh_access_token.return_value = ("new-access-token", "new-jti")

    response = client.post("/refresh", cookies={"refresh_token": refresh_token})
    assert response.status_code == 200
    data = response.json()
    assert data["access_token"] == "new-access-token"
    assert data["client_api_key"] == "client-api-key"
    assert data["user"]["client_id"] == "client-1"
    assert "refresh_token" not in data


def test_refresh_access_token_missing_token(client):
    response = client.post("/refresh")
    assert response.status_code == 401
    assert response.json()["detail"] == "No refresh token provided"

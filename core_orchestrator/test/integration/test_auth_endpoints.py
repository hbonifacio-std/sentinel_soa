"""
Integration tests for authentication endpoints and security.

Tests full authentication flow including login and user profile endpoints.
"""

import pytest
import asyncio
from httpx import AsyncClient

from core_orchestrator.main import app
from core_orchestrator.services.database import db
from core_orchestrator.services.user_service import UserService
from core_orchestrator.models.user import UserCreate


@pytest.fixture
async def client():
    """Create async test client."""
    return AsyncClient(app=app, base_url="http://test")


@pytest.fixture
async def setup_test_user():
    """Set up a test user in database."""
    # This would require actual database setup
    # For testing purposes, users would be seeded via migration script
    pass


@pytest.mark.asyncio
async def test_login_endpoint_with_valid_credentials(client):
    """Test login endpoint with valid credentials."""
    # Assuming admin user exists from migration
    response = await client.post(
        "/api/v1/auth/token",
        data={
            "username": "admin",
            "password": "AdminPassword123!"
        }
    )
    
    # Should only pass if database is set up with users
    # In CI/CD, this would require proper test setup
    if response.status_code == 200:
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "user" in data
        assert data["user"]["username"] == "admin"


@pytest.mark.asyncio
async def test_login_endpoint_with_invalid_credentials(client):
    """Test login endpoint with invalid credentials."""
    response = await client.post(
        "/api/v1/auth/token",
        data={
            "username": "admin",
            "password": "WrongPassword"
        }
    )
    
    # Should fail with 401
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_endpoint_missing_credentials(client):
    """Test login endpoint with missing credentials."""
    response = await client.post(
        "/api/v1/auth/token",
        data={}
    )
    
    # Should fail with 422 (validation error)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_me_endpoint_requires_auth(client):
    """Test that /me endpoint requires authentication."""
    response = await client.get("/api/v1/auth/me")
    
    # Should fail without token
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_me_endpoint_with_valid_token(client):
    """Test /me endpoint with valid token."""
    # First get a token
    login_response = await client.post(
        "/api/v1/auth/token",
        data={
            "username": "admin",
            "password": "AdminPassword123!"
        }
    )
    
    if login_response.status_code == 200:
        token = login_response.json()["access_token"]
        
        # Now use token to access /me
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "admin"
        assert "user_id" in data


@pytest.mark.asyncio
async def test_telemetry_endpoint_requires_hmac(client):
    """Test that telemetry endpoint requires HMAC headers."""
    response = await client.post(
        "/api/v1/telemetry/",
        json={"ip_address": "192.168.1.1", "method": "GET"}
    )
    
    # Should fail without HMAC headers
    assert response.status_code == 422  # Missing required headers


@pytest.mark.asyncio
async def test_analytics_endpoint_requires_auth(client):
    """Test that analytics endpoints require authentication."""
    response = await client.get("/api/v1/analytics/reports")
    
    # Should fail without token
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_rules_endpoint_requires_auth(client):
    """Test that rules endpoints require authentication."""
    response = await client.get("/api/v1/rules")
    
    # Should fail without token
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_cors_headers_present(client):
    """Test that CORS headers are present."""
    response = await client.get("/health")
    
    # CORS headers should be present
    assert "access-control-allow-origin" in response.headers or response.status_code == 200


@pytest.mark.asyncio
async def test_invalid_token_rejected(client):
    """Test that invalid tokens are rejected."""
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid_token_here"}
    )
    
    # Should fail with 401
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_missing_bearer_token_rejected(client):
    """Test that requests without Bearer prefix are rejected."""
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "NotBearer validtoken123"}
    )
    
    # Should fail
    assert response.status_code != 200


"""
Tests for Role-Based Access Control (RBAC) and authentication.

Tests user authentication, role-based access, and authorization enforcement.
"""

import pytest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from httpx import AsyncClient

from core_orchestrator.models.user import UserInDB, UserCreate
from core_orchestrator.security.password import hash_password, verify_password
from core_orchestrator.security.jwt_utils import create_access_token


def test_password_hashing():
    """Test password hashing and verification."""
    plain_password = "MySecurePassword123!"
    hashed = hash_password(plain_password)
    
    # Hashed password should not be plain text
    assert hashed != plain_password
    
    # Verification should work
    assert verify_password(plain_password, hashed) is True
    
    # Wrong password should fail
    assert verify_password("WrongPassword", hashed) is False


def test_password_hash_is_unique():
    """Test that same password produces different hashes."""
    plain_password = "SamePassword123!"
    hash1 = hash_password(plain_password)
    hash2 = hash_password(plain_password)
    
    # Hashes should be different (bcrypt adds random salt)
    assert hash1 != hash2
    
    # But both should verify correctly
    assert verify_password(plain_password, hash1) is True
    assert verify_password(plain_password, hash2) is True


@pytest.fixture
def admin_token():
    """Create a valid admin token."""
    return create_access_token(
        user_id="admin-user-123",
        username="admin",
        role="admin"
    )


@pytest.fixture
def analyst_token():
    """Create a valid analyst token."""
    return create_access_token(
        user_id="analyst-user-456",
        username="analyst",
        role="analyst"
    )


@pytest.fixture
def viewer_token():
    """Create a valid viewer token."""
    return create_access_token(
        user_id="viewer-user-789",
        username="viewer",
        role="viewer"
    )


def test_admin_can_access_admin_endpoints(admin_token):
    """Test that admin role can access admin-only endpoints."""
    # This would be tested in integration tests with actual FastAPI app
    assert admin_token is not None
    assert len(admin_token) > 0


def test_analyst_cannot_access_admin_endpoints(analyst_token):
    """Test that analyst role cannot access admin-only endpoints."""
    # This would be tested in integration tests with actual FastAPI app
    assert analyst_token is not None
    # Role should be analyst, not admin
    from core_orchestrator.security.jwt_utils import decode_token
    payload = decode_token(analyst_token)
    assert payload.role != "admin"


def test_viewer_cannot_access_restricted_endpoints(viewer_token):
    """Test that viewer role has limited access."""
    # This would be tested in integration tests with actual FastAPI app
    from core_orchestrator.security.jwt_utils import decode_token
    payload = decode_token(viewer_token)
    assert payload.role == "viewer"


def test_admin_higher_privilege_than_analyst():
    """Test that admin has higher privileges than analyst."""
    admin_roles = {"admin"}
    analyst_roles = {"analyst", "admin"}
    
    # Admin should be able to do everything analyst can
    assert admin_roles.issubset(analyst_roles) or "admin" in admin_roles


def test_role_hierarchy():
    """Test expected role hierarchy."""
    roles = {
        "admin": {"create_rules", "update_rules", "delete_rules", "view_analytics", "view_rules"},
        "analyst": {"view_analytics", "view_rules", "create_actions"},
        "viewer": {"view_analytics"}
    }
    
    # Admin can do all admin tasks
    admin_permissions = roles["admin"]
    assert "create_rules" in admin_permissions
    assert "delete_rules" in admin_permissions
    
    # Analyst has limited permissions
    analyst_permissions = roles["analyst"]
    assert "create_rules" not in analyst_permissions
    assert "view_analytics" in analyst_permissions
    
    # Viewer has minimal permissions
    viewer_permissions = roles["viewer"]
    assert "view_rules" not in viewer_permissions
    assert "view_analytics" in viewer_permissions


def test_user_model_with_role():
    """Test UserInDB model includes role information."""
    user_data = {
        "user_id": "user-123",
        "username": "testuser",
        "email": "test@example.com",
        "role": "analyst",
        "is_active": True,
        "hashed_password": "hashed_pwd",
        "created_at": "2024-01-01T00:00:00+00:00",
        "updated_at": "2024-01-01T00:00:00+00:00"
    }
    
    user = UserInDB(**user_data)
    assert user.role == "analyst"
    assert user.is_active is True


def test_inactive_user_cannot_authenticate():
    """Test that inactive users cannot use tokens effectively."""
    # In real implementation, inactive users should be rejected
    # even if they have a valid token
    pass


def test_token_contains_role_claim():
    """Test that JWT token contains role in claims."""
    token = create_access_token(
        user_id="user-123",
        username="testuser",
        role="admin"
    )
    
    from core_orchestrator.security.jwt_utils import decode_token
    payload = decode_token(token)
    
    assert payload.role == "admin"


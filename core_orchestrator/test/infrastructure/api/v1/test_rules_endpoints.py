import pytest
from unittest.mock import AsyncMock, Mock
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.testclient import TestClient
from core_orchestrator.infrastructure.api.v1.endpoints.rules import router
from core_orchestrator.infrastructure.api.dependencies import (
    get_rule_service,
    get_rule_validator,
    get_rules_engine_service,
)
from core_orchestrator.infrastructure.api.dependencies.user_auth import get_admin_user, get_analyst_user_with_client
from core_orchestrator.domain.entities.auth.user import UserInDB
from core_orchestrator.domain.entities.rule_engine.rules import HeuristicRule, RuleVersion, RulesBundle

dummy_analyst = UserInDB(
    user_id="u-analyst",
    username="analyst",
    email="analyst@example.com",
    role="analyst",
    is_active=True,
    client_id="client-1",
    hashed_password="hashed_pwd"
)

dummy_admin = UserInDB(
    user_id="u-admin",
    username="admin",
    email="admin@example.com",
    role="admin",
    is_active=True,
    client_id="client-1",
    hashed_password="hashed_pwd"
)

dummy_rule = HeuristicRule(
    rule_id="rule-1",
    rule_type="keyword_mapping",
    category="uri",
    version=1,
    is_active=True,
    description="A test rule",
    content={"type": "keyword_mapping", "data": {"test": 10}},
    metadata={"source": "test", "changed_by": "admin", "change_reason": "init"},
    created_at=datetime.now(timezone.utc),
    updated_at=datetime.now(timezone.utc)
)

@pytest.fixture
def mock_rule_service():
    return AsyncMock()

@pytest.fixture
def mock_rules_engine_service():
    return AsyncMock()

@pytest.fixture
def mock_validator():
    return Mock()

@pytest.fixture
def client(mock_rule_service, mock_rules_engine_service, mock_validator):
    app = FastAPI()
    app.include_router(router, prefix="/rules")
    app.dependency_overrides[get_rule_service] = lambda: mock_rule_service
    app.dependency_overrides[get_rules_engine_service] = lambda: mock_rules_engine_service
    app.dependency_overrides[get_rule_validator] = lambda: mock_validator
    app.dependency_overrides[get_analyst_user_with_client] = lambda: dummy_analyst
    app.dependency_overrides[get_admin_user] = lambda: dummy_admin
    yield TestClient(app)
    app.dependency_overrides.clear()

def test_rules_health(client, mock_rules_engine_service):
    health = Mock()
    health.status = "OK"
    health.cached = True
    health.version_hash = "hash-123"
    health.last_updated = datetime.now(timezone.utc)
    health.source = "redis"
    
    stats = Mock()
    stats.total_active_rules = 5
    
    mock_rules_engine_service.health_check.return_value = health
    mock_rules_engine_service.get_rules_stats.return_value = stats
    
    response = client.get("/rules/health")
    assert response.status_code == 200
    assert response.json()["status"] == "OK"
    assert response.json()["total_active_rules"] == 5

def test_get_audit_log(client, mock_rule_service):
    mock_rule_service.get_audit_logs.return_value = [{"id": "audit-1"}]
    response = client.get("/rules/audit-log?limit=10&offset=0")
    assert response.status_code == 200
    assert response.json()["total"] == 1
    mock_rule_service.get_audit_logs.assert_called_once_with(
        client_id="client-1",
        rule_id=None,
        limit=10,
        offset=0,
    )

def test_validate_rules(client, mock_validator):
    validation = Mock()
    validation.valid = True
    validation.errors = []
    validation.warnings = ["some warning"]
    
    test_result = Mock()
    test_result.passed = True
    test_result.passed_count = 2
    test_result.total = 2
    test_result.failures = []
    
    mock_validator.validate_rule_bundle.return_value = validation
    mock_validator.test_rules_with_patterns.return_value = test_result
    
    payload = {
        "rules": [dummy_rule.model_dump(mode="json")]
    }
    response = client.post("/rules/validate", json=payload)
    assert response.status_code == 200
    assert response.json()["valid"] is True
    assert response.json()["warnings"] == ["some warning"]

def test_list_versions(client, mock_rule_service):
    version = RuleVersion(
        version_hash="vhash-1",
        rules_included=["rule-1"],
        deployed_by="admin",
        created_at=datetime.now(timezone.utc)
    )
    mock_rule_service.list_versions.return_value = [version]
    response = client.get("/rules/versions")
    assert response.status_code == 200
    assert len(response.json()) == 1
    mock_rule_service.list_versions.assert_called_once_with(client_id="client-1", limit=50)

def test_get_version(client, mock_rule_service):
    version = RuleVersion(
        version_hash="vhash-1",
        rules_included=["rule-1"],
        deployed_by="admin",
        created_at=datetime.now(timezone.utc)
    )
    mock_rule_service.get_version.return_value = version
    response = client.get("/rules/versions/vhash-1")
    assert response.status_code == 200
    assert response.json()["version_hash"] == "vhash-1"
    mock_rule_service.get_version.assert_called_with("vhash-1", "client-1")
    
    mock_rule_service.get_version.return_value = None
    response = client.get("/rules/versions/vhash-2")
    assert response.status_code == 404

def test_create_version(client, mock_rule_service):
    version = RuleVersion(
        version_hash="vhash-1",
        rules_included=["rule-1"],
        deployed_by="admin",
        created_at=datetime.now(timezone.utc)
    )
    mock_rule_service.create_new_version.return_value = version
    
    payload = {
        "rules_included": ["rule-1"],
        "changelog": "init version",
        "deployed_by": "admin"
    }
    response = client.post("/rules/versions", json=payload)
    assert response.status_code == 201
    assert response.json()["version_hash"] == "vhash-1"
    mock_rule_service.create_new_version.assert_called_once_with(
        rule_ids=["rule-1"],
        changelog="init version",
        deployed_by="admin",
        client_id="client-1",
    )
    
    # ValueError case
    mock_rule_service.create_new_version.side_effect = ValueError("invalid rules")
    response = client.post("/rules/versions", json=payload)
    assert response.status_code == 422

def test_activate_version(client, mock_rule_service):
    version = RuleVersion(
        version_hash="vhash-1",
        rules_included=["rule-1"],
        deployed_by="admin",
        created_at=datetime.now(timezone.utc)
    )
    mock_rule_service.get_version.return_value = version
    mock_rule_service.get_active_version.return_value = None
    
    bundle = RulesBundle(
        version_hash="vhash-1",
        last_updated=datetime.now(timezone.utc)
    )
    mock_rule_service.deploy_version.return_value = bundle
    
    response = client.post("/rules/versions/activate/vhash-1")
    assert response.status_code == 200
    assert response.json()["active_version"] == "vhash-1"
    mock_rule_service.get_version.assert_called_with("vhash-1", "client-1")
    mock_rule_service.get_active_version.assert_called_with("client-1")
    mock_rule_service.deploy_version.assert_called_with("vhash-1", "client-1")
    
    # ValueError case
    mock_rule_service.deploy_version.side_effect = ValueError("deploy error")
    response = client.post("/rules/versions/activate/vhash-1")
    assert response.status_code == 422
    
    # Version not found case
    mock_rule_service.get_version.return_value = None
    response = client.post("/rules/versions/activate/vhash-2")
    assert response.status_code == 404

def test_list_rules(client, mock_rule_service):
    mock_rule_service.fetch_all_rules.return_value = [dummy_rule]
    mock_rule_service.get_active_version.return_value = None
    
    response = client.get("/rules")
    assert response.status_code == 200
    assert len(response.json()["rules"]) == 1
    mock_rule_service.fetch_all_rules.assert_called_once_with(include_inactive=False, client_id="client-1")

def test_get_rule(client, mock_rule_service):
    mock_rule_service.fetch_rule_by_id.return_value = dummy_rule
    response = client.get("/rules/rule-1")
    assert response.status_code == 200
    assert response.json()["rule_id"] == "rule-1"
    mock_rule_service.fetch_rule_by_id.assert_called_with("rule-1", "client-1")
    
    # Not found case
    mock_rule_service.fetch_rule_by_id.return_value = None
    response = client.get("/rules/rule-2")
    assert response.status_code == 404

def test_create_rule(client, mock_rule_service, mock_validator):
    mock_rule_service.rule_exists.return_value = False
    
    validation = Mock()
    validation.valid = True
    mock_validator.validate_rule.return_value = validation
    
    mock_rule_service.create_rule.return_value = dummy_rule
    
    payload = dummy_rule.model_dump(mode="json")
    response = client.post("/rules", json=payload)
    assert response.status_code == 201
    assert response.json()["rule_id"] == "rule-1"
    mock_rule_service.rule_exists.assert_any_call("rule-1", "client-1")
    
    # Already exists case
    mock_rule_service.rule_exists.return_value = True
    response = client.post("/rules", json=payload)
    assert response.status_code == 409
    
    # Validation fails case
    mock_rule_service.rule_exists.return_value = False
    validation.valid = False
    validation.errors = ["invalid name"]
    response = client.post("/rules", json=payload)
    assert response.status_code == 422

def test_update_rule(client, mock_rule_service, mock_validator):
    mock_rule_service.fetch_rule_by_id.return_value = dummy_rule
    
    validation = Mock()
    validation.valid = True
    mock_validator.validate_rule.return_value = validation
    mock_rule_service.update_rule.return_value = True
    
    payload = {"name": "Updated Test Rule", "metadata": {"source": "test", "changed_by": "admin", "change_reason": "fix"}}
    # Test update with X-Forwarded-For header to hit _client_ip line 107
    response = client.patch("/rules/rule-1", json=payload, headers={"X-Forwarded-For": "1.1.1.1, 2.2.2.2"})
    assert response.status_code == 200
    mock_rule_service.fetch_rule_by_id.assert_called_with("rule-1", "client-1")
    
    # Not found case
    mock_rule_service.fetch_rule_by_id.return_value = None
    mock_rule_service.rule_exists_any.return_value = False
    response = client.patch("/rules/rule-2", json=payload)
    assert response.status_code == 404

    # Cross-tenant forbidden case
    mock_rule_service.fetch_rule_by_id.return_value = None
    mock_rule_service.rule_exists_any.return_value = True
    response = client.patch("/rules/rule-2", json=payload)
    assert response.status_code == 403
    
    # Empty updates case (line 364)
    mock_rule_service.fetch_rule_by_id.return_value = dummy_rule
    response = client.patch("/rules/rule-1", json={})
    assert response.status_code == 400
    assert "No fields to update" in response.json()["detail"]

    # Validation fails case (line 369)
    validation.valid = False
    validation.errors = ["invalid value"]
    response = client.patch("/rules/rule-1", json=payload)
    assert response.status_code == 422

    # Failed to update DB case (line 373)
    validation.valid = True
    mock_rule_service.update_rule.return_value = False
    response = client.patch("/rules/rule-1", json=payload)
    assert response.status_code == 500

def test_delete_rule(client, mock_rule_service):
    mock_rule_service.fetch_rule_by_id.return_value = dummy_rule
    mock_rule_service.delete_rule.return_value = True
    
    response = client.delete("/rules/rule-1?user=admin&reason=test")
    assert response.status_code == 200
    mock_rule_service.delete_rule.assert_called_with("rule-1", "client-1")
    
    # Not found case
    mock_rule_service.fetch_rule_by_id.return_value = None
    mock_rule_service.rule_exists_any.return_value = False
    response = client.delete("/rules/rule-2")
    assert response.status_code == 404

    # Cross-tenant forbidden case
    mock_rule_service.fetch_rule_by_id.return_value = None
    mock_rule_service.rule_exists_any.return_value = True
    response = client.delete("/rules/rule-2")
    assert response.status_code == 403

    # Already inactive case (line 408)
    inactive_rule = HeuristicRule(
        rule_id="rule-inactive",
        rule_type="keyword_mapping",
        category="uri",
        version=1,
        is_active=False,
        description="A test rule",
        content={"type": "keyword_mapping", "data": {"test": 10}},
        metadata={"source": "test", "changed_by": "admin", "change_reason": "init"},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    mock_rule_service.fetch_rule_by_id.return_value = inactive_rule
    response = client.delete("/rules/rule-inactive")
    assert response.status_code == 409
    assert "already inactive" in response.json()["detail"]

    # Failed to delete DB case (line 413)
    mock_rule_service.fetch_rule_by_id.return_value = dummy_rule
    mock_rule_service.delete_rule.return_value = False
    response = client.delete("/rules/rule-1")
    assert response.status_code == 500

def test_serialize_datetime_helper():
    from core_orchestrator.infrastructure.api.v1.endpoints.rules import _serialize_datetime
    # Test valid string ISO format (line 117)
    res = _serialize_datetime("2026-07-08T12:00:00Z")
    assert isinstance(res, datetime)
    assert res.tzinfo is not None

    # Test invalid type returns None (line 118)
    assert _serialize_datetime(123) is None

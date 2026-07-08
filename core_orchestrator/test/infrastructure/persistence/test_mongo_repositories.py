import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone
from core_orchestrator.infrastructure.persistence.base_mongo_repository import BaseRepository
from core_orchestrator.infrastructure.persistence.mongo_user_repository import MongoUserRepository
from core_orchestrator.domain.models.rule_engine.rules import HeuristicRule, RuleContent, RuleMetadata
from core_orchestrator.domain.models.auth.user import UserCreate

@pytest.fixture
def mock_db_manager():
    manager = MagicMock()
    manager.get_auth_db.return_value = MagicMock()
    return manager

def get_dummy_rule():
    return HeuristicRule(
        rule_id="rule-1",
        rule_type="keyword_mapping",
        category="uri",
        version=1,
        is_active=True,
        description="A test rule",
        content=RuleContent(type="keyword_mapping", data={"test": 10}),
        metadata=RuleMetadata(source="test", changed_by="admin", change_reason="init")
    )

@pytest.mark.asyncio
async def test_base_repository_operations():
    collection = AsyncMock()
    collection.insert_one.return_value = MagicMock(inserted_id="inserted-id-123")
    
    dummy_rule = get_dummy_rule()
    collection.find_one.return_value = dummy_rule.model_dump(mode="json")
    collection.count_documents.return_value = 1
    
    # Mocking cursor for find_paginated
    cursor = MagicMock()
    cursor.sort.return_value = cursor
    cursor.skip.return_value = cursor
    cursor.limit.return_value = cursor
    cursor.to_list = AsyncMock(return_value=[dummy_rule.model_dump(mode="json")])
    collection.find = MagicMock(return_value=cursor)
    
    repo = BaseRepository(collection, HeuristicRule)
    
    # Insert
    ins_id = await repo.insert(dummy_rule)
    assert ins_id == "inserted-id-123"
    
    # Find one
    found = await repo.find_one({"rule_id": "rule-1"})
    assert found is not None
    assert found.rule_id == "rule-1"
    
    # Exists
    assert await repo.exists({"rule_id": "rule-1"}) is True
    
    # Paginated
    paginated = await repo.find_paginated(query={"rule_id": "rule-1"}, page=1, limit=5, sort_by="rule_id")
    assert paginated["info"]["total_records"] == 1
    assert len(paginated["results"]) == 1
    
    # Update partial
    collection.update_one.return_value = MagicMock(modified_count=1)
    assert await repo.update_partial({"rule_id": "rule-1"}, {"name": "New Name"}) is True
    assert await repo.update_partial({"rule_id": "rule-1"}, {}) is False

@pytest.mark.asyncio
async def test_mongo_user_repository(mock_db_manager):
    collection = AsyncMock()
    collection.find_one = AsyncMock()
    collection.find = MagicMock()
    mock_db_manager.get_auth_db.return_value = {"users": collection}
    repo = MongoUserRepository(mock_db_manager)
    
    # Get user
    collection.find_one.return_value = {"user_id": "u-1", "username": "alice", "email": "alice@ex.com", "role": "admin", "is_active": True, "hashed_password": "p"}
    user = await repo.get("u-1")
    assert user.username == "alice"
    
    # Get by username
    user = await repo.get_by_username("alice")
    assert user.username == "alice"
    
    # Get by email
    user = await repo.get_by_email("alice@ex.com")
    assert user.username == "alice"
    
    # Get not found
    collection.find_one.return_value = None
    assert await repo.get("u-2") is None
    
    # Create user
    collection.insert_one.return_value = MagicMock()
    new_user = await repo.create(UserCreate(username="bob", email="bob@ex.com", password="password", role="viewer"))
    assert new_user.username == "bob"
    
    # List all
    cursor = MagicMock()
    cursor.to_list = AsyncMock(return_value=[{"user_id": "u-1", "username": "alice", "email": "alice@ex.com", "role": "admin", "is_active": True, "hashed_password": "p"}])
    collection.find.return_value = cursor
    users = await repo.list_all()
    assert len(users) == 1
    
    # Indexes
    await repo.ensure_indexes()
    assert collection.create_index.call_count == 2

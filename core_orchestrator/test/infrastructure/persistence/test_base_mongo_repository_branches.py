"""
Additional tests to cover missing branches of BaseRepository (base_mongo_repository.py):
- exists() returns False when count is 0
- find_paginated() when page/limit is None
- update_partial() with empty updates (returns False)
- delete_physical() returns False when no document was deleted
- delete_logical() call
- bulk_insert() with empty list
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from core_orchestrator.infrastructure.persistence.base_mongo_repository import BaseRepository

class DummyModel:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
    
    def model_dump(self, mode="json"):
        return {"data": "dummy"}

@pytest.mark.asyncio
async def test_base_repository_missing_branches():
    mock_collection = AsyncMock()
    repo = BaseRepository(mock_collection, DummyModel)

    # 1. exists() returns False
    mock_collection.count_documents.return_value = 0
    res_exists = await repo.exists({"id": "nonexistent"})
    assert res_exists is False

    # 2. update_partial() with empty updates
    res_update = await repo.update_partial({"id": 1}, {})
    assert res_update is False

    # 3. delete_physical() when no document is deleted
    mock_delete_result = MagicMock()
    mock_delete_result.deleted_count = 0
    mock_collection.delete_many.return_value = mock_delete_result
    res_delete = await repo.delete_physical({"id": 1})
    assert res_delete is False

    # 4. bulk_insert() with empty list
    res_bulk = await repo.bulk_insert([])
    assert res_bulk == 0

    # 5. delete_logical()
    mock_update_result = MagicMock()
    mock_update_result.modified_count = 1
    mock_collection.update_one.return_value = mock_update_result
    res_logical = await repo.delete_logical({"id": 1}, "admin")
    assert res_logical is True

    # 6. find_paginated() with page/limit None
    mock_cursor = MagicMock()
    mock_cursor.to_list = AsyncMock(return_value=[{"id": 1, "val": "a"}])
    # Ensure collection.find returns the mock_cursor directly rather than an AsyncMock/coroutine
    mock_collection.find = MagicMock(return_value=mock_cursor)
    mock_collection.count_documents.return_value = 1

    res_pag = await repo.find_paginated(query={}, page=None, limit=None)
    assert res_pag["info"]["total_records"] == 1
    assert len(res_pag["results"]) == 1

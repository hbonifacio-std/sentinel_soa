from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from core_orchestrator.infrastructure.config.database import DatabaseManager
from core_orchestrator.domain.models.rules import HeuristicRule, RuleVersion
from core_orchestrator.domain.ports.rule_repository import RuleRepository as RuleRepositoryPort
from core_orchestrator.infrastructure.persistence.base_mongo_repository import BaseRepository


class MongoRuleRepository(BaseRepository[HeuristicRule], RuleRepositoryPort):
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager.get_rules_db()
        super().__init__(self.db["heuristic_rules"], HeuristicRule)
        self.heuristic_rules_collection = self.collection
        self.versions_collection = self.db["rule_versions"]
        self.audit_collection = self.db["rule_audit_log"]

    async def get_by_id(self, rule_id: str) -> Optional[HeuristicRule]:
        return await self.find_one({"rule_id": rule_id})

    async def get_all(self, include_inactive: bool = False) -> List[HeuristicRule]:
        query = {} if include_inactive else {"is_active": True}
        response = await self.find_paginated(query=query, page=1, limit=100) 
        return response["results"]

    async def get_by_ids(self, rule_ids: List[str]) -> List[HeuristicRule]:
        if not rule_ids:
            return []
        query = {"rule_id": {"$in": rule_ids}}
        return await self.find_many(query)

    async def rule_exists(self, rule_id: str) -> bool:
        return await self.exists({"rule_id": rule_id})

    async def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        updates = dict(updates)
        updates["updated_at"] = datetime.now(timezone.utc)
        return await self.update_partial({"rule_id": rule_id}, updates)

    async def create_rule(self, rule: HeuristicRule) -> HeuristicRule:
        await self.insert(rule)
        return rule

    async def delete_rule(self, rule_id: str) -> bool:
        return await self.update_rule(rule_id, {"is_active": False})

    # Versioning methods
    async def create_version(self, version: RuleVersion) -> RuleVersion:
        await self.versions_collection.insert_one(version.model_dump(by_alias=True))
        return version

    async def get_version(self, version_hash: str) -> Optional[RuleVersion]:
        doc = await self.versions_collection.find_one({"version_hash": version_hash})
        return RuleVersion(**doc) if doc else None

    async def get_active_version(self) -> Optional[RuleVersion]:
        doc = await self.versions_collection.find_one({"is_active": True})
        return RuleVersion(**doc) if doc else None

    async def list_versions(self, limit: int = 50) -> List[RuleVersion]:
        cursor = self.versions_collection.find({}).sort("created_at", -1).limit(limit)
        versions = []
        async for doc in cursor:
            versions.append(RuleVersion(**doc))
        return versions

    async def activate_version(self, version_hash: str) -> bool:
        session = await self.db.client.start_session()
        try:
            async with session.start_transaction():
                await self.versions_collection.update_many(
                    {"is_active": True},
                    {"$set": {"is_active": False}},
                    session=session
                )
                result = await self.versions_collection.update_one(
                    {"version_hash": version_hash},
                    {"$set": {"is_active": True, "deployment_timestamp": datetime.now(timezone.utc)}},
                    session=session
                )
                if result.modified_count == 0:
                     raise ValueError("Version not found or already active.") # This will abort the transaction
            return True
        except Exception:
            # Transaction aborted
            return False
        finally:
            await session.end_session()

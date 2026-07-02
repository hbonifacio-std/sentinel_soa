from typing import List, Optional
from core_orchestrator.infrastructure.config.database import DatabaseManager
from core_orchestrator.domain.models.rule_engine.rules import RuleVersion
from core_orchestrator.domain.ports.shared.version_repository import VersionRepository
from core_orchestrator.infrastructure.persistence.base_mongo_repository import BaseRepository

class MongoVersionRepository(BaseRepository[RuleVersion], VersionRepository):
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager.get_rules_db()
        super().__init__(self.db["rule_versions"], RuleVersion)

    async def list_versions(self, limit: int) -> List[RuleVersion]:
        cursor = self.collection.find({}).sort("created_at", -1).limit(limit)
        return await self.cursor_to_list(cursor)

    async def get_by_hash(self, version_hash: str) -> Optional[RuleVersion]:
        return await self.find_one({"version_hash": version_hash})

    async def get_active(self) -> Optional[RuleVersion]:
        return await self.find_one({"is_active": True})

    async def create_version(self, version: RuleVersion) -> RuleVersion:
        await self.insert(version)
        return version

    async def activate_version(self, version: RuleVersion) -> bool:
        async with await self.db.client.start_session() as session:
            async with session.start_transaction():
                # Deactivate previously active version
                await self.collection.update_one(
                    {"is_active": True},
                    {"$set": {"is_active": False}},
                    session=session
                )
                # Activate the new version
                result = await self.collection.update_one(
                    {"version_hash": version.version_hash},
                    {"$set": {"is_active": True}},
                    session=session
                )
                return result.modified_count > 0

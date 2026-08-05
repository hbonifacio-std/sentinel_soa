from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import logging
from pymongo import ASCENDING, DESCENDING

from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
from core_orchestrator.domain.entities.rule_engine.rules import HeuristicRule, RuleVersion
from core_orchestrator.domain.ports.rules.rule_repository import RuleRepository as RuleRepositoryPort
from core_orchestrator.infrastructure.adapters.mongodb.base_mongo_adapter import BaseRepository

logger = logging.getLogger(__name__)


class MongoRuleRepository(BaseRepository[HeuristicRule], RuleRepositoryPort):
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager.get_rules_db()
        super().__init__(self.db["heuristic_rules"], HeuristicRule)
        self.heuristic_rules_collection = self.collection
        self.versions_collection = self.db["rule_versions"]
        self.audit_collection = self.db["rule_audit_log"]

    @staticmethod
    def _client_rule_filter(client_id: Optional[str]) -> Dict[str, Any]:
        if client_id:
            return {
                "$or": [
                    {"client_id": client_id},
                    {"tenant_id": client_id},
                ]
            }
        return {"$or": [{"client_id": None}, {"tenant_id": None}]}

    @staticmethod
    def _exact_client_scope_filter(client_id: Optional[str]) -> Dict[str, Any]:
        if client_id:
            return {"$or": [{"client_id": client_id}, {"tenant_id": client_id}]}
        return {"$or": [{"client_id": None}, {"tenant_id": None}]}

    async def get_by_id(self, rule_id: str, client_id: Optional[str]) -> Optional[HeuristicRule]:
        if client_id:
            client_rule = await self.find_one({"rule_id": rule_id, **self._exact_client_scope_filter(client_id)})
            if client_rule:
                return client_rule
        return await self.find_one({"rule_id": rule_id, **self._client_rule_filter(None)})

    async def get_all(self, include_inactive: bool = False, client_id: Optional[str] = None) -> List[HeuristicRule]:
        query: Dict[str, Any] = {} if include_inactive else {"is_active": True}
        if client_id:
            query["$or"] = [{"client_id": None}, {"tenant_id": None}, {"client_id": client_id}, {"tenant_id": client_id}]
        else:
            query.update(self._client_rule_filter(None))
        return await self.find_many(query)

    async def get_by_ids(self, rule_ids: List[str], client_id: Optional[str]) -> List[HeuristicRule]:
        if not rule_ids:
            return []
        query: Dict[str, Any] = {"rule_id": {"$in": rule_ids}}
        if client_id:
            query["$or"] = [{"client_id": None}, {"tenant_id": None}, {"client_id": client_id}, {"tenant_id": client_id}]
        else:
            query.update(self._client_rule_filter(None))
        rules = await self.find_many(query)

        if not client_id:
            return rules

        # Prefer client-specific rules when same rule_id exists in global and client scopes.
        by_rule_id: Dict[str, HeuristicRule] = {}
        for rule in rules:
            existing = by_rule_id.get(rule.rule_id)
            if not existing:
                by_rule_id[rule.rule_id] = rule
                continue
            if existing.client_id is None and rule.client_id == client_id:
                by_rule_id[rule.rule_id] = rule
        return [by_rule_id[rid] for rid in rule_ids if rid in by_rule_id]

    async def get_rules_by_client(self, client_id: Optional[str], include_inactive: bool = False) -> List[HeuristicRule]:
        """Get rules for a specific client or global rules (if client_id is None)."""
        if client_id:
            query: Dict[str, Any] = {"$or": [{"client_id": client_id}, {"tenant_id": client_id}, {"client_id": None}, {"tenant_id": None}]}
        else:
            query = self._client_rule_filter(None)
        if not include_inactive:
            query["is_active"] = True
        rules = await self.find_many(query)

        if not client_id:
            return rules

        # Prefer client-specific rules over global ones when both share rule_id.
        merged_by_id: Dict[str, HeuristicRule] = {}
        for rule in rules:
            existing = merged_by_id.get(rule.rule_id)
            if not existing:
                merged_by_id[rule.rule_id] = rule
                continue
            if existing.client_id is None and rule.client_id == client_id:
                merged_by_id[rule.rule_id] = rule
        return list(merged_by_id.values())

    async def rule_exists(self, rule_id: str, client_id: Optional[str]) -> bool:
        return await self.exists({"rule_id": rule_id, **self._exact_client_scope_filter(client_id)})

    async def rule_exists_any(self, rule_id: str) -> bool:
        return await self.exists({"rule_id": rule_id})

    async def update_rule(self, rule_id: str, client_id: Optional[str], updates: Dict[str, Any]) -> bool:
        updates = dict(updates)
        updates["updated_at"] = datetime.now(timezone.utc)
        return await self.update_partial({"rule_id": rule_id, **self._exact_client_scope_filter(client_id)}, updates)

    async def create_rule(self, rule: HeuristicRule) -> HeuristicRule:
        await self.insert(rule)
        return rule

    async def delete_rule(self, rule_id: str, client_id: Optional[str]) -> bool:
        return await self.update_rule(rule_id, client_id, {"is_active": False})

    # Versioning methods
    async def create_version(self, version: RuleVersion) -> RuleVersion:
        # mode="json" serializes nested objects, by_alias=True handles field mapping
        doc = version.model_dump(mode="json", by_alias=True)
        logger.debug(f"Inserting rule version: {version.version_hash}")
        try:
            await self.versions_collection.insert_one(doc)
            logger.info(f"Rule version {version.version_hash} inserted successfully")
        except Exception as e:
            logger.error(f"Failed to insert rule version {version.version_hash}: {e}", exc_info=True)
            raise
        return version

    async def get_version(self, version_hash: str, client_id: Optional[str]) -> Optional[RuleVersion]:
        doc = await self.versions_collection.find_one({"version_hash": version_hash, "client_id": client_id})
        return RuleVersion(**doc) if doc else None

    async def get_active_version(self, client_id: Optional[str]) -> Optional[RuleVersion]:
        doc = await self.versions_collection.find_one({"is_active": True, "client_id": client_id})
        return RuleVersion(**doc) if doc else None

    async def list_versions(self, client_id: Optional[str], limit: int = 50) -> List[RuleVersion]:
        cursor = self.versions_collection.find({"client_id": client_id}).sort("created_at", -1).limit(limit)
        versions = []
        async for doc in cursor:
            versions.append(RuleVersion(**doc))
        return versions

    async def activate_version(self, version_hash: str, client_id: Optional[str]) -> bool:
        session = await self.db.client.start_session()
        try:
            async with session.start_transaction():
                await self.versions_collection.update_many(
                    {"is_active": True, "client_id": client_id},
                    {"$set": {"is_active": False}},
                    session=session
                )
                result = await self.versions_collection.update_one(
                    {"version_hash": version_hash, "client_id": client_id},
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

    async def ensure_indexes(self) -> None:
        await self.heuristic_rules_collection.create_index(
            [("client_id", ASCENDING), ("rule_id", ASCENDING)],
            name="heuristic_rules_client_rule_idx",
        )
        await self.heuristic_rules_collection.create_index(
            [("tenant_id", ASCENDING), ("rule_id", ASCENDING)],
            name="heuristic_rules_tenant_rule_idx",
        )
        await self.heuristic_rules_collection.create_index(
            [("client_id", ASCENDING), ("is_active", ASCENDING), ("updated_at", DESCENDING)],
            name="heuristic_rules_client_active_updated_idx",
        )
        await self.versions_collection.create_index(
            [("client_id", ASCENDING), ("created_at", DESCENDING)],
            name="rule_versions_client_created_idx",
        )
        await self.versions_collection.create_index(
            [("client_id", ASCENDING), ("is_active", ASCENDING)],
            name="rule_versions_client_active_idx",
        )

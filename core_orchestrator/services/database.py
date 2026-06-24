import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pymongo.asynchronous.mongo_client import AsyncMongoClient
from redis.asyncio import Redis

from core_orchestrator.models.rule_schema import HeuristicRule, RuleAuditLog, RuleVersion, RulesBundle

logger = logging.getLogger(__name__)

RULES_CACHE_KEY = "rules:active:all"
RULES_VERSION_KEY = "rules:metadata:version_hash"
RULES_UPDATED_KEY = "rules:metadata:last_updated"
DEFAULT_RULES_TTL = int(os.getenv("RULES_CACHE_TTL_SECONDS", "86400"))


class Database:
    def __init__(self):
        self.mongo_client: Optional[AsyncMongoClient] = None
        self.redis_client: Optional[Redis] = None
        self.redis_rules_client: Optional[Redis] = None
        self._app_mongo_db_name: str = "sentinel_soa"
        self._rules_mongo_db_name: str = "heuristy"

    async def connect_to_mongo(self):
        mongo_host = os.getenv("MONGO_HOST") or "mongo"
        mongo_port = os.getenv("MONGO_PORT") or "27017"
        self._app_mongo_db_name = os.getenv("MONGO_DB_NAME") or "sentinel_soa"
        self._rules_mongo_db_name = os.getenv("RULES_MONGO_DB_NAME") or "heuristy"
        mongo_user = os.getenv("MONGO_USER") or ""
        mongo_password = os.getenv("MONGO_PASSWORD") or ""
        mongo_auth_db = os.getenv("MONGO_AUTH_DB") or "admin"

        if mongo_user and mongo_password:
            mongodb_uri = (
                f"mongodb://{mongo_user}:{mongo_password}@{mongo_host}:{mongo_port}"
                f"/{self._app_mongo_db_name}?authSource={mongo_auth_db}"
            )
        else:
            mongodb_uri = f"mongodb://{mongo_host}:{mongo_port}/{self._app_mongo_db_name}"

        self.mongo_client = AsyncMongoClient(mongodb_uri)

    async def close_mongo_connection(self):
        if self.mongo_client:
            await self.mongo_client.close()

    async def connect_to_redis(self):
        redis_host = os.getenv("REDIS_HOST") or "redis"
        redis_port = int(os.getenv("REDIS_PORT") or 6379)
        redis_password = os.getenv("REDIS_PASSWORD") or None

        self.redis_client = Redis(
            host=redis_host,
            port=redis_port,
            password=redis_password,
            db=0,
        )
        rules_db = int(os.getenv("REDIS_RULES_DB", "3"))
        self.redis_rules_client = Redis(
            host=redis_host,
            port=redis_port,
            password=redis_password,
            db=rules_db,
        )

    async def close_redis_connection(self):
        if self.redis_client:
            await self.redis_client.close()
        if self.redis_rules_client:
            await self.redis_rules_client.close()

    def get_app_db_name(self) -> str:
        return self._app_mongo_db_name

    def get_rules_db_name(self) -> str:
        return self._rules_mongo_db_name

    def get_app_db(self):
        if not self.mongo_client:
            raise RuntimeError("MongoDB client is not connected")
        return self.mongo_client[self._app_mongo_db_name]

    def get_rules_db(self):
        return self._get_rules_db()

    def _get_rules_db(self):
        if not self.mongo_client:
            raise RuntimeError("MongoDB client is not connected")
        return self.mongo_client[self._rules_mongo_db_name]

    # ------------------------------------------------------------------
    # Heuristic rules CRUD
    # ------------------------------------------------------------------

    async def create_rule(self, rule: HeuristicRule) -> str:
        doc = rule.model_dump(mode="json")
        await self._get_rules_db()["heuristic_rules"].insert_one(doc)
        return rule.rule_id

    async def get_rule(self, rule_id: str) -> Optional[HeuristicRule]:
        doc = await self._get_rules_db()["heuristic_rules"].find_one({"rule_id": rule_id})
        if not doc:
            return None
        doc.pop("_id", None)
        return HeuristicRule(**doc)

    async def list_active_rules(self) -> List[HeuristicRule]:
        cursor = self._get_rules_db()["heuristic_rules"].find({"is_active": True})
        rules: List[HeuristicRule] = []
        async for doc in cursor:
            doc.pop("_id", None)
            rules.append(HeuristicRule(**doc))
        return rules

    async def list_all_rules(self, include_inactive: bool = False) -> List[HeuristicRule]:
        query: Dict[str, Any] = {} if include_inactive else {"is_active": True}
        cursor = self._get_rules_db()["heuristic_rules"].find(query)
        rules: List[HeuristicRule] = []
        async for doc in cursor:
            doc.pop("_id", None)
            rules.append(HeuristicRule(**doc))
        return rules

    async def get_rules_by_ids(self, rule_ids: List[str]) -> List[HeuristicRule]:
        cursor = self._get_rules_db()["heuristic_rules"].find({"rule_id": {"$in": rule_ids}})
        rules: List[HeuristicRule] = []
        async for doc in cursor:
            doc.pop("_id", None)
            rules.append(HeuristicRule(**doc))
        return rules

    async def rule_exists(self, rule_id: str) -> bool:
        doc = await self._get_rules_db()["heuristic_rules"].find_one({"rule_id": rule_id}, {"_id": 1})
        return doc is not None

    async def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        updates = dict(updates)
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        result = await self._get_rules_db()["heuristic_rules"].update_one(
            {"rule_id": rule_id},
            {"$set": updates},
        )
        return result.modified_count > 0

    async def delete_rule(self, rule_id: str) -> bool:
        result = await self._get_rules_db()["heuristic_rules"].update_one(
            {"rule_id": rule_id},
            {"$set": {"is_active": False, "updated_at": datetime.now(timezone.utc).isoformat()}},
        )
        return result.modified_count > 0

    # ------------------------------------------------------------------
    # Rule versions
    # ------------------------------------------------------------------

    async def create_version(self, version: RuleVersion) -> str:
        await self._get_rules_db()["rule_versions"].insert_one(version.model_dump(mode="json"))
        return version.version_hash

    async def get_version(self, version_hash: str) -> Optional[RuleVersion]:
        doc = await self._get_rules_db()["rule_versions"].find_one({"version_hash": version_hash})
        if not doc:
            return None
        doc.pop("_id", None)
        return RuleVersion(**doc)

    async def activate_version(self, version_hash: str) -> bool:
        db = self._get_rules_db()
        await db["rule_versions"].update_many({}, {"$set": {"is_active": False}})
        result = await db["rule_versions"].update_one(
            {"version_hash": version_hash},
            {
                "$set": {
                    "is_active": True,
                    "deployment_timestamp": datetime.now(timezone.utc).isoformat(),
                }
            },
        )
        return result.modified_count > 0

    async def get_active_version(self) -> Optional[RuleVersion]:
        doc = await self._get_rules_db()["rule_versions"].find_one({"is_active": True})
        if not doc:
            return None
        doc.pop("_id", None)
        return RuleVersion(**doc)

    async def list_versions(self, limit: int = 50) -> List[RuleVersion]:
        cursor = (
            self._get_rules_db()["rule_versions"]
            .find({})
            .sort("created_at", -1)
            .limit(limit)
        )
        versions: List[RuleVersion] = []
        async for doc in cursor:
            doc.pop("_id", None)
            versions.append(RuleVersion(**doc))
        return versions

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    async def log_rule_action(
        self,
        action: str,
        rule_id: str,
        user: str,
        changes: Dict[str, Any],
        reason: str = "",
        status: str = "success",
        ip_address: str = "127.0.0.1",
    ) -> str:
        entry = RuleAuditLog(
            action=action,  # type: ignore[arg-type]
            rule_id=rule_id,
            user=user,
            changes=changes,
            reason=reason,
            status=status,
            ip_address=ip_address,
        )
        result = await self._get_rules_db()["rule_audit_log"].insert_one(entry.model_dump(mode="json"))
        return str(result.inserted_id)

    async def get_audit_logs(self, rule_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {}
        if rule_id:
            query["rule_id"] = rule_id
        cursor = (
            self._get_rules_db()["rule_audit_log"]
            .find(query)
            .sort("timestamp", -1)
            .limit(limit)
        )
        logs: List[Dict[str, Any]] = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            logs.append(doc)
        return logs

    # ------------------------------------------------------------------
    # Redis rules cache (DB3)
    # ------------------------------------------------------------------

    async def cache_rules(self, bundle: RulesBundle, ttl_seconds: int = DEFAULT_RULES_TTL) -> bool:
        if not self.redis_rules_client:
            logger.warning("Redis rules client not connected; skipping cache")
            return False
        payload = json.dumps(bundle.to_cache_dict())
        pipe = self.redis_rules_client.pipeline()
        pipe.set(RULES_CACHE_KEY, payload, ex=ttl_seconds)
        pipe.set(RULES_VERSION_KEY, bundle.version_hash, ex=ttl_seconds)
        updated = bundle.last_updated.isoformat() if bundle.last_updated else datetime.now(timezone.utc).isoformat()
        pipe.set(RULES_UPDATED_KEY, updated, ex=ttl_seconds)
        await pipe.execute()
        return True

    async def get_cached_rules(self) -> Optional[RulesBundle]:
        if not self.redis_rules_client:
            return None
        raw = await self.redis_rules_client.get(RULES_CACHE_KEY)
        if not raw:
            return None
        data = json.loads(raw)
        return RulesBundle.from_cache_dict(data)

    async def invalidate_rules_cache(self) -> bool:
        if not self.redis_rules_client:
            return False
        await self.redis_rules_client.delete(RULES_CACHE_KEY, RULES_VERSION_KEY, RULES_UPDATED_KEY)
        return True


db = Database()

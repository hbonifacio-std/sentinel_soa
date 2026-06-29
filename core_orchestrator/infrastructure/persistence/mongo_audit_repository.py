from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from core_orchestrator.infrastructure.config.database import DatabaseManager
from core_orchestrator.domain.ports.audit_repository import AuditRepository
from core_orchestrator.infrastructure.persistence.base_mongo_repository import BaseRepository

# Using a generic dictionary for the model since audit logs can be flexible
class MongoAuditRepository(BaseRepository[Dict], AuditRepository):
    def __init__(self, db_manager: DatabaseManager):
        # Assuming the same DB manager provides access to the rules DB
        self.db = db_manager.get_rules_db()
        super().__init__(self.db["rule_audit_log"], dict)

    async def get_logs(self, rule_id: Optional[str] = None, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        query = {}
        if rule_id:
            query["rule_id"] = rule_id
        
        cursor = self.collection.find(query).sort("timestamp", -1).skip(offset).limit(limit)
        return await cursor.to_list(length=limit)

    async def log_action(self, action: str, rule_id: str, user: str, changes: Dict[str, Any], reason: str, ip_address: str):
        log_entry = {
            "action": action,
            "rule_id": rule_id,
            "user": user,
            "changes": changes,
            "reason": reason,
            "ip_address": ip_address,
            "timestamp": datetime.now(timezone.utc),
        }
        await self.collection.insert_one(log_entry)

import asyncio
from typing import Optional, List, Dict, Any

from bson import ObjectId

from core_orchestrator.infrastructure.config.database import DatabaseManager
from core_orchestrator.domain.ports.analytics_repository import AnalyticsRepository
from core_orchestrator.infrastructure.persistence.base_mongo_repository import BaseRepository

class MongoAnalyticsRepository(BaseRepository[Dict[str, Any]], AnalyticsRepository):


    def __init__(self, db_manager: DatabaseManager):
        # Assuming analytics data is stored in the main telemetry DB
        self.db = db_manager.get_telemetry_db()
        super().__init__(self.db["analysis_reports"], dict)
        self.analysis_reports_collection = self.collection
        self.logs_collection = self.db["logs"]

    async def get_summary_stats(self) -> Dict[str, Any]:
        threat_levels_pipeline = [
            {"$group": {"_id": "$threat_level", "count": {"$sum": 1}}}
        ]
        kill_chain_phases_pipeline = [
            {"$unwind": "$kill_chain_phase"},
            {"$group": {"_id": "$kill_chain_phase", "count": {"$sum": 1}}}
        ]
        top_attackers_pipeline = [
            {"$group": {"_id": "$source_ip", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        mitre_tactics_pipeline = [
            {"$unwind": "$mitre_tactics"},
            {"$group": {"_id": "$mitre_tactics", "count": {"$sum": 1}}}
        ]

        threat_levels_cursor = await self.collection.aggregate(threat_levels_pipeline)
        kill_chain_phases_cursor = await self.collection.aggregate(kill_chain_phases_pipeline)
        top_attackers_cursor = await self.collection.aggregate(top_attackers_pipeline)
        mitre_tactics_cursor = await self.collection.aggregate(mitre_tactics_pipeline)

        # Ahora asyncio.gather podrá consumir los cursores de manera asíncrona perfectamente
        threat_levels, kill_chain_phases, top_attackers, mitre_tactics = await asyncio.gather(
            threat_levels_cursor.to_list(length=None),
            kill_chain_phases_cursor.to_list(length=None),
            top_attackers_cursor.to_list(length=None),
            mitre_tactics_cursor.to_list(length=None)
        )

        # The frontend expects specific field names. Let's adapt the output.
        adapted_threat_levels = [{"level": item["_id"], "count": item["count"]} for item in threat_levels if item["_id"]]
        adapted_kill_chain_phases = [{"phase": item["_id"], "count": item["count"]} for item in kill_chain_phases if item["_id"]]
        adapted_top_attackers = [{"attacker": item["_id"], "count": item["count"]} for item in top_attackers if item["_id"]]
        adapted_mitre_tactics = [{"phase": item["_id"], "count": item["count"]} for item in mitre_tactics if item["_id"]]

        return {
            "threat_levels": adapted_threat_levels,
            "kill_chain_phases": adapted_kill_chain_phases,
            "top_attackers": adapted_top_attackers,
            "mitre_tactics": adapted_mitre_tactics
        }

    async def get_paginated_reports(self, query: dict, page: int, limit: int) -> dict:
        return await self.find_paginated(query=query, page=page, limit=limit)

    async def get_report_by_id(self, report_id: str) -> Optional[dict]:
        try:
            obj_id = ObjectId(report_id)
        except Exception:
            return None
        
        doc = await self.collection.find_one({"_id": obj_id})
        if doc and "_id" in doc:
            doc["id"] = str(doc.pop("_id"))
        return doc

    async def update_report(self, report_id: str, updates: dict) -> bool:
        try:
            obj_id = ObjectId(report_id)
        except Exception:
            return False
        return await self.update_partial({"_id": obj_id}, updates)

    async def add_action_to_report(self, report_id: str, action: dict) -> bool:
        try:
            obj_id = ObjectId(report_id)
        except Exception:
            return False

        result = await self.collection.update_one(
            {"_id": obj_id},
            {"$push": {"actions": action}}
        )
        return result.modified_count > 0

    async def get_distinct_source_ids(self) -> List[str]:
        return await self.collection.distinct("source_id")

    async def get_aggregated_stats(self, pipeline: list) -> List[dict]:
        cursor = await self.collection.aggregate(pipeline)
        return await cursor.to_list(length=None)

    async def get_paginated_logs(self, query: Dict[str, Any], page: int, limit: int) -> Dict[str, Any]:
        filter_query = query or {}
        cursor = self.logs_collection.find(filter_query)

        skip = (page - 1) * limit
        cursor = cursor.skip(skip).limit(limit)

        total_records, docs = await asyncio.gather(
            self.logs_collection.count_documents(filter_query),
            cursor.to_list(length=limit)
        )

        for doc in docs:
            if "_id" in doc and isinstance(doc["_id"], ObjectId):
                doc["_id"] = str(doc["_id"])

        total_pages = (total_records + limit - 1) // limit
        next_page = str(page + 1) if page < total_pages else None
        prev_page = str(page - 1) if page > 1 else None

        return {
            "info": {
                "total_records": total_records,
                "page": page,
                "limit": limit,
                "next_page": next_page,
                "prev_page": prev_page,
            },
            "results": docs,
        }

    async def get_debug_reports(self, limit: int) -> List[Dict[str, Any]]:
        reports_cursor = self.analysis_reports_collection.find({}).limit(limit)
        reports = await reports_cursor.to_list(length=limit)

        for report in reports:
            if "_id" in report and isinstance(report["_id"], ObjectId):
                report["_id"] = str(report["_id"])
        return reports

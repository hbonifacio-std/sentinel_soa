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

    async def get_paginated_reports(self, query: dict, page: int, limit: int) -> dict:
        return await self.find_paginated(query=query, page=page, limit=limit)

    async def get_report_by_id(self, report_id: str) -> Optional[dict]:
        return await self.find_one({"report_id": report_id})

    async def update_report(self, report_id: str, updates: dict) -> bool:
        return await self.update_partial({"report_id": report_id}, updates)

    async def add_action_to_report(self, report_id: str, action: dict) -> bool:
        result = await self.collection.update_one(
            {"report_id": report_id},
            {"$push": {"actions": action}}
        )
        return result.modified_count > 0

    async def get_distinct_source_ids(self) -> List[str]:
        return await self.collection.distinct("source.id")

    async def get_aggregated_stats(self, pipeline: list) -> List[dict]:
        cursor = self.collection.aggregate(pipeline)
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

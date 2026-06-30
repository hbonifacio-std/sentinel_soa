import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from bson import ObjectId

from core_orchestrator.domain.ports.analytics_repository import AnalyticsRepository

logger = logging.getLogger(__name__)

from core_orchestrator.domain.models.analysis_report import AnalysisActionEntry
from pydantic import BaseModel, Field

class ReportResolutionPayload(BaseModel):
    reviewed: bool = True
    resolved: bool = True
    resolved_at_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    )

class AnalyticsService:
    def __init__(self, analytics_repository: AnalyticsRepository):
        self.analytics_repository = analytics_repository

    async def get_paginated_reports(self, page: int, limit: int, source_id: Optional[str] = None) -> Dict[str, Any]:
        query = {}
        if source_id:
            query["source_id"] = source_id

        paginated_data = await self.analytics_repository.get_paginated_reports(query=query, page=page, limit=limit)

        for report in paginated_data.get("results", []):
            if "_id" in report and isinstance(report["_id"], ObjectId):
                report["id"] = str(report.pop("_id"))

        return paginated_data

    async def get_report_by_id(self, report_id: str) -> Optional[Dict[str, Any]]:
        return await self.analytics_repository.get_report_by_id(report_id)

    async def mark_report_as_reviewed(self, report_id: str) -> Optional[Dict[str, Any]]:
        report = await self.get_report_by_id(report_id)
        if not report:
            return None

        await self.analytics_repository.update_report(report_id, {"reviewed": True})
        
        updated_report = await self.get_report_by_id(report_id)
        return updated_report

    async def add_action_to_report(self, report_id: str, action_request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        report = await self.get_report_by_id(report_id)
        if not report:
            return None # Report not found

        if report.get("resolved"):
            raise ValueError("Report is resolved. No more actions can be added")

        if not report.get("reviewed"):
            raise ValueError("Report must be reviewed before adding actions")
        
        comment_text = action_request.get("comment", "").strip()
        action_model = AnalysisActionEntry(comment=comment_text)
        action_doc = action_model.model_dump(mode="json", by_alias=True)


        await self.analytics_repository.add_action_to_report(report_id, action_doc)
        
        updated_report = await self.get_report_by_id(report_id)
        return updated_report

    async def mark_report_as_resolved(self, report_id: str) -> Optional[Dict[str, Any]]:
        report = await self.get_report_by_id(report_id)
        if not report:
            return None

        resolution_payload = ReportResolutionPayload()
        updates = resolution_payload.model_dump()
        
        await self.analytics_repository.update_report(report_id, updates)
        
        updated_report = await self.get_report_by_id(report_id)
        return updated_report

    async def get_distinct_source_ids(self) -> List[str]:
        source_ids = await self.analytics_repository.get_distinct_source_ids()
        logger.info(f"Source IDs from repository: {source_ids}")
        return source_ids

    async def get_aggregated_stats(self, source_id: Optional[str] = None) -> Dict[str, Any]:
        pipeline = []
        match_stage = {}
        if source_id:
            match_stage["source_id"] = source_id

        if match_stage:
            pipeline.append({"$match": match_stage})

        facet_stage = {
            "$facet": {
                "threat_levels": [{"$group": {"_id": "$threat_level", "count": {"$sum": 1}}}],
                "kill_chain_phases": [{"$group": {"_id": "$kill_chain_phase", "count": {"$sum": 1}}}],
                "top_attackers": [
                    {"$match": {"threat_actor.ip_address": {"$ne": None}}},
                    {"$group": {"_id": "$threat_actor.ip_address", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                    {"$limit": 10}
                ]
            }
        }
        pipeline.append(facet_stage)

        stats_list = await self.analytics_repository.get_aggregated_stats(pipeline)

        if stats_list and isinstance(stats_list[0], dict):
            stats = stats_list[0]
            for key in stats:
                for item in stats[key]:
                    if "_id" in item and isinstance(item["_id"], ObjectId):
                        item["_id"] = str(item["_id"])
            return stats
        
        return {}

    async def get_paginated_logs(self, page: int, limit: int, query: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return await self.analytics_repository.get_paginated_logs(query=query or {}, page=page, limit=limit)

    async def get_debug_reports(self) -> List[Dict[str, Any]]:
        return await self.analytics_repository.get_debug_reports(limit=5)

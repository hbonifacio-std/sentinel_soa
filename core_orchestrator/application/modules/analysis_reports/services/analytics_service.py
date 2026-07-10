import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from pydantic import BaseModel

from core_orchestrator.domain.models.analysis import AnalysisActionEntry
from core_orchestrator.domain.ports.analysis.analytics_repository import AnalyticsRepository

from core_orchestrator.domain.ports.telemetry.report_telemetry_service_port import ReportTelemetryServicePort

logger = logging.getLogger(__name__)
GROUP_STAGE = "$group"

class ReportResolutionPayload:
    def to_dict(self) -> Dict[str, Any]:
        return {
            "reviewed": True,
            "resolved": True,
            "resolved_at_utc": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        }

class ReportTelemetryService(ReportTelemetryServicePort):
    def __init__(self, analytics_repository: AnalyticsRepository):
        self.analytics_repository = analytics_repository

    async def get_paginated_reports(
        self,
        page: int,
        limit: int,
        client_id: str,
        source_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        query: Dict[str, Any] = {"client_id": client_id}
        if source_id:
            query["source_id"] = source_id

        return await self.analytics_repository.get_paginated_reports(query=query, page=page, limit=limit)

    async def get_report_by_id(self, report_id: str, client_id: str) -> Optional[Dict[str, Any]]:
        return await self.analytics_repository.get_report_by_id(report_id, client_id)

    async def mark_report_as_reviewed(self, report_id: str, client_id: str) -> Optional[Dict[str, Any]]:
        report = await self.get_report_by_id(report_id, client_id)
        if not report:
            return None

        await self.analytics_repository.update_report(report_id, client_id, {"reviewed": True})

        updated_report = await self.get_report_by_id(report_id, client_id)
        return updated_report

    async def add_action_to_report(
        self,
        report_id: str,
        client_id: str,
        action_request: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        report = await self.get_report_by_id(report_id, client_id)
        if not report:
            return None # Report not found

        if report.get("resolved"):
            raise ValueError("Report is resolved. No more actions can be added")

        if not report.get("reviewed"):
            raise ValueError("Report must be reviewed before adding actions")

        comment_text = action_request.get("comment", "").strip()
        action_model = AnalysisActionEntry(comment=comment_text)
        action_doc = action_model.model_dump(mode="json", by_alias=True)


        await self.analytics_repository.add_action_to_report(report_id, client_id, action_doc)

        updated_report = await self.get_report_by_id(report_id, client_id)
        return updated_report

    async def mark_report_as_resolved(self, report_id: str, client_id: str) -> Optional[Dict[str, Any]]:
        report = await self.get_report_by_id(report_id, client_id)
        if not report:
            return None

        updates = ReportResolutionPayload().to_dict()

        await self.analytics_repository.update_report(report_id, client_id, updates)

        updated_report = await self.get_report_by_id(report_id, client_id)
        return updated_report

    async def get_distinct_source_ids(self, client_id: str) -> List[str]:
        source_ids = await self.analytics_repository.get_distinct_source_ids(client_id)
        logger.info(f"Source IDs from repository: {source_ids}")
        return source_ids

    async def get_aggregated_stats(self, client_id: str, source_id: Optional[str] = None) -> Dict[str, Any]:
        pipeline = []
        match_stage: Dict[str, Any] = {"client_id": client_id}
        if source_id:
            match_stage["source_id"] = source_id

        if match_stage:
            pipeline.append({"$match": match_stage})

        facet_stage = {
            "$facet": {
                "threat_levels": [{GROUP_STAGE: {"_id": "$threat_level", "count": {"$sum": 1}}}],
                "kill_chain_phases": [{GROUP_STAGE: {"_id": "$kill_chain_phase", "count": {"$sum": 1}}}],
                "top_attackers": [
                    {"$match": {"threat_actor.ip_address": {"$ne": None}}},
                    {GROUP_STAGE: {"_id": "$threat_actor.ip_address", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                    {"$limit": 10}
                ]
            }
        }
        pipeline.append(facet_stage)

        stats_list = await self.analytics_repository.get_aggregated_stats(pipeline)
        if stats_list and isinstance(stats_list[0], dict):
            return stats_list[0]
        return {}

    async def get_paginated_logs(
        self,
        page: int,
        limit: int,
        client_id: str,
        query: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        resolved_query = {"client_id": client_id}
        if query:
            resolved_query.update({k: v for k, v in query.items() if v is not None})
        return await self.analytics_repository.get_paginated_logs(query=resolved_query, page=page, limit=limit)

    async def get_debug_reports(self, client_id: str) -> List[Dict[str, Any]]:
        return await self.analytics_repository.get_debug_reports(client_id=client_id, limit=5)

    async def create_analysis_report(self, report_data: BaseModel) -> str:
        """
        Creates a new analysis report in the database.
        """
        source_ip = getattr(report_data, "source_ip", "UNKNOWN")
        logger.info(f"Creating analysis report for {source_ip}")
        
        try:
            result = await self.analytics_repository.create_report(report_data)
            logger.info(f"Analysis report created successfully with ID: {result} for {source_ip}")
            return result
        except Exception as e:
            logger.error(f"Failed to create analysis report for {source_ip}: {e}", exc_info=True)
            raise

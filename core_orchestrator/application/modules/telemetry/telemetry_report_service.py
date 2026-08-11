import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from core_orchestrator.domain.entities.telemetry.reports import AnalysisReport
from core_orchestrator.domain.ports.telemetry.telemetry_reports_port import AnalyticsReportsPort
from core_orchestrator.infrastructure.adapters.mongodb.responses import PaginatedResult
from core_orchestrator.infrastructure.dto.telemetry.analysis_report_dto import AnalysisActionEntryDTO

logger = logging.getLogger(__name__)
GROUP_STAGE = "$group"


class CrossTenantAccessError(PermissionError):
    """Raised when a report exists but belongs to a different client scope."""


class ReportResolutionPayload:
    @staticmethod
    def to_dict() -> Dict[str, Any]:
        return {
            "reviewed": True,
            "resolved": True,
            "resolved_at_utc": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        }

class TelemetryReportService:
    def __init__(self, analytics_repository: AnalyticsReportsPort):
        self.analytics_repository = analytics_repository

    async def get_paginated_reports(
        self,
        page: int,
        limit: int,
        client_id: str,
        source_id: Optional[str] = None,
    ) -> PaginatedResult[AnalysisReport]:
        query: Dict[str, Any] = {"client_id": client_id}
        if source_id:
            query["source_id"] = source_id

        return await self.analytics_repository.get_paginated_reports(query=query, page=page, limit=limit)

    async def get_report_by_id(self, report_id: str, client_id: str) -> Optional[Dict[str, Any]]:
        return await self.analytics_repository.get_report_by_id(report_id, client_id)

    async def _get_mutable_report_in_scope(self, report_id: str, client_id: str) -> Optional[Dict[str, Any]]:
        report = await self.get_report_by_id(report_id, client_id)
        if report:
            return report
        if await self.analytics_repository.report_exists(report_id):
            raise CrossTenantAccessError("Cross-tenant report mutation is not allowed")
        return None

    async def mark_report_as_reviewed(self, report_id: str, client_id: str) -> Optional[Dict[str, Any]]:
        report = await self._get_mutable_report_in_scope(report_id, client_id)
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
        report = await self._get_mutable_report_in_scope(report_id, client_id)
        if not report:
            return None

        if report.get("resolved"):
            raise ValueError("Report is resolved. No more actions can be added")

        if not report.get("reviewed"):
            raise ValueError("Report must be reviewed before adding actions")

        comment_text = action_request.get("comment", "").strip()
        action_model = AnalysisActionEntryDTO(comment=comment_text)
        action_doc = action_model.model_dump(mode="json", by_alias=True)


        await self.analytics_repository.add_action_to_report(report_id, client_id, action_doc)

        updated_report = await self.get_report_by_id(report_id, client_id)
        return updated_report

    async def mark_report_as_resolved(self, report_id: str, client_id: str) -> Optional[Dict[str, Any]]:
        report = await self._get_mutable_report_in_scope(report_id, client_id)
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
    ) -> PaginatedResult[AnalysisReport]:
        resolved_query = {"client_id": client_id}
        if query:
            resolved_query.update({k: v for k, v in query.items() if v is not None})
        return await self.get_paginated_reports(page=page, limit=limit,client_id=client_id)

    async def get_debug_reports(self, client_id: str) -> List[Dict[str, Any]]:
        return await self.analytics_repository.get_debug_reports(client_id=client_id, limit=5)

    async def create_report(self, report_data: AnalysisReport) -> str:
        """
        Creates a new analysis report in the database.
        """
        source_ip = getattr(report_data, "source_ip", "UNKNOWN")
        logger.info(
            "Persisting analysis report for source_ip=%s window_id=%s threat_level=%s threat_detected=%s",
            source_ip,
            getattr(report_data, "window_id", None),
            getattr(report_data, "threat_level", None),
            getattr(report_data, "threat_detected", None),
        )
        
        try:
            result = await self.analytics_repository.create_report(report_data)
            logger.info(
                "Analysis report persisted successfully with report_id=%s source_ip=%s",
                result,
                source_ip,
            )
            return result
        except Exception as e:
            logger.exception(f"Failed to create analysis report for {source_ip}: {e}", exc_info=True)
            raise

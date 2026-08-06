import asyncio
import logging
import uuid
from typing import Optional, List, Dict, Any

from bson import ObjectId
from core_orchestrator.domain.entities.telemetry.reports import (
    ReportSummary,
    ThreatLevelStat,
    KillChainPhaseStat,
    TopAttackerStat,
    MitreTacticStat, AnalysisReport,
)
from core_orchestrator.infrastructure.adapters.mongodb.responses import PaginatedResult
from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
from core_orchestrator.domain.ports.telemetry.telemetry_reports_port import AnalyticsReportsPort
from core_orchestrator.infrastructure.adapters.mongodb.base_mongo_adapter import BaseRepository

logger = logging.getLogger(__name__)
GROUP_STAGE = "$group"

class MongoAnalyticsReportsAdapter(BaseRepository[AnalysisReport], AnalyticsReportsPort):


    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager.get_telemetry_db()
        super().__init__(self.db["rules_heuristics"], AnalysisReport)


    async def get_summary_stats(self) -> ReportSummary:
        threat_levels_pipeline = [
            {GROUP_STAGE: {"_id": "$threat_level", "count": {"$sum": 1}}}
        ]
        kill_chain_phases_pipeline = [
            {"$unwind": "$kill_chain_phase"},
            {GROUP_STAGE: {"_id": "$kill_chain_phase", "count": {"$sum": 1}}}
        ]
        top_attackers_pipeline = [
            {GROUP_STAGE: {"_id": "$source_ip", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        mitre_tactics_pipeline = [
            {"$unwind": "$mitre_tactics"},
            {GROUP_STAGE: {"_id": "$mitre_tactics", "count": {"$sum": 1}}}
        ]

        threat_levels_cursor = await self.collection.aggregate(threat_levels_pipeline)
        kill_chain_phases_cursor = await self.collection.aggregate(kill_chain_phases_pipeline)
        top_attackers_cursor = await self.collection.aggregate(top_attackers_pipeline)
        mitre_tactics_cursor = await self.collection.aggregate(mitre_tactics_pipeline)


        threat_levels, kill_chain_phases, top_attackers, mitre_tactics = await asyncio.gather(
            threat_levels_cursor.to_list(length=None),
            kill_chain_phases_cursor.to_list(length=None),
            top_attackers_cursor.to_list(length=None),
            mitre_tactics_cursor.to_list(length=None)
        )

        adapted_threat_levels: List[ThreatLevelStat] = [
            ThreatLevelStat(level=item["_id"], count=item["count"])
            for item in threat_levels
            if item.get("_id")
        ]
        adapted_kill_chain_phases: List[KillChainPhaseStat] = [
            KillChainPhaseStat(phase=item["_id"], count=item["count"])
            for item in kill_chain_phases
            if item.get("_id")
        ]
        adapted_top_attackers: List[TopAttackerStat] = [
            TopAttackerStat(attacker=item["_id"], count=item["count"])
            for item in top_attackers
            if item.get("_id")
        ]
        adapted_mitre_tactics: List[MitreTacticStat] = [
            MitreTacticStat(phase=item["_id"], count=item["count"])
            for item in mitre_tactics
            if item.get("_id")
        ]

        return ReportSummary(
            threat_levels= adapted_threat_levels,
            kill_chain_phases= adapted_kill_chain_phases,
            top_attackers= adapted_top_attackers,
            mitre_tactics= adapted_mitre_tactics
        )



    async def get_paginated_reports(self, query: dict, page: int, limit: int) -> PaginatedResult[AnalysisReport]:
        paginated = await self.find_paginated(query=query, page=page, limit=limit)
        return paginated

    async def get_report_by_id(self, report_id: str, client_id: str) -> AnalysisReport | None:
        query = self._build_report_query_with_client(report_id, client_id)
        if query is None:
            return None

        reports = await self.find_one(query)
        return reports

    async def report_exists(self, report_id: str) -> bool:
        report_id_query = self._build_report_id_query(report_id)
        if report_id_query is None:
            return False
        return await self.exists(report_id_query)

    async def update_report(self, report_id: str, client_id: str, updates: dict) -> bool:
        query = self._build_report_query_with_client(report_id, client_id)
        if query is None:
            return False
        return await self.update_partial(query, updates)

    async def add_action_to_report(self, report_id: str, client_id: str, action: dict) -> bool:
        query = self._build_report_query_with_client(report_id, client_id)
        if query is None:
            return False

        result = await self.collection.update_one(query, {"$push": {"actions": action}})
        return result.modified_count > 0

    async def get_distinct_source_ids(self, client_id: str) -> List[str]:
        return await self.collection.distinct("source_id", {"client_id": client_id})

    async def get_aggregated_stats(self, pipeline: list) -> List[dict]:
        cursor = await self.collection.aggregate(pipeline)
        raw_stats = await cursor.to_list(length=None)
        return self._normalize_aggregation_stats([dict(group) for group in raw_stats])

    async def get_debug_reports(self, client_id: str, limit: int) -> List[Dict[str, Any]]:
        reports_cursor = self.collection.find({"client_id": client_id}).limit(limit)
        reports = [dict(report) for report in await reports_cursor.to_list(length=limit)]

        for report in reports:
            if "_id" in report and isinstance(report["_id"], ObjectId):
                report["_id"] = str(report["_id"])
        return reports

    async def create_report(self, report: AnalysisReport) -> str:
        """Saves an analysis report to MongoDB with proper serialization and logging."""

        logger.debug(f"Attempting to insert analysis report: {report}")
        result = await self.insert(report)
        logger.info(f"Analysis report successfully inserted with ID: {result}")
        return result


    @staticmethod
    def _normalize_document_id(document: Dict[str, Any]) -> Dict[str, Any]:
        doc_copy = dict(document)
        if "_id" in doc_copy:
            doc_copy["id"] = str(doc_copy.pop("_id"))
        return doc_copy

    def _normalize_aggregation_stats(self, stats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized_stats = [dict(group) for group in stats]
        for stat_group in normalized_stats:
            self._normalize_nested_ids(stat_group)
        return normalized_stats

    def _normalize_nested_ids(self, node: Dict[str, Any]) -> None:
        for value in node.values():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._normalize_document_id(item)

    def _build_report_query_with_client(self, report_id: str, client_id: str) -> Optional[Dict[str, Any]]:
        report_id_query = self._build_report_id_query(report_id)
        if report_id_query is None:
            return None
        return {"$and": [report_id_query, {"client_id": client_id}]}

    @staticmethod
    def _build_report_id_query(report_id: str) -> Optional[Dict[str, Any]]:
        try:
            return {"_id": ObjectId(report_id)}
        except Exception:
            try:
                uuid.UUID(str(report_id))
            except Exception:
                return None
            return {"_id": report_id}

"""MongoDB adapter for forensic analysis persistence and telemetry querying."""
import logging
from typing import Any, Optional

from bson import ObjectId

from core_orchestrator.domain.entities.telemetry.reports import ForensicAnalysisRecord
from core_orchestrator.infrastructure.adapters.mongodb.base_mongo_adapter import BaseRepository
from core_orchestrator.infrastructure.dto.telemetry.forensic_analysis_dto import (
    ForensicAnalyzeRequestDTO,
    ForensicAnalysisRecordDTO,
    ForensicHistoryQueryDTO,
)
from core_orchestrator.domain.ports.forensic import ForensicAnalysisRepositoryPort
from core_orchestrator.infrastructure.database.database_manager import DatabaseManager

logger = logging.getLogger(__name__)
class MongoForensicAnalysisRepositoryAdapter(BaseRepository[ForensicAnalysisRecord],ForensicAnalysisRepositoryPort):
    """Concrete forensic repository backed by MongoDB collections."""
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager.get_telemetry_db()
        super().__init__(self.db["forensic_analysis"], dict)

    async def query_telemetry(
        self,
        request: ForensicAnalyzeRequestDTO,
        query_filter: Optional[dict[str, Any]] = None,
    ) -> tuple[list[dict[str, Any]], int]:
        resolved_filter = self._resolve_query_filter(request, query_filter)

        total_matches = await self.collection.count_documents(resolved_filter)
        skip = (request.page - 1) * request.limit
        cursor = self.collection.find(resolved_filter).sort("timestamp", -1).skip(skip).limit(request.limit)
        docs = await cursor.to_list(length=request.limit)

        normalized_docs: list[dict[str, Any]] = []
        for doc in docs:
            normalized = dict(doc)
            if "_id" in normalized and isinstance(normalized["_id"], ObjectId):
                normalized["id"] = str(normalized.pop("_id"))
            normalized_docs.append(normalized)

        return normalized_docs, total_matches

    def _resolve_query_filter(
        self,
        request: ForensicAnalyzeRequestDTO,
        query_filter: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        base_filter = self._default_regex_filter(request.query)
        resolved = dict(query_filter) if isinstance(query_filter, dict) and query_filter else base_filter
        if request.client_id:
            resolved = {"$and": [resolved, {"client_id": request.client_id}]}

        if request.source_id:
            resolved = {"$and": [resolved, {"source_id": request.source_id}]}

        return resolved

    @staticmethod
    def _default_regex_filter(query: str) -> dict[str, Any]:
        regex_operator = "$regex"
        options_operator = "$options"
        return {
            "$or": [
                {"request_uri": {regex_operator: query, options_operator: "i"}},
                {"user_agent": {regex_operator: query, options_operator: "i"}},
                {"source_ip": {regex_operator: query, options_operator: "i"}},
                {"http.path": {regex_operator: query, options_operator: "i"}},
                {"http.query": {regex_operator: query, options_operator: "i"}},
            ]
        }

    async def save_analysis(self, record: ForensicAnalysisRecordDTO) -> str:
        payload = record.model_dump(mode="json", exclude={"analysis_id"})
        result = await self.insert(payload)
        analysis_id = result

        return analysis_id

    async def get_analysis_by_id(self, analysis_id: str, client_id: str) -> Optional[ForensicAnalysisRecordDTO]:
        document = await self._find_analysis_document(analysis_id, client_id)
        return ForensicAnalysisRecordDTO(**document) if document else None

    async def get_history(self, query: ForensicHistoryQueryDTO) -> dict[str, Any]:
        filter_query: dict[str, Any] = {}
        if query.client_id:
            filter_query["client_id"] = query.client_id
        if query.source_id:
            filter_query["source_id"] = query.source_id

        total_records = await self.collection.count_documents(filter_query)
        skip = (query.page - 1) * query.limit
        cursor = self.collection.find(filter_query).sort("created_at_utc", -1).skip(skip).limit(query.limit)
        docs = await cursor.to_list(length=query.limit)

        results: list[ForensicAnalysisRecordDTO] = []
        for doc in docs:
            normalized = dict(doc)
            if "_id" in normalized and isinstance(normalized["_id"], ObjectId):
                normalized.setdefault("analysis_id", str(normalized["_id"]))
                normalized.pop("_id", None)
            results.append(ForensicAnalysisRecordDTO(**normalized))

        return {
            "info": {
                "total_records": total_records,
                "page": query.page,
                "limit": query.limit,
                "next_page": str(query.page + 1) if (skip + query.limit) < total_records else None,
                "prev_page": str(query.page - 1) if query.page > 1 else None,
            },
            "results": results,
        }

    async def _find_analysis_document(self, analysis_id: str, client_id: str) -> Optional[dict[str, Any]]:
        client_filter = {"client_id": client_id}
        document = await self.collection.find_one({"analysis_id": analysis_id, **client_filter})
        if not document:
            try:
                object_id = ObjectId(analysis_id)
            except Exception as e:
                logger.exception(f"Invalid analysis_id format: {analysis_id}. Error: {e}")
                return None
            document = await self.collection.find_one({"_id": object_id, **client_filter})

        if not document:
            return None

        normalized = dict(document)
        if "_id" in normalized and isinstance(normalized["_id"], ObjectId):
            normalized.setdefault("analysis_id", str(normalized["_id"]))
            normalized.pop("_id", None)
        return normalized


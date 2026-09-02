"""MongoDB adapter for forensic analysis persistence and telemetry querying."""
import logging
from typing import Any, Optional, List

from bson import ObjectId

from core_orchestrator.domain.entities.telemetry.forensic import ForensicChatSession
from core_orchestrator.infrastructure.adapters.mongodb.base_mongo_adapter import BaseRepository
from core_orchestrator.infrastructure.adapters.mongodb.responses import PaginatedResult
from core_orchestrator.infrastructure.dto.telemetry.forensic_analysis_dto import (
    ChatForensicQuestionDTO,
    ForensicHistoryQueryDTO,
)
from core_orchestrator.domain.ports.forensic import ForensicAnalysisRepositoryPort
from core_orchestrator.infrastructure.database.database_manager import DatabaseManager

logger = logging.getLogger(__name__)
class MongoForensicAnalysisRepositoryAdapter(BaseRepository[ForensicChatSession],ForensicAnalysisRepositoryPort):
    """Concrete forensic repository backed by MongoDB collections."""
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager.get_telemetry_db()
        super().__init__(self.db["chat_forensic_analysis"], ForensicChatSession)

    async def query_telemetry(
        self,
        request: ChatForensicQuestionDTO,
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
        request: ChatForensicQuestionDTO,
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

    async def save_analysis(self, record: ForensicChatSession) -> Optional[ForensicChatSession]:
        if record.session_id:
            query = {"_id": ObjectId(record.session_id), "client_id": record.client_id}
            result = await self.update_partial(query=query,model_instance=record)
        else:
            result = await self.insert(record)
        return result

    async def get_by_id(self, session_id: str, client_id: str) -> Optional[ForensicChatSession]:
        query = {"_id": ObjectId(session_id), "client_id": client_id}
        return await self.find_one(query=query)

    async def get_history(self, query: ForensicHistoryQueryDTO) -> PaginatedResult[ForensicChatSession]:
        query_search = {"client_id": query.client_id} if query.client_id else {}
        paginated = await self.find_paginated(query=query_search, page=query.page, limit=query.limit)
        return paginated

    async def _find_analysis_document(self, session_id: str, client_id: str) -> Optional[dict[str, Any]]:
        client_filter = {"client_id": client_id}
        document = await self.collection.find_one({"session_id": session_id, **client_filter})
        if not document:
            try:
                object_id = ObjectId(session_id)
            except Exception as e:
                logger.exception(f"Invalid session_id format: {session_id}. Error: {e}")
                return None
            document = await self.collection.find_one({"_id": object_id, **client_filter})

        if not document:
            return None

        normalized = dict(document)
        if "_id" in normalized and isinstance(normalized["_id"], ObjectId):
            normalized.setdefault("session_id", str(normalized["_id"]))
            normalized.pop("_id", None)
        return normalized


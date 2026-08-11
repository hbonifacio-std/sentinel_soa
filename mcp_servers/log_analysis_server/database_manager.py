"""MongoDB manager for MCP read-only telemetry tools."""

from __future__ import annotations

import logging
from typing import Optional

from pymongo import AsyncMongoClient
from pymongo.asynchronous.collection import AsyncCollection
from pymongo.asynchronous.database import AsyncDatabase

from mcp_servers.log_analysis_server.config import server_settings

logger = logging.getLogger(__name__)


class MongoDatabaseManager:
    """Handles MongoDB connection lifecycle and enforces allowed MCP collections."""

    _ALLOWED_COLLECTIONS = {"raw_telemetry", "reports"}

    def __init__(self) -> None:
        self._settings = server_settings
        self._client: Optional[AsyncMongoClient] = None
        self._db: Optional[AsyncDatabase] = None

    async def connect(self) -> None:
        """Create and validate a Mongo connection."""
        if self._client is not None and self._db is not None:
            return

        mongo_uri = self._settings.build_mongo_uri()
        self._client = AsyncMongoClient(
            mongo_uri,
            serverSelectionTimeoutMS=self._settings.mongo_server_selection_timeout_ms,
            connectTimeoutMS=self._settings.mongo_connect_timeout_ms,
            socketTimeoutMS=self._settings.mongo_socket_timeout_ms,
        )
        await self._client.admin.command("ping")
        self._db = self._client[self._settings.mongo_db_name]
        logger.info("MCP Mongo connection established for database %s", self._settings.mongo_db_name)

    async def disconnect(self) -> None:
        """Close Mongo connection if present."""
        if self._client is None:
            return
        self._client.close()
        self._client = None
        self._db = None
        logger.info("MCP Mongo connection closed")

    def get_collection(self, collection_name: str) -> AsyncCollection:
        """Return an allowed collection from sentinel_soa database."""
        if collection_name not in self._ALLOWED_COLLECTIONS:
            raise ValueError(
                f"Collection '{collection_name}' is not authorized. "
                f"Allowed collections: {sorted(self._ALLOWED_COLLECTIONS)}"
            )
        if self._db is None:
            raise RuntimeError("MongoDB client is not connected")
        return self._db[collection_name]

"""Neo4j manager for MCP graph-based forensic tools."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from neo4j import AsyncDriver, AsyncGraphDatabase
from neo4j.exceptions import ServiceUnavailable

from mcp_servers.log_analysis_server.config import server_settings

logger = logging.getLogger(__name__)
_NEO4J_MAX_CONNECT_ATTEMPTS = 12
_NEO4J_RETRY_DELAY_SECONDS = 2


class Neo4jDatabaseManager:
    """Manages Neo4j connection lifecycle for read-only MCP graph queries."""

    def __init__(self) -> None:
        self._settings = server_settings
        self._driver: Optional[AsyncDriver] = None

    async def connect(self) -> None:
        if self._driver is not None:
            return
        auth = self._settings.build_neo4j_auth()
        last_error: Optional[Exception] = None
        for attempt in range(1, _NEO4J_MAX_CONNECT_ATTEMPTS + 1):
            self._driver = AsyncGraphDatabase.driver(
                self._settings.neo4j_uri,
                auth=auth,
                connection_timeout=self._settings.neo4j_connection_timeout_s,
            )
            try:
                async with self._driver.session(database=self._settings.neo4j_database) as session:
                    await session.run("RETURN 1")
                logger.info("MCP Neo4j connection established for database %s", self._settings.neo4j_database)
                return
            except ServiceUnavailable as exc:
                last_error = exc
                await self._driver.close()
                self._driver = None
                logger.warning(
                    "Neo4j is not ready yet (%s/%s). Retrying in %ss.",
                    attempt,
                    _NEO4J_MAX_CONNECT_ATTEMPTS,
                    _NEO4J_RETRY_DELAY_SECONDS,
                )
                await asyncio.sleep(_NEO4J_RETRY_DELAY_SECONDS)
        raise RuntimeError("Neo4j connection failed after retry budget") from last_error

    async def disconnect(self) -> None:
        if self._driver is None:
            return
        await self._driver.close()
        self._driver = None
        logger.info("MCP Neo4j connection closed")

    def get_driver(self) -> AsyncDriver:
        if self._driver is None:
            raise RuntimeError("Neo4j driver is not connected")
        return self._driver

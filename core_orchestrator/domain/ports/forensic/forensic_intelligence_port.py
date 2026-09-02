"""Domain port for forensic MCP intelligence operations."""

from abc import ABC, abstractmethod
from typing import Any, Optional


class ForensicIntelligencePort(ABC):
    """Contract to generate forensic query plans and intelligence reports via external analyzers."""

    @abstractmethod
    async def generate_mongo_query_from_nl(
        self,
        query: str,
        source_id: Optional[str],
        provider_override: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Translate a natural-language forensic query into a safe Mongo-compatible filter plan."""
        raise NotImplementedError

    @abstractmethod
    async def generate_forensic_report_from_logs(
        self,
        query: str,
        source_id: Optional[str],
        total_matches: int,
        rows: list[dict[str, Any]],
        provider_override: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Generate structured forensic insights (markdown and highlights) from telemetry rows."""
        raise NotImplementedError


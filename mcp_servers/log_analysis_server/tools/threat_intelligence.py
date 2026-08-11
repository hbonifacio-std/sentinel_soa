"""MCP tool executors for Mongo-backed telemetry and threat intelligence."""

from __future__ import annotations

from typing import Any

from mcp_servers.log_analysis_server.config import server_settings
from mcp_servers.log_analysis_server.database_manager import MongoDatabaseManager
from mcp_servers.log_analysis_server.models.threat_tools import (
    PotentialThreatAnalysisInput,
    RawTelemetryQueryInput,
    SourceTimelineInput,
    ThreatReportQueryInput,
)
from mcp_servers.log_analysis_server.services.threat_queries import ThreatQueriesService

mongo_db_manager = MongoDatabaseManager()
threat_queries_service = ThreatQueriesService(mongo_db_manager)


def execute_get_mongo_access_scope() -> dict[str, Any]:
    """Return explicit MCP least-privilege Mongo scope for host-side auditing."""
    return {
        "database": server_settings.mongo_db_name,
        "authorized_collections": [
            server_settings.raw_telemetry_collection,
            server_settings.reports_collection,
        ],
        "domain_to_collection_mapping": {
            "LogEvent": server_settings.raw_telemetry_collection,
            "AnalysisReport": server_settings.reports_collection,
        },
        "access_mode": "read_only",
    }


async def execute_get_raw_telemetry_events(arguments: dict[str, Any]) -> dict[str, Any]:
    """Fetch raw telemetry from sentinel_soa.raw_telemetry using validated filters."""
    payload = RawTelemetryQueryInput(**arguments)
    return await threat_queries_service.get_raw_telemetry_events(payload)


async def execute_get_threat_reports(arguments: dict[str, Any]) -> dict[str, Any]:
    """Fetch reports from sentinel_soa.reports using validated filters."""
    payload = ThreatReportQueryInput(**arguments)
    return await threat_queries_service.get_threat_reports(payload)


async def execute_get_source_threat_timeline(arguments: dict[str, Any]) -> dict[str, Any]:
    """Assemble source-level telemetry + reports timeline for deep investigations."""
    payload = SourceTimelineInput(**arguments)
    return await threat_queries_service.get_source_threat_timeline(payload)


async def execute_analyze_potential_threat(arguments: dict[str, Any]) -> dict[str, Any]:
    """Run deterministic threat analysis using only Mongo evidence from allowed collections."""
    payload = PotentialThreatAnalysisInput(**arguments)
    return await threat_queries_service.analyze_potential_threat(payload)

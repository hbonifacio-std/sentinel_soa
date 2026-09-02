"""Execution layer for MCP threat-intelligence tools."""

from __future__ import annotations

from typing import Any

from mcp_servers.log_analysis_server.config import server_settings
from mcp_servers.log_analysis_server.database_manager import MongoDatabaseManager
from mcp_servers.log_analysis_server.graph_database_manager import Neo4jDatabaseManager
from mcp_servers.log_analysis_server.models.threat_tools import (
    GraphLateralMovementInput,
    GraphMitreContextInput,
    GraphThreatLandscapeInput,
    PotentialThreatAnalysisInput,
    RawTelemetryQueryInput,
    ThreatReportQueryInput,
    UnifiedForensicContextInput,
)
from mcp_servers.log_analysis_server.services.forensic_context_fusion import (
    ForensicContextFusionService,
)
from mcp_servers.log_analysis_server.services.graph_threat_queries import GraphThreatQueriesService
from mcp_servers.log_analysis_server.services.threat_queries import ThreatQueriesService

mongo_db_manager = MongoDatabaseManager()
neo4j_db_manager = Neo4jDatabaseManager()
threat_queries_service = ThreatQueriesService(mongo_db_manager)
graph_threat_queries_service = GraphThreatQueriesService(neo4j_db_manager)
forensic_context_fusion_service = ForensicContextFusionService(
    threat_queries_service=threat_queries_service,
    graph_threat_queries_service=graph_threat_queries_service,
)


def execute_get_mongo_access_scope() -> dict[str, Any]:
    """Return MongoDB scope metadata (database, collections, and access mode)."""
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


def execute_get_graph_access_scope() -> dict[str, Any]:
    """Return Neo4j scope metadata (database, labels, and access mode)."""
    return {
        "database": server_settings.neo4j_database,
        "uri": server_settings.neo4j_uri,
        "labels": [
            "Client",
            "Source",
            "IPAddress",
            "TelemetryWindow",
            "LogEvent",
            "HttpRequest",
            "ThreatReport",
            "AttackIndicator",
            "MitreTactic",
            "MitreTechnique",
            "MitreSubTechnique",
        ],
        "access_mode": "read_only",
    }


async def execute_get_raw_telemetry_events(arguments: dict[str, Any]) -> dict[str, Any]:
    """Query raw telemetry events from MongoDB using validated filters."""
    payload = RawTelemetryQueryInput(**arguments)
    return await threat_queries_service.get_raw_telemetry_events(payload)


async def execute_get_threat_reports(arguments: dict[str, Any]) -> dict[str, Any]:
    """Query threat reports from MongoDB using validated filters."""
    payload = ThreatReportQueryInput(**arguments)
    return await threat_queries_service.get_threat_reports(payload)


async def execute_analyze_potential_threat(arguments: dict[str, Any]) -> dict[str, Any]:
    """Run deterministic risk scoring from MongoDB evidence only."""
    payload = PotentialThreatAnalysisInput(**arguments)
    return await threat_queries_service.analyze_potential_threat(payload)

async def execute_get_graph_threat_landscape(arguments: dict[str, Any]) -> dict[str, Any]:
    """Get a global Neo4j threat landscape snapshot for SOC context."""
    payload = GraphThreatLandscapeInput(**arguments)
    return await graph_threat_queries_service.get_graph_threat_landscape(payload)


async def execute_get_graph_lateral_movement_paths(arguments: dict[str, Any]) -> dict[str, Any]:
    """Get lateral-movement candidates from Neo4j graph evidence."""
    payload = GraphLateralMovementInput(**arguments)
    return await graph_threat_queries_service.get_graph_lateral_movement_paths(payload)


async def execute_get_graph_mitre_context(arguments: dict[str, Any]) -> dict[str, Any]:
    """Get MITRE ATT&CK and kill-chain context from Neo4j relationships."""
    payload = GraphMitreContextInput(**arguments)
    return await graph_threat_queries_service.get_graph_mitre_context(payload)


async def execute_get_unified_forensic_context(arguments: dict[str, Any]) -> dict[str, Any]:
    """Fuse MongoDB + Neo4j evidence into a single SOC-ready context payload."""
    payload = UnifiedForensicContextInput(**arguments)
    return await forensic_context_fusion_service.get_unified_forensic_context(payload)

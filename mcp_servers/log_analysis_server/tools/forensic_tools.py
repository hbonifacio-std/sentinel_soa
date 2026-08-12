"""FastMCP forensic tools for real-time threat detection and AI-driven analysis."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from mcp_servers.log_analysis_server.database_manager import MongoDatabaseManager
from mcp_servers.log_analysis_server.graph_database_manager import Neo4jDatabaseManager
from mcp_servers.log_analysis_server.models.threat_tools import (
    AttackerChronologicalTimelineInput,
    DataExfiltrationEvidenceInput,
    PivotBlastRadiusInput,
    ThreatDashboardSummaryInput,
    WindowTelemetrySummaryInput,
)

logger = logging.getLogger(__name__)

mongo_db_manager = MongoDatabaseManager()
neo4j_db_manager = Neo4jDatabaseManager()

# Patterns for sensitive path detection
SENSITIVE_PATH_PATTERNS = [
    "/etc/passwd",
    "/etc/shadow",
    ".env",
    ".secrets",
    "credentials",
    "private_key",
    "secret_key",
    "/admin",
    "/backup",
    "/config",
    "/download",
]


async def execute_get_threat_dashboard_summary(
    client_id: str,
    time_window_hours: int = 24,
    min_threat_level: str = "LOW",
) -> Dict[str, Any]:
    """
    Get high-level security posture overview with global alert metrics, top attacking IPs,
    latest alert timestamp, and top threat types.

    ENFORCES: client_id filter at pipeline start (multi-tenancy).
    Returns: total_alerts, latest_alert_timestamp_utc, severity_counts, top_threat_types,
             top_attacking_ips, affected_sources, active_windows.
    """
    await mongo_db_manager.connect()
    collection = mongo_db_manager.get_collection("reports")

    threat_level_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    min_level_value = threat_level_order.get(min_threat_level.upper(), 1)

    from_utc = datetime.now(timezone.utc) - timedelta(hours=time_window_hours)

    allowed_threat_levels = [
        k for k, v in threat_level_order.items() if v >= min_level_value
    ]

    pipeline = [
        # 1. Filtro inicial multi-tenant y ventana temporal
        {
            "$match": {
                "client_id": client_id,
                "created_at_utc": {"$gte": from_utc},
                "threat_level": {"$in": allowed_threat_levels},
            }
        },
        # 2. Agregación paralela de métricas mediante $facet
        {
            "$facet": {
                # Metadatos generales (Timestamp más reciente, sources, windows)
                "metadata": [
                    {
                        "$group": {
                            "_id": None,
                            "latest_alert_utc": {"$max": "$created_at_utc"},
                            "sources": {"$addToSet": "$source_id"},
                            "windows": {"$addToSet": "$window_id"},
                        }
                    }
                ],
                # Distribución de severidad
                "severity": [
                    {"$group": {"_id": "$threat_level", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                ],
                # Top tipos de amenazas / categorías de alerta
                "threat_types": [
                    {
                        "$group": {
                            "_id": {"$ifNull": ["$threat_type", "$category"]},
                            "count": {"$sum": 1},
                        }
                    },
                    {"$sort": {"count": -1}},
                    {"$limit": 5},
                ],
                # Top IPs atacantes
                "top_ips": [
                    {"$group": {"_id": "$source_ip", "reports_count": {"$sum": 1}}},
                    {"$sort": {"reports_count": -1}},
                    {"$limit": 10},
                ],
            }
        },
    ]

    results = await (await collection.aggregate(pipeline)).to_list(None)

    if not results or not results[0]:
        return {
            "total_alerts": 0,
            "latest_alert_timestamp_utc": None,
            "severity_counts": {},
            "top_threat_types": [],
            "top_attacking_ips": [],
            "affected_sources": [],
            "active_windows": [],
        }

    facet_data = results[0]

    # Extracción de metadata
    metadata = facet_data["metadata"][0] if facet_data.get("metadata") else {}
    latest_alert_raw = metadata.get("latest_alert_utc")
    latest_alert_timestamp_utc = (
        latest_alert_raw.isoformat() if isinstance(latest_alert_raw, datetime) else str(latest_alert_raw) if latest_alert_raw else None
    )

    affected_sources = [s for s in metadata.get("sources", []) if s][:20]
    active_windows = [w for w in metadata.get("windows", []) if w][:20]

    # Extracción de severidades y cálculo de total_alerts
    severity_counts = {
        item["_id"]: item["count"]
        for item in facet_data.get("severity", [])
        if item["_id"]
    }
    total_alerts = sum(severity_counts.values())

    # Extracción de top threat types e IPs
    top_threat_types = [
        item["_id"] for item in facet_data.get("threat_types", []) if item["_id"]
    ]
    top_attacking_ips = [
        {"ip": item["_id"], "reports_count": item["reports_count"]}
        for item in facet_data.get("top_ips", [])
        if item["_id"]
    ]

    return {
        "total_alerts": total_alerts,
        "latest_alert_timestamp_utc": latest_alert_timestamp_utc,
        "severity_counts": severity_counts,
        "top_threat_types": top_threat_types,
        "top_attacking_ips": top_attacking_ips,
        "affected_sources": affected_sources,
        "active_windows": active_windows,
    }


async def execute_summarize_window_telemetry(
    client_id: str,
    window_id: str,
) -> Dict[str, Any]:
    """
    Statistically analyze telemetry logs in a batch/window without retrieving individual events.

    ENFORCES: client_id and window_id filters at pipeline start (multi-tenancy).
    Returns: window_id, timeframe, total_events, unique_ips, top_source_ips,
             status_code_distribution, suspicious_events_count, top_user_agents, top_targeted_paths.
    """
    await mongo_db_manager.connect()
    collection = mongo_db_manager.get_collection("raw_telemetry")

    match_filter = {
        "client_id": client_id,
        "window_id": window_id,
    }

    # Pipeline consolidado mediante $facet para mayor rendimiento
    pipeline = [
        {"$match": match_filter},
        {
            "$facet": {
                # 1. Metadatos generales (Total eventos, Timeframe)
                "metadata": [
                    {
                        "$group": {
                            "_id": None,
                            "total_events": {"$sum": 1},
                            "window_start_utc": {"$min": "$timestamp_utc"},
                            "window_end_utc": {"$max": "$timestamp_utc"},
                        }
                    }
                ],
                # 2. Distribución de códigos de estado HTTP
                "status_codes": [
                    {"$group": {"_id": "$http.status_code", "count": {"$sum": 1}}},
                    {"$sort": {"_id": 1}},
                ],
                # 3. Top IPs origen más activas
                "top_ips": [
                    {"$group": {"_id": "$source_ip", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                    {"$limit": 5},
                ],
                # 4. Total de IPs únicas
                "unique_ips_count": [
                    {"$group": {"_id": "$source_ip"}},
                    {"$count": "count"},
                ],
                # 5. Top User-Agents
                "top_user_agents": [
                    {"$group": {"_id": "$http.user_agent", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                    {"$limit": 5},
                ],
                # 6. Top Rutas HTTP más consultadas
                "top_paths": [
                    {"$group": {"_id": "$http.path", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                    {"$limit": 5},
                ],
            }
        },
    ]

    results = await (await collection.aggregate(pipeline)).to_list(None)

    if not results or not results[0]:
        return {
            "window_id": window_id,
            "window_start_utc": None,
            "window_end_utc": None,
            "total_events": 0,
            "unique_ips": 0,
            "top_source_ips": [],
            "status_code_distribution": {},
            "top_user_agents": [],
            "top_targeted_paths": [],
        }

    data = results[0]

    # Extraer metadatos
    metadata = data["metadata"][0] if data["metadata"] else {}
    total_events = metadata.get("total_events", 0)
    window_start_utc = str(metadata["window_start_utc"]) if metadata.get("window_start_utc") else None
    window_end_utc = str(metadata["window_end_utc"]) if metadata.get("window_end_utc") else None


    # Extraer distribuciones y listas
    status_code_distribution = {
        str(item["_id"]): item["count"] for item in data["status_codes"] if item["_id"] is not None
    }
    top_source_ips = [item["_id"] for item in data["top_ips"] if item["_id"]]
    unique_ips = data["unique_ips_count"][0]["count"] if data["unique_ips_count"] else 0
    top_user_agents = [item["_id"] for item in data["top_user_agents"] if item["_id"]]
    top_targeted_paths = [item["_id"] for item in data["top_paths"] if item["_id"]]

    return {
        "window_id": window_id,
        "window_start_utc": window_start_utc,
        "window_end_utc": window_end_utc,
        "total_events": total_events,
        "unique_ips": unique_ips,
        "top_source_ips": top_source_ips,
        "status_code_distribution": status_code_distribution,
        "top_user_agents": top_user_agents,
        "top_targeted_paths": top_targeted_paths,
    }


async def execute_get_attacker_chronological_timeline(
    client_id: str,
    source_ip: Optional[str] = None,
    window_id: Optional[str] = None,
    only_suspicious: bool = True,
    limit: int = 30,
) -> Dict[str, Any]:
    """
    Reconstruct exact step-by-step chronological sequence of attacker events.

    ENFORCES: client_id filter in MATCH clause (multi-tenancy).
    Uses Neo4j graph to traverse: Client -> LogEvent -> HttpRequest.
    Returns: timeline_events with full context (sorted by timestamp_utc).
    """
    await neo4j_db_manager.connect()
    driver = neo4j_db_manager.get_driver()

    cypher_query = """
    MATCH (c:Client {client_id: $client_id})-[:GENERATED]->(e:LogEvent)
    WHERE ($source_ip IS NULL OR e.source_ip = $source_ip)
      AND ($window_id IS NULL OR e.window_id = $window_id)
      AND ($only_suspicious = FALSE OR e.is_suspicious = TRUE)
    OPTIONAL MATCH (e)-[:HAS_HTTP]->(h:HttpRequest)
    RETURN 
        e.timestamp_utc AS timestamp_utc,
        e.source_ip AS source_ip,
        e.source_id AS target_service,
        h.method AS method,
        h.path AS path,
        h.query_params AS query_params,
        h.status_code AS status_code,
        h.response_size_bytes AS response_size_bytes,
        h.user_agent AS user_agent,
        e.suspicious_reason AS suspicious_reason
    ORDER BY e.timestamp_utc ASC
    LIMIT $limit
    """

    timeline_events = []
    try:
        async with driver.session() as session:
            results = await session.run(
                cypher_query,
                {
                    "client_id": client_id,
                    "source_ip": source_ip,
                    "window_id": window_id,
                    "only_suspicious": only_suspicious,
                    "limit": limit,
                },
            )
            records = await results.fetch(limit)

            for record in records:
                event = {
                    "timestamp_utc": str(record["timestamp_utc"]) if record["timestamp_utc"] else "",
                    "source_ip": record["source_ip"] or "",
                    "target_service": record["target_service"] or "",
                    "method": record["method"] or "",
                    "path": record["path"] or "",
                    "query_params": record["query_params"],
                    "status_code": record["status_code"],
                    "response_size_bytes": record["response_size_bytes"] or 0,
                    "user_agent": record["user_agent"] or "",
                    "suspicious_reason": record["suspicious_reason"],
                }
                timeline_events.append(event)
    except Exception as e:
        logger.error("Error fetching attacker chronological timeline: %s", e)
        timeline_events = []

    return {"timeline_events": timeline_events}


async def execute_check_data_exfiltration_evidence(
        client_id: str,
        source_ip: str,
        window_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Determine if IP successfully extracted sensitive information or attempted unauthorized downloads.

    ENFORCES: client_id filter at pipeline start (multi-tenancy).
    Analyzes: successful/failed HTTP requests, total bytes transferred, sensitive paths, and sample endpoints.
    Returns: exfiltration risk level + detailed evidence.
    """
    await mongo_db_manager.connect()
    collection = mongo_db_manager.get_collection("raw_telemetry")

    # Filtro base para peticiones exitosas (200, 206)
    match_criteria = {
        "client_id": client_id,
        "source_ip": source_ip,
        "http.status_code": {"$in": [200, 206]},
    }

    # Filtro base general para la IP
    base_ip_criteria = {
        "client_id": client_id,
        "source_ip": source_ip,
    }

    if window_id:
        match_criteria["window_id"] = window_id
        base_ip_criteria["window_id"] = window_id

    # 1. Total bytes descargados y conteo de descargas exitosas
    bytes_pipeline = [
        {"$match": match_criteria},
        {
            "$group": {
                "_id": None,
                "total_bytes": {"$sum": "$http.response_size_bytes"},
                "count": {"$sum": 1},
            }
        },
    ]

    bytes_results = await (await collection.aggregate(bytes_pipeline)).to_list(None)
    total_bytes_downloaded = 0
    successful_downloads_count = 0

    if bytes_results:
        total_bytes_downloaded = bytes_results[0].get("total_bytes", 0) or 0
        successful_downloads_count = bytes_results[0].get("count", 0) or 0

    # 2. Conteo de intentos de descarga fallidos (401, 403, 404)
    failed_attempts_count = await collection.count_documents({
        **base_ip_criteria,
        "http.status_code": {"$in": [401, 403, 404]}
    })

    # 3. Rutas sensibles accedidas
    sensitive_pipeline = [
        {"$match": match_criteria},
        {
            "$project": {
                "path": "$http.path",
                "status_code": "$http.status_code",
                "bytes": "$http.response_size_bytes",
                "is_sensitive": {
                    "$anyElementTrue": {
                        "$map": {
                            "input": SENSITIVE_PATH_PATTERNS,
                            "as": "pattern",
                            "in": {
                                "$regexMatch": {
                                    "input": "$http.path",
                                    "regex": "$$pattern",
                                    "options": "i"
                                }
                            }
                        }
                    }
                },
            }
        },
        {"$match": {"is_sensitive": True}},
        {"$project": {"path": 1, "status_code": 1, "bytes": 1}},
        {"$limit": 20},
    ]

    sensitive_results = await (await collection.aggregate(sensitive_pipeline)).to_list(None)
    sensitive_paths_accessed = [
        {
            "path": item["path"],
            "status_code": item["status_code"],
            "bytes": item.get("bytes", 0) or 0,
        }
        for item in sensitive_results
    ]

    # 4. Muestra de rutas normales accedidas (máximo 5 rutas distintas)
    sample_paths = await collection.distinct("http.path", match_criteria)
    sample_paths_accessed = [p for p in sample_paths if p][:5]

    # 5. Determinación del nivel de riesgo de exfiltración
    risk_level = "NONE"
    if sensitive_paths_accessed:
        if len(sensitive_paths_accessed) >= 5 or total_bytes_downloaded > 10_000_000:
            risk_level = "HIGH"
        elif len(sensitive_paths_accessed) >= 2 or total_bytes_downloaded > 1_000_000:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
    elif successful_downloads_count > 100:
        risk_level = "MEDIUM"
    elif successful_downloads_count > 50:
        risk_level = "LOW"

    return {
        "source_ip": source_ip,
        "evaluated_window_id": window_id,
        "total_bytes_downloaded": total_bytes_downloaded,
        "successful_downloads_count": successful_downloads_count,
        "failed_download_attempts": failed_attempts_count,
        "sensitive_paths_accessed": sensitive_paths_accessed,
        "sample_paths_accessed": sample_paths_accessed,
        "exfiltration_risk": risk_level,
    }


async def execute_find_pivot_blast_radius(
    client_id: str,
    source_ip: str,
) -> Dict[str, Any]:
    """
    Discover the blast radius, targeted endpoints, and threat context of an attacking IP.

    Identifies affected microservices (source_id), HTTP paths/endpoints probed, User-Agents,
    attack indicators, and associated MITRE ATT&CK tactics, techniques, and sub-techniques.

    Inputs:
    - client_id (str, REQUIRED): Tenant unique ID
    - source_ip (str, REQUIRED): IP address to investigate

    Output includes:
    - affected_sources (list[str])
    - user_agents_used (list[str])
    - targeted_paths (list[str])
    - mitre_tactics_observed (list[str])
    - mitre_techniques_observed (list[str])
    - mitre_subtechniques_observed (list[str])
    - attack_indicators (list[str])
    """
    await neo4j_db_manager.connect()
    driver = neo4j_db_manager.get_driver()

    cypher_query = """
    MATCH (c:Client {client_id: $client_id})

    // 1. Eventos de la IP, microservicios, User-Agents y Rutas HTTP (endpoints)
    OPTIONAL MATCH (e:LogEvent {client_id: $client_id, source_ip: $source_ip})
    OPTIONAL MATCH (e)-[:HAS_HTTP]->(h:HttpRequest)

    // 2. Reportes de amenaza por IP directa o ventana de telemetría
    OPTIONAL MATCH (r:ThreatReport {client_id: $client_id})
    OPTIONAL MATCH (r)-[:IN_WINDOW]->(w:TelemetryWindow)
    WHERE r.source_ip = $source_ip OR w.window_id = e.window_id

    // 3. Inteligencia de amenazas (Tácticas, Técnicas, Subtécnicas e Indicadores)
    OPTIONAL MATCH (r)-[:USES_TACTIC]->(t:MitreTactic)
    OPTIONAL MATCH (r)-[:USES_TECHNIQUE]->(tech:MitreTechnique)
    OPTIONAL MATCH (r)-[:USES_SUB_TECHNIQUE]->(sub:MitreSubTechnique)
    OPTIONAL MATCH (r)-[:HAS_INDICATOR]->(ind:AttackIndicator)

    RETURN
      [s IN collect(DISTINCT e.source_id) WHERE s IS NOT NULL][..50] AS affected_sources,
      [ua IN collect(DISTINCT h.user_agent) WHERE ua IS NOT NULL][..20] AS user_agents_used,
      [path IN collect(DISTINCT h.path) WHERE path IS NOT NULL][..20] AS targeted_paths,
      [t_name IN collect(DISTINCT t.name) WHERE t_name IS NOT NULL][..20] AS mitre_tactics,
      [tech_name IN collect(DISTINCT tech.name) WHERE tech_name IS NOT NULL][..20] AS mitre_techniques,
      [sub_name IN collect(DISTINCT sub.name) WHERE sub_name IS NOT NULL][..20] AS mitre_subtechniques,
      [ind_name IN collect(DISTINCT ind.name) WHERE ind_name IS NOT NULL][..20] AS attack_indicators
    """

    async with driver.session() as session:
        result = await session.run(cypher_query, {"client_id": client_id, "source_ip": source_ip})
        record = await result.single()

        if not record:
            return {
                "affected_sources": [],
                "user_agents_used": [],
                "targeted_paths": [],
                "mitre_tactics_observed": [],
                "mitre_techniques_observed": [],
                "mitre_subtechniques_observed": [],
                "attack_indicators": [],
            }

        return {
            "affected_sources": record["affected_sources"] or [],
            "user_agents_used": record["user_agents_used"] or [],
            "targeted_paths": record["targeted_paths"] or [],
            "mitre_tactics_observed": record["mitre_tactics"] or [],
            "mitre_techniques_observed": record["mitre_techniques"] or [],
            "mitre_subtechniques_observed": record["mitre_subtechniques"] or [],
            "attack_indicators": record["attack_indicators"] or [],
        }
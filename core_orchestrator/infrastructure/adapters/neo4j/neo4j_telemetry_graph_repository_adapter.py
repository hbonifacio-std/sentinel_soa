import asyncio
import hashlib
import json
from dataclasses import asdict
from datetime import datetime
from typing import Any, Optional, Sequence

from neo4j import AsyncDriver

from core_orchestrator.domain.entities.telemetry.logs_event import LogEvent
from core_orchestrator.domain.entities.telemetry.reports import AnalysisReport
from core_orchestrator.domain.ports.telemetry.telemetry_graph_repository_port import (
    TelemetryGraphRepositoryPort,
)
from core_orchestrator.infrastructure.database.database_manager import DatabaseManager


def _safe_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _serialize_datetime(value: datetime) -> str:
    return value.isoformat()


def _source_key(client_id: Optional[str], source_id: Optional[str]) -> Optional[str]:
    source = _safe_text(source_id)
    if not source:
        return None
    client = _safe_text(client_id)
    return f"{client}:{source}" if client else source


def _build_event_id(log_event: LogEvent) -> str:
    http_path = None
    http_status = None
    http_method = None
    if log_event.http is not None:
        http_path = log_event.http.path
        http_status = log_event.http.status_code
        http_method = log_event.http.method
    key_parts = [
        log_event.source_ip,
        _serialize_datetime(log_event.timestamp_utc),
        _safe_text(log_event.client_id) or "",
        _safe_text(log_event.source_id) or "",
        _safe_text(log_event.window_id) or "",
        _safe_text(http_method) or "",
        _safe_text(http_path) or "",
        str(http_status or ""),
    ]
    digest = hashlib.sha256("|".join(key_parts).encode("utf-8")).hexdigest()
    return f"log_{digest}"


class Neo4jTelemetryGraphRepositoryAdapter(TelemetryGraphRepositoryPort):
    def __init__(self, db_manager: DatabaseManager):
        self._driver: AsyncDriver = db_manager.get_neo4j_driver()
        self._database_name = db_manager.get_neo4j_database_name()
        self._schema_ready = False
        self._schema_lock = asyncio.Lock()

    async def upsert_log_event(self, log_event: LogEvent, event_id: Optional[str] = None) -> None:
        await self._ensure_schema()
        payload = self._build_log_payload(log_event=log_event, event_id=event_id)
        query = """
        MERGE (client:Client {client_id: $client_id})

  
        MERGE (event:LogEvent {event_id: $event_id})
        SET event.timestamp_utc = datetime($timestamp_utc),
            event.source_ip = $source_ip,
            event.source_id = $source_id,
            event.client_id = $client_id,
            event.window_id = $window_id,
            event.is_suspicious = $is_suspicious,
            event.extra_fields_json = $extra_fields_json

        MERGE (client)-[:GENERATED]->(event)

 
        FOREACH (_ IN CASE WHEN $source_ip IS NULL THEN [] ELSE [1] END |
            MERGE (ip:IPAddress {address: $source_ip, client_id: $client_id})
            MERGE (event)-[:ORIGINATES_FROM]->(ip)
            MERGE (client)-[:OWNS_IP]->(ip)
        )

 
        FOREACH (_ IN CASE WHEN $window_id IS NULL THEN [] ELSE [1] END |
            MERGE (window:TelemetryWindow {window_id: $window_id, client_id: $client_id})
            MERGE (event)-[:IN_WINDOW]->(window)
            MERGE (client)-[:HAS_WINDOW]->(window)
        )

      
        FOREACH (_ IN CASE WHEN $source_key IS NULL THEN [] ELSE [1] END |
            MERGE (source:Source {source_key: $source_key, client_id: $client_id})
            SET source.source_id = $source_id,
                source.client_id = $client_id
            MERGE (source)-[:EMITTED]->(event)
            MERGE (client)-[:OWNS_SOURCE]->(source)
        )

      
        FOREACH (_ IN CASE WHEN $http_method IS NULL AND $http_path IS NULL AND $http_status_code IS NULL THEN [] ELSE [1] END |
            MERGE (http:HttpRequest {request_id: $event_id, client_id: $client_id})
            SET http.method = $http_method,
                http.path = $http_path,
                http.status_code = $http_status_code,
                http.query = $http_query,
                http.user_agent = $http_user_agent,
                http.referrer = $http_referrer,
                http.response_size_bytes = $http_response_size_bytes,
                http.payload = $http_payload
            MERGE (event)-[:HAS_HTTP]->(http)
        )
                """
        async with self._driver.session(database=self._database_name) as session:
            await session.run(query, payload)

    async def upsert_bulk_log_events(self, log_events: Sequence[LogEvent]) -> None:
        if not log_events:
            return
        await self._ensure_schema()
        rows = [self._build_log_payload(log_event=event) for event in log_events]
        query = """
        UNWIND $rows AS row

        // 1. Nodo Raíz por Fila
        MERGE (client:Client {client_id: row.client_id})

        // 2. Evento aislado
        MERGE (event:LogEvent {event_id: row.event_id})
        SET event.timestamp_utc = datetime(row.timestamp_utc),
            event.source_ip = row.source_ip,
            event.source_id = row.source_id,
            event.client_id = row.client_id,
            event.window_id = row.window_id,
            event.is_suspicious = row.is_suspicious,
            event.extra_fields_json = row.extra_fields_json

        MERGE (client)-[:GENERATED]->(event)

        // 3. Sub-nodos aislados por client_id
        FOREACH (_ IN CASE WHEN row.source_ip IS NULL THEN [] ELSE [1] END |
            MERGE (ip:IPAddress {address: row.source_ip, client_id: row.client_id})
            MERGE (event)-[:ORIGINATES_FROM]->(ip)
            MERGE (client)-[:OWNS_IP]->(ip)
        )

        FOREACH (_ IN CASE WHEN row.window_id IS NULL THEN [] ELSE [1] END |
            MERGE (window:TelemetryWindow {window_id: row.window_id, client_id: row.client_id})
            MERGE (event)-[:IN_WINDOW]->(window)
            MERGE (client)-[:HAS_WINDOW]->(window)
        )

        FOREACH (_ IN CASE WHEN row.source_key IS NULL THEN [] ELSE [1] END |
            MERGE (source:Source {source_key: row.source_key, client_id: row.client_id})
            SET source.source_id = row.source_id,
                source.client_id = row.client_id
            MERGE (source)-[:EMITTED]->(event)
            MERGE (client)-[:OWNS_SOURCE]->(source)
        )

        FOREACH (_ IN CASE WHEN row.http_method IS NULL AND row.http_path IS NULL AND row.http_status_code IS NULL THEN [] ELSE [1] END |
            MERGE (http:HttpRequest {request_id: row.event_id, client_id: row.client_id})
            SET http.method = row.http_method,
                http.path = row.http_path,
                http.status_code = row.http_status_code,
                http.query = row.http_query,
                http.user_agent = row.http_user_agent,
                http.referrer = row.http_referrer,
                http.response_size_bytes = row.http_response_size_bytes,
                http.payload = row.http_payload
            MERGE (event)-[:HAS_HTTP]->(http)
        )
        """
        async with self._driver.session(database=self._database_name) as session:
            await session.run(query, {"rows": rows})

    async def upsert_analysis_report(self, report: AnalysisReport, report_id: Optional[str] = None) -> None:
        await self._ensure_schema()
        normalized_report_id = _safe_text(report_id) or _safe_text(report.id) or ""
        if not normalized_report_id:
            raise ValueError("report_id is required to persist analysis report into Neo4j")

        payload = self._build_report_payload(report=report, report_id=normalized_report_id)
        report_query = """
        // 1. Inicio en el Cliente
        MERGE (client:Client {client_id: $client_id})

        // 2. Reporte asignado al cliente
        MERGE (report:ThreatReport {report_id: $report_id})
        SET report.threat_detected = $threat_detected,
            report.source_ip = $source_ip,
            report.source_id = $source_id,
            report.client_id = $client_id,
            report.window_id = $window_id,
            report.threat_level = $threat_level,
            report.threat_score = $threat_score,
            report.kill_chain_phase = $kill_chain_phase,
            report.reasoning_summary = $reasoning_summary,
            report.recommendation = $recommendation,
            report.reviewed = $reviewed,
            report.resolved = $resolved,
            report.created_at_utc = datetime($created_at_utc),
            report.resolved_at_utc = CASE
                WHEN $resolved_at_utc IS NULL THEN report.resolved_at_utc
                ELSE datetime($resolved_at_utc)
            END,
            report.suggested_mitigations_json = $suggested_mitigations_json

        MERGE (client)-[:HAS_REPORT]->(report)

        // 3. Entidades contextuales aisladas por cliente
        FOREACH (_ IN CASE WHEN $source_ip IS NULL THEN [] ELSE [1] END |
            MERGE (ip:IPAddress {address: $source_ip, client_id: $client_id})
            MERGE (report)-[:FROM_IP]->(ip)
            MERGE (client)-[:OWNS_IP]->(ip)
        )
        FOREACH (_ IN CASE WHEN $window_id IS NULL THEN [] ELSE [1] END |
            MERGE (window:TelemetryWindow {window_id: $window_id, client_id: $client_id})
            MERGE (report)-[:IN_WINDOW]->(window)
            MERGE (client)-[:HAS_WINDOW]->(window)
        )
        FOREACH (_ IN CASE WHEN $source_key IS NULL THEN [] ELSE [1] END |
            MERGE (source:Source {source_key: $source_key, client_id: $client_id})
            SET source.source_id = $source_id,
                source.client_id = $client_id
            MERGE (source)-[:HAS_REPORT]->(report)
            MERGE (client)-[:OWNS_SOURCE]->(source)
        )

        // 4. Entidades globales compartidas (MITRE e Indicadores)
        FOREACH (_ IN CASE WHEN $mitre_tactic_id IS NULL THEN [] ELSE [1] END |
            MERGE (tactic:MitreTactic {tactic_id: $mitre_tactic_id})
            SET tactic.name = $mitre_tactic
            MERGE (report)-[:USES_TACTIC]->(tactic)
        )
        FOREACH (_ IN CASE WHEN $mitre_technique_id IS NULL THEN [] ELSE [1] END |
            MERGE (technique:MitreTechnique {technique_id: $mitre_technique_id})
            SET technique.name = $mitre_technique
            MERGE (report)-[:USES_TECHNIQUE]->(technique)
        )
        FOREACH (_ IN CASE WHEN $mitre_sub_technique_id IS NULL THEN [] ELSE [1] END |
            MERGE (sub:MitreSubTechnique {sub_technique_id: $mitre_sub_technique_id})
            SET sub.name = $mitre_sub_technique
            MERGE (report)-[:USES_SUB_TECHNIQUE]->(sub)
        )
        FOREACH (indicator_name IN $indicators |
            MERGE (indicator:AttackIndicator {name: indicator_name})
            MERGE (report)-[:HAS_INDICATOR]->(indicator)
        )
        """

        async with self._driver.session(database=self._database_name) as session:
            await session.run(report_query, payload)

    async def _ensure_schema(self) -> None:
        if self._schema_ready:
            return
        async with self._schema_lock:
            if self._schema_ready:
                return
            queries = [
                "CREATE CONSTRAINT client_id_unique IF NOT EXISTS FOR (c:Client) REQUIRE c.client_id IS UNIQUE",
                "CREATE CONSTRAINT source_key_unique IF NOT EXISTS FOR (s:Source) REQUIRE s.source_key IS UNIQUE",
                "CREATE CONSTRAINT ip_address_unique IF NOT EXISTS FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE",
                "CREATE CONSTRAINT window_id_unique IF NOT EXISTS FOR (w:TelemetryWindow) REQUIRE w.window_id IS UNIQUE",
                "CREATE CONSTRAINT log_event_id_unique IF NOT EXISTS FOR (e:LogEvent) REQUIRE e.event_id IS UNIQUE",
                "CREATE CONSTRAINT request_id_unique IF NOT EXISTS FOR (h:HttpRequest) REQUIRE h.request_id IS UNIQUE",
                "CREATE CONSTRAINT threat_report_id_unique IF NOT EXISTS FOR (r:ThreatReport) REQUIRE r.report_id IS UNIQUE",
                "CREATE CONSTRAINT attack_indicator_name_unique IF NOT EXISTS FOR (i:AttackIndicator) REQUIRE i.name IS UNIQUE",
                "CREATE CONSTRAINT mitre_tactic_id_unique IF NOT EXISTS FOR (t:MitreTactic) REQUIRE t.tactic_id IS UNIQUE",
                "CREATE CONSTRAINT mitre_technique_id_unique IF NOT EXISTS FOR (t:MitreTechnique) REQUIRE t.technique_id IS UNIQUE",
                "CREATE CONSTRAINT mitre_sub_technique_id_unique IF NOT EXISTS FOR (t:MitreSubTechnique) REQUIRE t.sub_technique_id IS UNIQUE",
            ]
            async with self._driver.session(database=self._database_name) as session:
                for query in queries:
                    await session.run(query)
            self._schema_ready = True

    def _build_log_payload(self, log_event: LogEvent, event_id: Optional[str] = None) -> dict[str, Any]:
        http = log_event.http
        normalized_event_id = _safe_text(event_id) or _build_event_id(log_event)
        extra_fields_json = json.dumps(log_event.extra_fields or {}, default=str, ensure_ascii=True)
        return {
            "event_id": normalized_event_id,
            "timestamp_utc": _serialize_datetime(log_event.timestamp_utc),
            "source_ip": log_event.source_ip,
            "source_id": _safe_text(log_event.source_id),
            "client_id": _safe_text(log_event.client_id),
            "window_id": _safe_text(log_event.window_id),
            "source_key": _source_key(log_event.client_id, log_event.source_id),
            "is_suspicious": bool(log_event.is_suspicious_event),
            "extra_fields_json": extra_fields_json,
            "http_method": _safe_text(http.method) if http else None,
            "http_path": _safe_text(http.path) if http else None,
            "http_status_code": http.status_code if http else None,
            "http_query": _safe_text(http.query) if http else None,
            "http_user_agent": _safe_text(http.user_agent) if http else None,
            "http_referrer": _safe_text(http.referrer) if http else None,
            "http_response_size_bytes": log_event.http.response_size_bytes if log_event.http else None,
            "http_payload": _safe_text(log_event.http.payload) if http else None,
        }

    def _build_report_payload(self, report: AnalysisReport, report_id: str) -> dict[str, Any]:
        report_dict = asdict(report)
        indicators = sorted({str(indicator).strip() for indicator in (report.indicators_found or []) if str(indicator).strip()})
        suggested_mitigations = report_dict.get("suggested_mitigations") or []
        return {
            "report_id": report_id,
            "threat_detected": bool(report.threat_detected),
            "source_id": _safe_text(report.source_id),
            "source_ip": _safe_text(report.source_ip),
            "window_id": _safe_text(report.window_id),
            "client_id": _safe_text(report.client_id),
            "source_key": _source_key(report.client_id, report.source_id),
            "threat_level": _safe_text(report.threat_level),
            "threat_score": report.threat_score,
            "kill_chain_phase": _safe_text(report.kill_chain_phase),
            "reasoning_summary": _safe_text(report.reasoning_summary),
            "recommendation": _safe_text(report.recommendation),
            "reviewed": bool(report.reviewed),
            "resolved": bool(report.resolved),
            "created_at_utc": _serialize_datetime(report.created_at_utc),
            "resolved_at_utc": _serialize_datetime(report.resolved_at_utc) if report.resolved_at_utc else None,
            "mitre_tactic": _safe_text(report.mitre_tactic),
            "mitre_tactic_id": _safe_text(report.mitre_tactic_id),
            "mitre_technique": _safe_text(report.mitre_technique),
            "mitre_technique_id": _safe_text(report.mitre_technique_id),
            "mitre_sub_technique": _safe_text(report.mitre_sub_technique),
            "mitre_sub_technique_id": _safe_text(report.mitre_sub_technique_id),
            "indicators": indicators,
            "suggested_mitigations_json": json.dumps(suggested_mitigations, default=str, ensure_ascii=True),
        }

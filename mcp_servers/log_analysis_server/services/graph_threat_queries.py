"""Read-only Neo4j forensic context queries."""

from __future__ import annotations

from collections import Counter
from typing import Any

from mcp_servers.log_analysis_server.config import server_settings
from mcp_servers.log_analysis_server.graph_database_manager import Neo4jDatabaseManager
from mcp_servers.log_analysis_server.models.threat_tools import (
    AttackGraphContextInput,
    GraphLateralMovementInput,
    GraphMitreContextInput,
    GraphThreatLandscapeInput,
)


class GraphThreatQueriesService:
    """Provides high-context forensic graph queries with minimal analyst input."""

    def __init__(self, graph_db_manager: Neo4jDatabaseManager) -> None:
        self._graph_db_manager = graph_db_manager

    async def get_source_attack_context(self, payload: AttackGraphContextInput) -> dict[str, Any]:
        driver = self._graph_db_manager.get_driver()
        event_query = """
        MATCH (ip:IPAddress {address: $source_ip})<-[:ORIGINATES_FROM]-(event:LogEvent)
        WHERE event.timestamp_utc >= datetime() - duration({hours: $lookback_hours})
        OPTIONAL MATCH (event)-[:HAS_HTTP]->(http:HttpRequest)
        OPTIONAL MATCH (event)-[:IN_WINDOW]->(window:TelemetryWindow)
        OPTIONAL MATCH (source:Source)-[:EMITTED]->(event)
        WITH event, http, window, source
        WHERE $client_id IS NULL OR event.client_id = $client_id
        RETURN event.event_id AS event_id,
               event.timestamp_utc AS timestamp_utc,
               event.client_id AS client_id,
               event.source_id AS source_id,
               event.window_id AS window_id,
               event.is_suspicious AS is_suspicious,
               http.method AS http_method,
               http.path AS http_path,
               http.status_code AS http_status_code,
               http.user_agent AS http_user_agent
        ORDER BY event.timestamp_utc DESC
        LIMIT $limit_events
        """
        report_query = """
        MATCH (ip:IPAddress {address: $source_ip})<-[:FROM_IP]-(report:ThreatReport)
        WHERE report.created_at_utc >= datetime() - duration({hours: $lookback_hours})
        OPTIONAL MATCH (report)-[:HAS_INDICATOR]->(indicator:AttackIndicator)
        OPTIONAL MATCH (report)-[:USES_TACTIC]->(tactic:MitreTactic)
        OPTIONAL MATCH (report)-[:USES_TECHNIQUE]->(technique:MitreTechnique)
        OPTIONAL MATCH (report)-[:USES_SUB_TECHNIQUE]->(sub:MitreSubTechnique)
        WITH report, indicator, tactic, technique, sub
        WHERE $client_id IS NULL OR report.client_id = $client_id
        RETURN report.report_id AS report_id,
               report.created_at_utc AS created_at_utc,
               report.client_id AS client_id,
               report.source_id AS source_id,
               report.window_id AS window_id,
               report.threat_detected AS threat_detected,
               report.threat_level AS threat_level,
               report.threat_score AS threat_score,
               report.kill_chain_phase AS kill_chain_phase,
               report.reviewed AS reviewed,
               report.resolved AS resolved,
               collect(DISTINCT indicator.name) AS indicators,
               collect(DISTINCT tactic.name) AS tactics,
               collect(DISTINCT technique.name) AS techniques,
               collect(DISTINCT sub.name) AS sub_techniques
        ORDER BY report.created_at_utc DESC
        LIMIT $limit_reports
        """
        lateral_query = """
        MATCH (src:IPAddress {address: $source_ip})<-[:FROM_IP]-(:ThreatReport)-[:HAS_INDICATOR]->(indicator:AttackIndicator)
              <-[:HAS_INDICATOR]-(peer_report:ThreatReport)-[:FROM_IP]->(peer:IPAddress)
        WHERE peer.address <> $source_ip
          AND peer_report.created_at_utc >= datetime() - duration({hours: $lookback_hours})
          AND ($client_id IS NULL OR peer_report.client_id = $client_id)
        RETURN peer.address AS peer_ip,
               count(DISTINCT indicator.name) AS shared_indicators,
               collect(DISTINCT indicator.name)[0..8] AS shared_indicator_sample,
               max(peer_report.threat_score) AS max_peer_threat_score,
               count(DISTINCT peer_report.report_id) AS linked_reports
        ORDER BY shared_indicators DESC, max_peer_threat_score DESC
        LIMIT 10
        """

        parameters = {
            "source_ip": payload.source_ip,
            "client_id": payload.client_id,
            "lookback_hours": payload.lookback_hours,
            "limit_events": payload.limit_events,
            "limit_reports": payload.limit_reports,
        }

        async with driver.session(database=server_settings.neo4j_database) as session:
            event_result = await session.run(event_query, parameters)
            report_result = await session.run(report_query, parameters)
            lateral_result = await session.run(lateral_query, parameters)
            event_rows = [record.data() async for record in event_result]
            report_rows = [record.data() async for record in report_result]
            lateral_rows = [record.data() async for record in lateral_result]

        status_counter = Counter()
        path_counter = Counter()
        source_counter = Counter()
        client_counter = Counter()
        suspicious_events = 0
        for row in event_rows:
            status = row.get("http_status_code")
            if status is not None:
                status_counter[str(status)] += 1
            path = row.get("http_path")
            if path:
                path_counter[str(path)] += 1
            source_id = row.get("source_id")
            if source_id:
                source_counter[str(source_id)] += 1
            client_id = row.get("client_id")
            if client_id:
                client_counter[str(client_id)] += 1
            if bool(row.get("is_suspicious")):
                suspicious_events += 1

        threat_levels = Counter(str(row.get("threat_level")) for row in report_rows if row.get("threat_level"))
        indicators = Counter()
        tactics = Counter()
        techniques = Counter()
        sub_techniques = Counter()
        unresolved_reports = 0
        kill_chain_phase_counter = Counter()
        for row in report_rows:
            if row.get("resolved") is False:
                unresolved_reports += 1
            kill_chain_phase = row.get("kill_chain_phase")
            if kill_chain_phase:
                kill_chain_phase_counter[str(kill_chain_phase)] += 1
            for indicator in row.get("indicators", []) or []:
                if indicator:
                    indicators[str(indicator)] += 1
            for tactic in row.get("tactics", []) or []:
                if tactic:
                    tactics[str(tactic)] += 1
            for technique in row.get("techniques", []) or []:
                if technique:
                    techniques[str(technique)] += 1
            for sub in row.get("sub_techniques", []) or []:
                if sub:
                    sub_techniques[str(sub)] += 1

        return {
            "source_ip": payload.source_ip,
            "client_id_filter": payload.client_id,
            "lookback_hours": payload.lookback_hours,
            "summary": {
                "total_events": len(event_rows),
                "suspicious_events": suspicious_events,
                "total_reports": len(report_rows),
                "unresolved_reports": unresolved_reports,
                "threat_levels": dict(threat_levels),
                "top_status_codes": status_counter.most_common(10),
                "top_paths": path_counter.most_common(10),
                "related_sources": source_counter.most_common(10),
                "related_clients": client_counter.most_common(10),
                "top_indicators": indicators.most_common(15),
                "mitre_tactics": tactics.most_common(10),
                "mitre_techniques": techniques.most_common(10),
                "mitre_sub_techniques": sub_techniques.most_common(10),
                "kill_chain_phases": dict(kill_chain_phase_counter),
                "lateral_movement_candidates_count": len(lateral_rows),
            },
            "events": event_rows,
            "reports": report_rows,
            "lateral_movement_candidates": lateral_rows,
        }

    async def get_graph_threat_landscape(self, payload: GraphThreatLandscapeInput) -> dict[str, Any]:
        driver = self._graph_db_manager.get_driver()
        common_params = {
            "client_id": payload.client_id,
            "lookback_hours": payload.lookback_hours,
            "limit_entities": payload.limit_entities,
        }
        top_ips_query = """
        MATCH (ip:IPAddress)<-[:FROM_IP]-(report:ThreatReport)
        WHERE report.created_at_utc >= datetime() - duration({hours: $lookback_hours})
          AND ($client_id IS NULL OR report.client_id = $client_id)
        RETURN ip.address AS source_ip,
               count(DISTINCT report.report_id) AS report_count,
               max(report.threat_score) AS max_threat_score,
               avg(report.threat_score) AS avg_threat_score,
               sum(CASE WHEN report.resolved = false THEN 1 ELSE 0 END) AS unresolved_reports
        ORDER BY unresolved_reports DESC, max_threat_score DESC, report_count DESC
        LIMIT $limit_entities
        """
        top_indicators_query = """
        MATCH (indicator:AttackIndicator)<-[:HAS_INDICATOR]-(report:ThreatReport)
        WHERE report.created_at_utc >= datetime() - duration({hours: $lookback_hours})
          AND ($client_id IS NULL OR report.client_id = $client_id)
        RETURN indicator.name AS indicator,
               count(DISTINCT report.report_id) AS report_count,
               count(DISTINCT report.source_ip) AS affected_ips,
               max(report.threat_score) AS max_threat_score
        ORDER BY affected_ips DESC, report_count DESC, max_threat_score DESC
        LIMIT $limit_entities
        """
        top_techniques_query = """
        MATCH (tech:MitreTechnique)<-[:USES_TECHNIQUE]-(report:ThreatReport)
        WHERE report.created_at_utc >= datetime() - duration({hours: $lookback_hours})
          AND ($client_id IS NULL OR report.client_id = $client_id)
        RETURN tech.name AS technique,
               count(DISTINCT report.report_id) AS report_count,
               count(DISTINCT report.source_ip) AS affected_ips,
               avg(report.threat_score) AS avg_threat_score
        ORDER BY report_count DESC, affected_ips DESC
        LIMIT $limit_entities
        """
        health_query = """
        MATCH (report:ThreatReport)
        WHERE report.created_at_utc >= datetime() - duration({hours: $lookback_hours})
          AND ($client_id IS NULL OR report.client_id = $client_id)
        RETURN count(*) AS total_reports,
               sum(CASE WHEN report.resolved = false THEN 1 ELSE 0 END) AS unresolved_reports,
               sum(CASE WHEN report.reviewed = true THEN 1 ELSE 0 END) AS reviewed_reports,
               max(report.created_at_utc) AS latest_report_utc
        """
        async with driver.session(database=server_settings.neo4j_database) as session:
            ips_result = await session.run(top_ips_query, common_params)
            indicators_result = await session.run(top_indicators_query, common_params)
            techniques_result = await session.run(top_techniques_query, common_params)
            health_result = await session.run(health_query, common_params)
            top_ips = [row.data() async for row in ips_result]
            top_indicators = [row.data() async for row in indicators_result]
            top_techniques = [row.data() async for row in techniques_result]
            health_rows = [row.data() async for row in health_result]

        health = health_rows[0] if health_rows else {
            "total_reports": 0,
            "unresolved_reports": 0,
            "reviewed_reports": 0,
            "latest_report_utc": None,
        }
        return {
            "context_type": "graph_threat_landscape",
            "client_id_filter": payload.client_id,
            "lookback_hours": payload.lookback_hours,
            "summary": {
                "total_reports": int(health.get("total_reports", 0) or 0),
                "unresolved_reports": int(health.get("unresolved_reports", 0) or 0),
                "reviewed_reports": int(health.get("reviewed_reports", 0) or 0),
                "latest_report_utc": health.get("latest_report_utc"),
            },
            "top_risky_ips": top_ips,
            "top_attack_indicators": top_indicators,
            "top_mitre_techniques": top_techniques,
        }

    async def get_graph_lateral_movement_paths(self, payload: GraphLateralMovementInput) -> dict[str, Any]:
        driver = self._graph_db_manager.get_driver()
        path_query = """
        MATCH (src:IPAddress {address: $source_ip})<-[:FROM_IP]-(r1:ThreatReport)-[:HAS_INDICATOR]->(i:AttackIndicator)
              <-[:HAS_INDICATOR]-(r2:ThreatReport)-[:FROM_IP]->(peer:IPAddress)
        WHERE peer.address <> $source_ip
          AND r1.created_at_utc >= datetime() - duration({hours: $lookback_hours})
          AND r2.created_at_utc >= datetime() - duration({hours: $lookback_hours})
          AND ($client_id IS NULL OR r1.client_id = $client_id)
          AND ($client_id IS NULL OR r2.client_id = $client_id)
        OPTIONAL MATCH (r2)-[:USES_TECHNIQUE]->(tech:MitreTechnique)
        RETURN peer.address AS peer_ip,
               collect(DISTINCT i.name)[0..8] AS shared_indicators,
               count(DISTINCT i.name) AS shared_indicator_count,
               collect(DISTINCT tech.name)[0..8] AS related_techniques,
               max(r2.threat_score) AS max_peer_threat_score,
               count(DISTINCT r2.report_id) AS peer_reports
        ORDER BY shared_indicator_count DESC, max_peer_threat_score DESC, peer_reports DESC
        LIMIT $limit_paths
        """
        async with driver.session(database=server_settings.neo4j_database) as session:
            result = await session.run(
                path_query,
                {
                    "source_ip": payload.source_ip,
                    "client_id": payload.client_id,
                    "lookback_hours": payload.lookback_hours,
                    "limit_paths": payload.limit_paths,
                },
            )
            rows = [row.data() async for row in result]

        high_risk_peers = sum(
            1 for row in rows if (row.get("max_peer_threat_score") or 0) >= 60
        )
        return {
            "context_type": "graph_lateral_movement_paths",
            "source_ip": payload.source_ip,
            "client_id_filter": payload.client_id,
            "lookback_hours": payload.lookback_hours,
            "summary": {
                "candidate_paths": len(rows),
                "high_risk_peers": high_risk_peers,
            },
            "paths": rows,
        }

    async def get_graph_mitre_context(self, payload: GraphMitreContextInput) -> dict[str, Any]:
        driver = self._graph_db_manager.get_driver()
        params = {
            "client_id": payload.client_id,
            "lookback_hours": payload.lookback_hours,
            "tactic": payload.tactic,
            "technique": payload.technique,
            "limit_items": payload.limit_items,
        }
        mitre_query = """
        MATCH (report:ThreatReport)
        WHERE report.created_at_utc >= datetime() - duration({hours: $lookback_hours})
          AND ($client_id IS NULL OR report.client_id = $client_id)
        OPTIONAL MATCH (report)-[:USES_TACTIC]->(t:MitreTactic)
        OPTIONAL MATCH (report)-[:USES_TECHNIQUE]->(tech:MitreTechnique)
        WITH report, t, tech
        WHERE ($tactic IS NULL OR toLower(t.name) CONTAINS toLower($tactic))
          AND ($technique IS NULL OR toLower(tech.name) CONTAINS toLower($technique))
        RETURN t.name AS tactic,
               tech.name AS technique,
               count(DISTINCT report.report_id) AS report_count,
               count(DISTINCT report.source_ip) AS affected_ips,
               avg(report.threat_score) AS avg_threat_score,
               max(report.threat_score) AS max_threat_score,
               collect(DISTINCT report.source_ip)[0..8] AS sample_ips
        ORDER BY report_count DESC, affected_ips DESC, max_threat_score DESC
        LIMIT $limit_items
        """
        kill_chain_query = """
        MATCH (report:ThreatReport)
        WHERE report.created_at_utc >= datetime() - duration({hours: $lookback_hours})
          AND ($client_id IS NULL OR report.client_id = $client_id)
          AND report.kill_chain_phase IS NOT NULL
        RETURN report.kill_chain_phase AS phase,
               count(*) AS count
        ORDER BY count DESC
        LIMIT $limit_items
        """
        async with driver.session(database=server_settings.neo4j_database) as session:
            mitre_result = await session.run(mitre_query, params)
            kill_chain_result = await session.run(kill_chain_query, params)
            mitre_rows = [row.data() async for row in mitre_result]
            kill_chain_rows = [row.data() async for row in kill_chain_result]

        return {
            "context_type": "graph_mitre_context",
            "client_id_filter": payload.client_id,
            "lookback_hours": payload.lookback_hours,
            "tactic_filter": payload.tactic,
            "technique_filter": payload.technique,
            "mitre_activity": mitre_rows,
            "kill_chain_distribution": kill_chain_rows,
        }

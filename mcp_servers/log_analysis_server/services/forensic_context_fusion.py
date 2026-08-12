"""Cross-store forensic context fusion for SOC agents (Mongo + Neo4j)."""

from __future__ import annotations

from typing import Any

from mcp_servers.log_analysis_server.models.threat_tools import (
    AttackGraphContextInput,
    PotentialThreatAnalysisInput,
    UnifiedForensicContextInput,
)
from mcp_servers.log_analysis_server.services.graph_threat_queries import GraphThreatQueriesService
from mcp_servers.log_analysis_server.services.threat_queries import ThreatQueriesService

_SEVERITY_RANK = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}
_SEVERITY_FROM_RANK = {
    0: "NONE",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
}


class ForensicContextFusionService:
    """Builds an opinionated, high-signal context payload for incident triage agents."""

    def __init__(
        self,
        threat_queries_service: ThreatQueriesService,
        graph_threat_queries_service: GraphThreatQueriesService,
    ) -> None:
        self._threat_queries_service = threat_queries_service
        self._graph_threat_queries_service = graph_threat_queries_service

    async def get_unified_forensic_context(self, payload: UnifiedForensicContextInput) -> dict[str, Any]:
        mongo_analysis = await self._threat_queries_service.analyze_potential_threat(
            PotentialThreatAnalysisInput(
                source_ip=payload.source_ip,
                source_id=payload.source_id,
                window_id=payload.window_id,
                client_id=payload.client_id,
                query_text=payload.query_text,
                limit_raw_events=payload.limit_raw_events,
                limit_reports=payload.limit_reports,
            )
        )
        graph_context = await self._graph_threat_queries_service.get_source_attack_context(
            AttackGraphContextInput(
                source_ip=payload.source_ip,
                client_id=payload.client_id,
                lookback_hours=payload.lookback_hours,
                limit_events=payload.limit_raw_events,
                limit_reports=payload.limit_reports,
            )
        )
        return self._build_unified_payload(payload, mongo_analysis, graph_context)

    def _build_unified_payload(
        self,
        payload: UnifiedForensicContextInput,
        mongo_analysis: dict[str, Any],
        graph_context: dict[str, Any],
    ) -> dict[str, Any]:
        mongo_level = str(mongo_analysis.get("threat_level", "NONE")).upper()
        mongo_score = int(mongo_analysis.get("threat_score", 0) or 0)
        graph_summary = graph_context.get("summary", {})
        lateral_candidates = graph_context.get("lateral_movement_candidates", []) or []
        unresolved_reports = int(graph_summary.get("unresolved_reports", 0) or 0)
        suspicious_events = int(graph_summary.get("suspicious_events", 0) or 0)
        total_events = int(graph_summary.get("total_events", 0) or 0)
        suspicious_ratio = (suspicious_events / total_events) if total_events else 0.0
        risk_boost = 0
        rationale: list[str] = []

        if lateral_candidates:
            risk_boost += 15
            rationale.append("Graph correlation detected lateral movement candidates sharing attack indicators.")
        if unresolved_reports > 0:
            risk_boost += 10
            rationale.append("Open unresolved threat reports remain associated with the source.")
        if suspicious_ratio >= 0.4 and total_events >= 20:
            risk_boost += 10
            rationale.append("A high ratio of suspicious graph events was observed.")
        if graph_summary.get("mitre_techniques"):
            risk_boost += 5
            rationale.append("MITRE technique mapping is present in related reports.")

        confidence_score = min(100, mongo_score + risk_boost)
        confidence_level = "LOW"
        if confidence_score >= 80:
            confidence_level = "VERY_HIGH"
        elif confidence_score >= 60:
            confidence_level = "HIGH"
        elif confidence_score >= 40:
            confidence_level = "MEDIUM"

        severity_rank = _SEVERITY_RANK.get(mongo_level, 0)
        if confidence_score >= 85:
            severity_rank = max(severity_rank, _SEVERITY_RANK["CRITICAL"])
        elif confidence_score >= 65:
            severity_rank = max(severity_rank, _SEVERITY_RANK["HIGH"])
        fused_level = _SEVERITY_FROM_RANK[severity_rank]

        attack_vectors = {
            "primary_indicators": graph_summary.get("top_indicators", []),
            "top_paths": graph_summary.get("top_paths", []),
            "top_status_codes": graph_summary.get("top_status_codes", []),
            "mitre_tactics": graph_summary.get("mitre_tactics", []),
            "mitre_techniques": graph_summary.get("mitre_techniques", []),
            "kill_chain_phases": graph_summary.get("kill_chain_phases", {}),
            "lateral_movement_candidates": lateral_candidates,
        }

        recommendations = mongo_analysis.get("recommended_actions", []) or []
        if lateral_candidates:
            recommendations = [
                "Hunt and contain peer source IPs linked by shared indicators before closing this incident.",
                *recommendations,
            ]

        response: dict[str, Any] = {
            "context_type": "unified_forensic_context",
            "input": {
                "source_ip": payload.source_ip,
                "client_id": payload.client_id,
                "source_id": payload.source_id,
                "window_id": payload.window_id,
                "lookback_hours": payload.lookback_hours,
            },
            "verdict": {
                "threat_detected": fused_level not in {"NONE", "LOW"},
                "threat_level": fused_level,
                "threat_score": confidence_score,
                "confidence_level": confidence_level,
                "confidence_score": confidence_score,
                "rationale": rationale,
            },
            "attack_vectors": attack_vectors,
            "containment_priorities": recommendations,
            "coverage": {
                "mongo_raw_events": int(mongo_analysis.get("summary", {}).get("total_raw_events", 0) or 0),
                "mongo_reports": int(mongo_analysis.get("summary", {}).get("total_reports", 0) or 0),
                "graph_events": total_events,
                "graph_reports": int(graph_summary.get("total_reports", 0) or 0),
            },
        }

        if payload.include_full_evidence:
            response["evidence"] = {
                "mongo_analysis": mongo_analysis,
                "graph_context": graph_context,
            }
        return response

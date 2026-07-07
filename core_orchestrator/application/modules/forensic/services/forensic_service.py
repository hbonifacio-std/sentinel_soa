"""Application service for forensic analysis workflows."""

from collections import Counter
from datetime import datetime, timezone
import logging
from typing import Any

from core_orchestrator.domain.models.forensic.forensic_analysis import (
    ForensicAnalyzeRequest,
    ForensicAnalysisRecord,
    ForensicHistoryQuery,
    ForensicHistoryResponse,
)
from core_orchestrator.domain.ports.forensic import (
    ForensicAnalysisRepositoryPort,
    ForensicIntelligencePort,
    ForensicServicePort,
)


logger = logging.getLogger(__name__)


class ForensicService(ForensicServicePort):
    """Coordinates forensic queries and report persistence."""

    def __init__(
        self,
        forensic_repository: ForensicAnalysisRepositoryPort,
        forensic_intelligence_port: ForensicIntelligencePort,
    ):
        self.forensic_repository = forensic_repository
        self.forensic_intelligence_port = forensic_intelligence_port

    async def analyze_activity(self, request: ForensicAnalyzeRequest) -> ForensicAnalysisRecord:
        query_plan = await self._build_query_plan(request)
        rows, total_matches = await self.forensic_repository.query_telemetry(
            request,
            query_filter=query_plan.get("mongo_filter"),
        )

        report_payload = await self._build_intelligence_report(request, total_matches, rows)
        highlights = self._safe_highlights(report_payload, rows, total_matches)
        markdown_report = str(
            report_payload.get("markdown_report")
            or self._build_markdown_report(request=request, total_matches=total_matches, rows=rows)
        )

        record = ForensicAnalysisRecord(
            analysis_id="",
            query=request.query,
            source_id=request.source_id,
            created_at_utc=datetime.now(timezone.utc),
            total_matches=total_matches,
            highlights=highlights,
            markdown_report=markdown_report,
            sample_results=rows,
        )

        analysis_id = await self.forensic_repository.save_analysis(record)
        return record.model_copy(update={"analysis_id": analysis_id})

    async def get_analysis_history(self, query: ForensicHistoryQuery) -> ForensicHistoryResponse:
        history = await self.forensic_repository.get_history(query)
        return ForensicHistoryResponse(**history)

    async def get_analysis_by_id(self, analysis_id: str) -> ForensicAnalysisRecord | None:
        return await self.forensic_repository.get_analysis_by_id(analysis_id)

    async def _build_query_plan(self, request: ForensicAnalyzeRequest) -> dict[str, Any]:
        try:
            plan = await self.forensic_intelligence_port.generate_mongo_query_from_nl(
                query=request.query,
                source_id=request.source_id,
            )
            if isinstance(plan, dict) and isinstance(plan.get("mongo_filter"), dict):
                return plan
            logger.warning("MCP forensic NLQ returned payload without mongo_filter; using fallback query plan")
            return {"mongo_filter": {}}
        except Exception as exc:
            logger.warning("MCP forensic NLQ unavailable, using fallback query plan: %s", exc)
            return {"mongo_filter": {}}

    async def _build_intelligence_report(
        self,
        forensic_analyzer_request: ForensicAnalyzeRequest,
        total_matches: int,
        rows: list[dict[str, Any]],
    ) -> dict[str, Any]:
        try:
            payload = await self.forensic_intelligence_port.generate_forensic_report_from_logs(
                query=forensic_analyzer_request.query,
                source_id=forensic_analyzer_request.source_id,
                total_matches=total_matches,
                rows=rows,
            )
            if isinstance(payload, dict) and payload:
                return payload
            logger.warning("MCP forensic report returned empty/invalid payload; using local markdown fallback")
            return {}
        except Exception as exc:
            logger.warning("MCP forensic report unavailable, using local markdown fallback: %s", exc)
            return {}

    def _safe_highlights(self, report_payload: dict[str, Any], rows: list[dict[str, Any]], total_matches: int) -> list[str]:
        raw_highlights = report_payload.get("highlights")
        if isinstance(raw_highlights, list):
            normalized = [str(item).strip() for item in raw_highlights if str(item).strip()]
            if normalized:
                return normalized[:10]
        return self._build_highlights(rows=rows, total_matches=total_matches)

    def _build_highlights(self, rows: list[dict], total_matches: int) -> list[str]:
        if total_matches == 0:
            return ["No se encontraron coincidencias para la consulta indicada."]

        ip_counter = Counter(str(row.get("source_ip", "N/A")) for row in rows if row.get("source_ip"))
        status_counter = Counter(int(row.get("response_code", 0)) for row in rows if row.get("response_code") is not None)

        highlights: list[str] = [f"Se detectaron {total_matches} eventos coincidentes."]
        if ip_counter:
            top_ip, top_count = ip_counter.most_common(1)[0]
            highlights.append(f"IP dominante: {top_ip} ({top_count} eventos).")
        if status_counter:
            top_status, status_count = status_counter.most_common(1)[0]
            highlights.append(f"Codigo HTTP mas frecuente: {top_status} ({status_count} eventos).")

        return highlights

    def _build_markdown_report(self, request: ForensicAnalyzeRequest, total_matches: int, rows: list[dict]) -> str:
        lines = [
            "# Reporte Forense",
            "",
            f"- Consulta: `{request.query}`",
            f"- Fuente: `{request.source_id or 'todas'}`",
            f"- Coincidencias totales: **{total_matches}**",
            "",
            "## Hallazgos rapidos",
        ]

        for highlight in self._build_highlights(rows=rows, total_matches=total_matches):
            lines.append(f"- {highlight}")

        lines.extend(["", "## Muestras de eventos", ""])

        if not rows:
            lines.append("Sin muestras disponibles.")
            return "\n".join(lines)

        for event in rows[:10]:
            timestamp = event.get("timestamp") or event.get("created_at_utc") or "N/A"
            source_ip = event.get("source_ip") or "N/A"
            method = event.get("http_method") or "N/A"
            path = event.get("request_uri") or "/"
            status_code = event.get("response_code")
            status_label = status_code if status_code is not None else "N/A"
            lines.append(f"- `{timestamp}` {source_ip} {method} {path} -> {status_label}")

        return "\n".join(lines)

import logging
from typing import Optional, Dict, Any, List

from core_orchestrator.domain.models.analysis_report import AnalysisReportResponse
from core_orchestrator.domain.models.log_event import LogEvent
from core_orchestrator.domain.ports.telemetry_repository import TelemetryRepository

logger = logging.getLogger(__name__)


class TelemetryService:
    def __init__(self, repository: TelemetryRepository):
        self.repo = repository

    # ------------------------------------------------------------------
    # 1. LOG EVENTS & TELEMETRÍA CRUDA
    # ------------------------------------------------------------------

    async def ingest_log_event(self, log_event: LogEvent) -> str:
        """
        Ingesta y almacena un evento único de telemetría de seguridad en el sistema.
        """
        # Consume el método mapeado al insert genérico
        return await self.repo.insert_log_event(log_event)

    async def ingest_bulk_logs(self, log_events: List[LogEvent]) -> int:
        """
        Ingesta masiva de registros en un único lote para optimizar viajes de red.
        """
        if not log_events:
            return 0
        return await self.repo.bulk_insert_log_events(log_events)

    async def get_telemetry_logs(
        self, query: Optional[Dict[str, Any]] = None, page: int = 1, limit: int = 10
    ) -> Dict[str, Any]:
        """
        Obtiene los logs de telemetría paginados listos para el Frontend.
        Estructura devuelta: { "info": PageInfo, "results": LogEvent[] }
        """
        return await self.repo.get_logs_paginated(query=query, page=page, limit=limit)

    # ------------------------------------------------------------------
    # 2. ANALYSIS REPORTS / ALERT CENTER
    # ------------------------------------------------------------------

    async def create_analysis_report(self, report: AnalysisReportResponse) -> str:
        """
        Registra un nuevo reporte analítico generado por el motor de IA
        dentro del Alert Center.
        """
        # Ejecuta la inserción desviada a la colección secundaria de reportes
        return await self.repo.insert_analysis_report(report)

    async def get_alert_center_reports(
        self, query: Optional[Dict[str, Any]] = None, page: int = 1, limit: int = 10
    ) -> list[AnalysisReportResponse]:
        """
        Consulta los reportes del Alert Center de forma paginada para la interfaz de usuario.
        Estructura devuelta: { "info": PageInfo, "results": AnalysisReportResponse[] }
        """
        return await self.repo.get_analysis_reports_paginated(query=query, page=page, limit=limit)

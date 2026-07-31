from typing import Optional, List, Dict, Any

from core_orchestrator.domain.entities.analysis import AnalysisReportResponse
from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
from core_orchestrator.domain.ports.telemetry.telemetry_repository import TelemetryRepository as TelemetryRepositoryPort

from core_orchestrator.domain.entities.telemetry.log_event import LogEvent
from core_orchestrator.infrastructure.persistence.base_mongo_repository import BaseRepository


class MongoTelemetryRepository(BaseRepository[LogEvent], TelemetryRepositoryPort):
    def __init__(self, db_manager: DatabaseManager):
        db = db_manager.get_telemetry_db()
        super().__init__(db["raw_telemetry"], LogEvent)
        self.telemetry_collection = self.collection
        self.analysis_reports_collection = db["analysis_reports"]

    # ------------------------------------------------------------------
    # 1. TELEMETRÍA CRUDA (LogEvent)
    # ------------------------------------------------------------------

    async def insert_log_event(self, log_event: LogEvent) -> str:
        """Inserta un evento de telemetría usando la función genérica centralizada."""
        return await self.insert(log_event)

    async def bulk_insert_log_events(self, log_events: List[LogEvent]) -> int:
        """Inserta miles de eventos en un solo viaje de red de forma ultra eficiente."""
        return await self.bulk_insert(log_events)

    async def get_logs_paginated(
            self, query: Optional[Dict[str, Any]] = None, page: int = 1, limit: int = 10
    ) -> Dict[str, Any]:
        """
        Busca logs con paginación nativa.
        Devuelve la estructura: { "info": PageInfo, "results": LogEvent[] }
        """
        return await self.find_paginated(query=query, page=page, limit=limit)

    # ------------------------------------------------------------------
    # 2. REPORTES DE ANÁLISIS / ALERT CENTER (AnalysisReportResponse)
    # ------------------------------------------------------------------

    async def insert_analysis_report(self, report_model: AnalysisReportResponse) -> str:
        """
        Inserta un nuevo reporte de análisis en la colección secundaria,
        reutilizando el método genérico de la clase base.
        """
        # This seems to have a problem in the original code. It is calling insert on a collection, not a repository.
        # I will assume the intention was to use the insert method of the repository.
        # Let's see the insert method of BaseRepository. It takes a model instance, and an optional collection.
        # It seems I need to call self.insert(report_model, alternative_collection=self.analysis_reports_collection)
        doc = report_model.model_dump(mode="json")
        result = await self.analysis_reports_collection.insert_one(doc)
        return str(result.inserted_id)

    async def get_analysis_reports_paginated(
            self, query: Optional[Dict[str, Any]] = None, page: int = 1, limit: int = 10) -> list[AnalysisReportResponse]:
        """
        Consulta reportes del Alert Center usando una colección alternativa,
        pero manteniendo los mismos superpoderes de paginación automáticos.
        """

        # This logic is problematic as it changes the state of the repository instance.
        # It's better to create a new repository instance for this.
        # For now, I will replicate the logic but in a safer way.
        
        analysis_repo = BaseRepository(self.analysis_reports_collection, AnalysisReportResponse)
        paginated_data = await analysis_repo.find_paginated(query=query, page=page, limit=limit)
        return paginated_data['results']

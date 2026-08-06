from typing import Optional, List, Dict, Any

from core_orchestrator.domain.entities.telemetry.logs_event import LogEvent
from core_orchestrator.infrastructure.adapters.mongodb.responses import PaginatedResult
from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
from core_orchestrator.domain.ports.telemetry.telemetry_repository_port import TelemetryRepositoryPort as TelemetryRepositoryPort
from core_orchestrator.infrastructure.dto.telemetry.analysis_report_dto import AnalysisReportResponseDTO

from core_orchestrator.infrastructure.dto.telemetry.log_event_dto import LogEventDTO
from core_orchestrator.infrastructure.adapters.mongodb.base_mongo_adapter import BaseRepository


class MongoTelemetryAdapter(BaseRepository[LogEvent], TelemetryRepositoryPort):
    """
    Adapter class for a MongoDB-based telemetry repository.

    This class serves as an adapter implementing the TelemetryRepositoryPort interface
    and extends the base repository implementation. It provides functionalities for
    storing and retrieving log events and analysis reports in a MongoDB telemetry
    database.

    The class is designed to handle both single and bulk insertions of log events,
    as well as to retrieve data in a paginated format. It uses asynchronous
    database interactions and allows filtering based on query parameters.


    """
    def __init__(self, db_manager: DatabaseManager):
        db = db_manager.get_telemetry_db()
        super().__init__(db["raw_telemetry"], LogEvent)

    async def insert_log_event(self, log_event: LogEvent) -> str:
        """
        Insert a log event into the data store.

        This asynchronous method is responsible for adding a log event to the
        underlying data storage system. The log event should conform to the
        LogEvent type, which represents the event details to be recorded.

        Parameters:
        log_event: LogEvent
            The log event to be inserted into the data store.

        Returns:
        str
            The ID of the inserted log event as a string.
        """
        return await self.insert(log_event)

    async def bulk_insert_log_events(self, log_events: List[LogEvent]) -> int:
        """
        Asynchronously inserts multiple log events into the database.

        This method takes a list of log event data transfer objects and performs a
        bulk insertion operation into the database. It is designed for efficient
        handling of multiple log events simultaneously.

        Arguments:
            log_events: List of LogEvent
                A list of log event objects to be inserted into the database.

        Returns:
            int
                The number of log events successfully inserted into the database.

        Raises:
            Any exception encountered during the database insertion operation.
        """
        return await self.bulk_insert(log_events)

    async def get_logs_paginated(
            self, query: Optional[Dict[str, Any]] = None, page: int = 1, limit: int = 10
    ) -> PaginatedResult[LogEvent]:
        """
        Gets paginated logs based on the provided query parameters.

        This method retrieves logs in a paginated format, allowing for efficient handling
        of large datasets by specifying the page number and the number of items per page.
        You can also provide optional query parameters to filter the log results. The
        returned data is encapsulated in a PaginatedResult object, containing a collection of
        LogEvent objects.

        Args:
            query (Optional[Dict[str, Any]]): A dictionary containing key-value pairs
                to filter the logs. If None, no specific filter is applied
            page (int): The page number to retrieve. Defaults to 1
            limit (int): The maximum number of items to retrieve per page. Defaults to 10

        Returns:
            PaginatedResult[LogEvent]: A paginated result containing a subset of LogEvent objects
            matching the query parameters and pagination settings.

        Raises:
            None
        """
        return await self.find_paginated(query=query, page=page, limit=limit)


    async def insert_analysis_report(self, report_model: AnalysisReportResponseDTO) -> str:
        """
        Asynchronously inserts an analysis report into the database and returns the inserted document's ID.

        The method converts the provided analysis report model to a dictionary representation in
        JSON-compatible format before saving it to the `analysis_reports_collection`.

        Parameters:
            report_model (AnalysisReportResponseDTO): The model instance representing the analysis
                report to be inserted into the database.

        Returns:
            str: The ID of the newly inserted document.
        """

        doc = report_model.model_dump(mode="json")
        result = await self.insert(doc)
        return result

    async def get_analysis_reports_paginated(
            self, query: Optional[Dict[str, Any]] = None, page: int = 1, limit: int = 10) -> PaginatedResult[LogEvent]:
        """
        Retrieves paginated analysis reports based on the given query parameters.

        This asynchronous method fetches and returns a paginated result containing
        analysis reports filtered by the specified query, page, and limit.

        Parameters:
            query (Optional[Dict[str, Any]]): A dictionary containing query parameters
                to filter the analysis reports. Defaults to None
            page (int): The page number to retrieve. Defaults to 1
            limit (int): The maximum number of analysis reports to include on a single
                page. Defaults to 10

        Returns:
            PaginatedResult[LogEventDTO]: A paginated result containing the analysis
            reports matching the query criteria.
        """


        paginated_data = await self.find_paginated(query=query, page=page, limit=limit)
        return paginated_data

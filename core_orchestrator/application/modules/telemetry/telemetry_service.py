import logging
from typing import Optional, Dict, Any, List

from core_orchestrator.domain.entities.telemetry.logs_event import LogEvent
from core_orchestrator.infrastructure.adapters.mongodb.responses import PaginatedResult
from core_orchestrator.infrastructure.dto.telemetry.analysis_report_dto import AnalysisReportResponseDTO
from core_orchestrator.infrastructure.dto.telemetry.log_event_dto import LogEventDTO
from core_orchestrator.domain.ports.telemetry.telemetry_repository_port import TelemetryRepositoryPort

logger = logging.getLogger(__name__)


class TelemetryService:
    """
    Handles telemetry services, including log ingestion, analysis reports,
    and generating paginated telemetry data.

    This class serves as middleware for managing telemetry operations such as storing
    individual or bulk log events, retrieving logs in a paginated format, storing analysis
    reports, and querying the Alert Center reports. The class interacts with a repository
    layer to perform these operations asynchronously.
    """
    def __init__(self, repository: TelemetryRepositoryPort):
        self.repo = repository

    async def ingest_log_event(self, log_event: LogEventDTO) -> str:
        """
        Asynchronously ingests a log event by inserting it into the repository.

        This method ensures that the provided log event is consumed and saved to the
        designated repository for storage and further processing.

        Parameters:
        log_event (LogEventDTO): The data transfer object representing the log event
        to be ingested.

        Returns:
        str: A string indicating the result of the insertion operation.

        """

        return await self.repo.insert_log_event(log_event)

    async def ingest_bulk_logs(self, log_events: List[LogEvent]) -> int:
        """
        Asynchronously inserts a batch of log events into the repository.

        This method takes a list of log events and processes them in bulk for
        insertion into the associated data repository. If the provided list
        is empty, no operations are performed, and a count of `0` is returned.
        Otherwise, the method delegates the bulk insertion to the repository
        and returns the number of successfully processed events.

        Parameters:
            log_events (List[LogEventDTO]): A list of log event data transfer
            objects to be ingested.

        Returns:
            int: The number of log events that were successfully inserted.
        """
        if not log_events:
            return 0
        return await self.repo.bulk_insert_log_events(log_events)

    async def get_telemetry_logs(
        self, query: Optional[Dict[str, Any]] = None, page: int = 1, limit: int = 10
    ) -> PaginatedResult[LogEvent]:
        """
        Fetch telemetry logs with an optional query and pagination.

        This asynchronous method retrieves telemetry logs based on the provided query
        parameters and supports pagination to limit the number of results per request.
        It interacts with the underlying repository to fetch filtered and paginated logs.

        Parameters:
        query (Optional[Dict[str, Any]]): A dictionary containing query parameters to
            filter the telemetry logs. If None, no filtering is applied
        page (int): The page number to retrieve. Defaults to 1
        limit (int): The maximum number of logs per page. Defaults to 10

        Returns:
        Dict[str, Any]: A dictionary containing the paginated telemetry logs.

        Raises:
        Any exception raised by the underlying repository layer when fetching
        the logs.
        """
        return await self.repo.get_logs_paginated(query=query, page=page, limit=limit)


    async def create_analysis_report(self, report: AnalysisReportResponseDTO) -> str:
        """
        Asynchronously creates and stores an analysis report.

        This method performs an insertion of the given analysis report into the
        appropriate secondary collection for reports. It ensures the process
        is executed asynchronously for better performance and scalability.

        Args:
            report (AnalysisReportResponseDTO): The analysis report data to
            be inserted into the designated collection.

        Returns:
            str: The ID of the newly inserted analysis report.
        """
        return await self.repo.insert_analysis_report(report)

    async def get_alert_center_reports(
        self, query: Optional[Dict[str, Any]] = None, page: int = 1, limit: int = 10
    ) -> list[AnalysisReportResponseDTO]:
        """
        Retrieve a paginated list of alert center reports based on the query parameters.

        This method interacts with the repository layer to fetch paginated analysis reports. It allows
        optional query parameters for filtering the reports and provides pagination support through
        the page and limit parameters.

        Parameters:
            query (Optional[Dict[str, Any]]): A dictionary containing filtering criteria for the
                reports. If not provided, all reports will be retrieved
            page (int): The page number to fetch. Defaults to 1
            limit (int): The maximum number of reports to return in a single page. Defaults to 10.

        Returns:
            list[AnalysisReportResponseDTO]: A list of AnalysisReportResponseDTO objects representing
            the fetched alert center reports.

        Raises:
            This method does not explicitly raise exceptions but may pass through exceptions raised
            by the repository layer or other underlying operations.
        """
        return await self.repo.get_analysis_reports_paginated(query=query, page=page, limit=limit)


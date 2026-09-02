import logging
from typing import Annotated
from fastapi import APIRouter, Depends, Query
from core_orchestrator.application.modules.telemetry.telemetry_report_service import (TelemetryReportService)
from core_orchestrator.application.modules.telemetry.telemetry_service import TelemetryService
from core_orchestrator.domain.entities.auth.user import UserInDB
from core_orchestrator.infrastructure.api.dependencies.general_dependencies import get_analytics_service, get_telemetry_service
from core_orchestrator.infrastructure.api.dependencies.user_auth import get_analyst_user_with_client
from core_orchestrator.infrastructure.dto.responses import ResponsePaginatedDTO
from core_orchestrator.infrastructure.dto.telemetry.analysis_report_dto import AnalysisReportResponseDTO, \
    ReportActionRequestDTO
from core_orchestrator.infrastructure.dto.telemetry.log_event_dto import LogEventDTO
from core_orchestrator.infrastructure.mappers.mappers import analysis_report_mapper, log_event_mapper

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/analytics/logs_row_telemetry",response_model=ResponsePaginatedDTO[LogEventDTO])
async def get_logs_row_telemetry(
    source_id: Annotated[str,Query],
    telemetry_service:  Annotated[TelemetryService, Depends(get_telemetry_service)],
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
    limit: Annotated[int,Query(ge=1, le=100, description="Number of records per page (maximum 100)")]=100,
    page: Annotated[int, Query(ge=1,description="Page number (minimum 1)")]=1
):
    """
    Handles the retrieval of telemetry log data for a specific source ID with pagination support.

    This function is part of the telemetry analytics functionality, allowing authorized users to fetch
    log data associated with a particular telemetry source. The results are returned in a paginated
    format to enhance performance and usability. The current user's client ID is included in the query
    to restrict the logs retrieved to only those relevant to the user's client.

    Args:
        source_id (str): Unique identifier for the telemetry source
        telemetry_service (TelemetryService): Dependency providing access to the telemetry service
        current_user (UserInDB): Dependency providing details of the currently authenticated user
        limit (int, optional): Number of records to retrieve per page. Must be between 1 and 100. Defaults to 100
        page (int, optional): Page number of the results to retrieve. Must be at least 1. Defaults to 1

    Returns:
        ResponsePaginatedDTO[LogEventDTO]: A paginated list of telemetry log events.
    """
    paginated_data = await telemetry_service.get_telemetry_logs(
        page=page,
        limit=limit,
        query={"client_id": current_user.client_id,"source_id": source_id},
    )
    return log_event_mapper.to_paginated_dto(
                    entities=paginated_data.results,
                        info_paginated=paginated_data.info,
                        path="/analytics/logs_row_telemetry"
    )


@router.patch("/analytics/reports/{report_id}/review")
async def mark_report_reviewed(
        report_id: str,
        analytics_service: Annotated[TelemetryReportService, Depends(get_analytics_service)],
        current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)]
    ):
    """
    Marks a specific analytics report as reviewed.

    This function is used to mark an analytics report as reviewed by the current user.
    It fetches the report by ID and associates the review action with the
    user's client ID.

    Arguments:
        report_id (str): The unique identifier of the report to be marked as reviewed
        analytics_service (TelemetryReportService): A service dependency for handling analytics operations
        current_user (UserInDB): The current authenticated user, with access to their client ID

    Returns:
        Response: The result of the review marking operation, as returned by the analytics service.
    """
    return await analytics_service.mark_report_as_reviewed(report_id, current_user.client_id)


@router.post("/analytics/reports/{report_id}/actions")
async def add_report_action(
        report_id: str,
        action_request: ReportActionRequestDTO,
        analytics_service: Annotated[TelemetryReportService, Depends(get_analytics_service)],
        current_user:  Annotated[UserInDB, Depends(get_analyst_user_with_client)]
):
    """
    Handle an HTTP POST request to add an action to a specific analytics report.

    This endpoint allows users to associate an action with a report by providing the
    report ID and action details. The user must be authenticated and have the proper
    permissions to access and modify the specified report.

    Arguments:
        report_id (str): The unique identifier of the report to which the action will be added
        action_request (ReportActionRequestDTO): The details of the action being added,
            encapsulated in a request object
        analytics_service (TelemetryReportService): A service dependency for handling
            analytics-related operations
        current_user (UserInDB): The currently authenticated user, provided by a dependency.

    Returns:
        Report: The updated report object after the action has been added.
    """

    report = await analytics_service.add_action_to_report(
            report_id,
            current_user.client_id,
            action_request.model_dump(),
    )
    return report



@router.patch("/analytics/reports/{report_id}/resolve")
async def mark_report_resolved(
        report_id: str,
        analytics_service: Annotated[TelemetryReportService, Depends(get_analytics_service)],
        current_user:  Annotated[UserInDB, Depends(get_analyst_user_with_client)]
):
    """
    Marks a specific analytics report as resolved.

    The endpoint is designed for analysts with client association to mark a report
    as resolved. It requires the report ID"""
    return await analytics_service.mark_report_as_resolved(report_id, current_user.client_id)



@router.get("/analytics/source_ids")
async def get_source_ids(
        analytics_service: Annotated[TelemetryReportService, Depends(get_analytics_service)],
        current_user: Annotated[UserInDB,Depends(get_analyst_user_with_client)],
):
    """
    Handles the retrieval of distinct source IDs for a given client.

    This function is used to fetch all unique source IDs associated with the client of the
    current user. It interacts with an analytics service to perform this operation.

    Parameters:
    analytics_service (ReportTelemetryService): The analytics service dependency used to
        interact with telemetry data
    current_user (UserInDB): The current authenticated user's details, including their
        associated client ID.

    Returns:
    list: A list of distinct source IDs for the client's telemetry data.
    """
    source_ids = await analytics_service.get_distinct_source_ids(current_user.client_id)
    return source_ids


@router.get("/analytics/reports", response_model=ResponsePaginatedDTO[AnalysisReportResponseDTO])
async def get_reports(
        analytics_service: Annotated[TelemetryReportService, Depends(get_analytics_service)],
        current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
        source_id: str | None = None,
        page: Annotated[int, Query(ge=1, description="Page number (minimum 1)")]=1,
        limit: Annotated[int, Query(ge=1, le=100, description="Number of reports per page (maximum 100)")]=10,
):
    """
    Handles the retrieval of paginated analysis reports from the analytics service.

    This endpoint fetches a list of analysis reports with pagination and optional filtering
    based on the specified `source_id`. The results are constrained by the page number
    and the limit of reports per page. The endpoint leverages the current authenticated user's
    client information to ensure that only the reports associated with the applicable client
    are retrieved.

    Parameters:
        analytics_service: Dependency-injected instance of ReportTelemetryService responsible
                           for handling report analytics logic.
        current_user: The currently authenticated user and their associated client information.
        source_id: Optional ID of the source to filter the reports.
        page: Page number for the paginated response. Must be greater than or equal to 1.
        limit: Maximum number of reports per page. Must be between 1 and 100 (inclusive).

    Returns:
        A ResponsePaginatedDTO object containing a paginated list of analysis report response
        DTOs and accompanying"""
    paginated_data = await analytics_service.get_paginated_reports(
        page=page,
        limit=limit,
        source_id=source_id,
        client_id=current_user.client_id,
    )
    return analysis_report_mapper.to_paginated_dto(
        entities=paginated_data.results,
        info_paginated=paginated_data.info,
        path="/analytics/reports"
    )


@router.get("/analytics/stats")
async def get_stats(
        source_id: str,
        analytics_service: Annotated[TelemetryReportService, Depends(get_analytics_service)],
        current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
):
    """
    Endpoint to retrieve aggregated analytics statistics for a specified source.

    This function handles a GET request to the "/analytics/stats" endpoint. It retrieves
    aggregated statistics related to the analytics data source specified by the given
    source ID. The data is fetched by using the injected analytics service, and it
    also validates the request based on the authenticated current user with the role
    of an analyst tied to a specific client. The resultant statistics are returned
    to the caller.

    Parameters:
        source_id: str
            The identifier for the analytics data source for which statistics need to be retrieved.
        analytics_service: ReportTelemetryService
            An instance of the service used for performing analytical computations and
            retrieving aggregated data.
        current_user: UserInDB
            The current authenticated user object, containing client-specific context required
            for querying analytics data.

    Returns:
        dict
            A dictionary containing the aggregated statistics for the requested source.
    """
    stats = await analytics_service.get_aggregated_stats(
        client_id=current_user.client_id,
        source_id=source_id,
    )
    return stats


@router.get("/analytics/debug_reports")
async def debug_reports(
        analytics_service: Annotated[TelemetryReportService, Depends(get_analytics_service)],
        current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)]
):
    """
    Gets the debug reports for the current user's client.

    This endpoint retrieves debug reports related to analytics, based on the
    client ID of the currently authenticated user.

    Arguments:
    - analytics_service: An instance of the ReportTelemetryService, provided as a
      dependency, is used to fetch debug reports.
    - current_user: The currently authenticated user's information, including
      client details, is provided as a dependency.

    Returns:
    - A list of debug reports associated with the current user's client.

    Raises:
    - HTTPException: If the user is not authenticated or authorized.
    """
    reports = await analytics_service.get_debug_reports(current_user.client_id)
    return reports

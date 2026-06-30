import logging
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query

from core_orchestrator.application.services.analytics_service import AnalyticsService
from core_orchestrator.infrastructure.api.dependencies import get_analytics_service
from core_orchestrator.infrastructure.security.dependencies import get_analyst_user

logger = logging.getLogger(__name__)

router = APIRouter()

# ============================================================================
# Endpoints de la API
# ============================================================================

@router.get("/analytics/logs_row_telemetry")
async def get_logs_row_telemetry(
    page: int = Query(default=1, ge=1, description="Número de la página (mínimo 1)"),
    limit: int = Query(default=10, ge=1, le=100, description="Cantidad de registros por página (máximo 100)"),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
    _: None = Depends(get_analyst_user)
):
    """
    Get paginated raw telemetry logs.
    """
    paginated_data = await analytics_service.get_paginated_logs(page=page, limit=limit)

    info = paginated_data.get("info", {})
    total_records = info.get("total_records", 0)
    skip = (page - 1) * limit

    return {
        "info": {
            "total_records": total_records,
            "page": page,
            "limit": limit,
            "next_page": f"/analytics/logs_row_telemetry?page={page + 1}&limit={limit}" if (skip + limit) < total_records else None,
            "prev_page": f"/analytics/logs_row_telemetry?page={page - 1}&limit={limit}" if page > 1 else None
        },
        "results": paginated_data.get("results", [])
    }


@router.patch("/analytics/reports/{report_id}/review")
async def mark_report_reviewed(
        report_id: str,
        analytics_service: AnalyticsService = Depends(get_analytics_service),
        _: None = Depends(get_analyst_user)
):
    report = await analytics_service.mark_report_as_reviewed(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return report


@router.post("/analytics/reports/{report_id}/actions")
async def add_report_action(
        report_id: str,
        action_request: Dict[str, Any],
        analytics_service: AnalyticsService = Depends(get_analytics_service),
        _: None = Depends(get_analyst_user)
):
    try:
        report = await analytics_service.add_action_to_report(report_id, action_request)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        return report
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.patch("/analytics/reports/{report_id}/resolve")
async def mark_report_resolved(
        report_id: str,
        analytics_service: AnalyticsService = Depends(get_analytics_service),
        _: None = Depends(get_analyst_user)
):
    report = await analytics_service.mark_report_as_resolved(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return report


@router.get("/analytics/source_ids")
async def get_source_ids(
        analytics_service: AnalyticsService = Depends(get_analytics_service),
        _: None = Depends(get_analyst_user)
):
    """
    Get a list of all unique source_ids from the analysis_reports collection.
    """
    source_ids = await analytics_service.get_distinct_source_ids()
    return source_ids


@router.get("/analytics/reports")
async def get_reports(
        source_id: str | None = None,
        page: int = Query(default=1, ge=1, description="Numero de pagina (minimo 1)"),
        limit: int = Query(default=10, ge=1, le=100, description="Cantidad de reportes por pagina (maximo 100)"),
        analytics_service: AnalyticsService = Depends(get_analytics_service),
        _: None = Depends(get_analyst_user)
):
    """
    Get analysis reports, optionally filtered by source_id and time_range.
    """
    paginated_data = await analytics_service.get_paginated_reports(
        page=page, limit=limit, source_id=source_id
    )

    info = paginated_data.get("info", {})
    total_records = info.get("total_records", 0)
    skip = (page - 1) * limit

    return {
        "info": {
            "total_records": total_records,
            "page": page,
            "limit": limit,
            "next_page": f"/analytics/reports?page={page + 1}&limit={limit}" if (skip + limit) < total_records else None,
            "prev_page": f"/analytics/reports?page={page - 1}&limit={limit}" if page > 1 else None,
        },
        "results": paginated_data.get("results", []),
    }


@router.get("/analytics/stats")
async def get_stats(
        source_id: str = None,
        analytics_service: AnalyticsService = Depends(get_analytics_service),
        _: None = Depends(get_analyst_user)
):
    """
    Get aggregated statistics, optionally filtered by source_id and time_range.
    """
    stats = await analytics_service.get_aggregated_stats(source_id=source_id)
    return stats


@router.get("/analytics/debug_reports")
async def debug_reports(
        analytics_service: AnalyticsService = Depends(get_analytics_service),
        _: None = Depends(get_analyst_user)
):
    """
    Debug endpoint to get a few sample documents from the analysis_reports collection.
    """
    reports = await analytics_service.get_debug_reports()
    return reports

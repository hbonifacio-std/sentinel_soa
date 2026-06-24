from fastapi import APIRouter, HTTPException, Query, Request

from core_orchestrator.services.limiter import limiter
from ....services.database import db
from datetime import datetime, timezone
from ....models.feedback import ActionRequest, AlertWorkflowResponse, ActionEntry
from bson.objectid import ObjectId

router = APIRouter()

def serialize_timestamp(value, fallback: str | None = None) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str) and value.strip():
        return value
    return fallback

def resolve_report_created_at(report: dict) -> str:
    """Extracts or derives created_at_utc from a report document, falling back to ObjectId generation time."""
    created_at = report.get("created_at_utc")
    if created_at:
        if isinstance(created_at, datetime):
            return created_at.isoformat()
        return str(created_at)
    
    object_id_value = report.get("_id")
    if object_id_value:
        try:
            if isinstance(object_id_value, str) and ObjectId.is_valid(object_id_value):
                return ObjectId(object_id_value).generation_time.isoformat()
            elif isinstance(object_id_value, ObjectId):
                return object_id_value.generation_time.isoformat()
        except Exception:
            pass
            
    return datetime.now(timezone.utc).isoformat()

def get_reports_collection():
    return db.get_app_db().analysis_reports

def get_raw_telemetry_collection():
    return db.get_app_db().raw_telemetry

def parse_report_object_id(report_id: str) -> ObjectId:
    try:
        return ObjectId(report_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid report_id format")


def normalize_actions(actions: list) -> list[dict]:
    normalized: list[dict] = []
    for action in actions or []:
        if isinstance(action, str):
            normalized.append({"comment": action, "created_at_utc": datetime.now(timezone.utc).isoformat()})
            continue

        if not isinstance(action, dict):
            continue

        comment = str(action.get("comment", "")).strip()
        timestamp = action.get("timestamp") or action.get("created_at_utc")
        normalized.append({
            "comment": comment,
            "created_at_utc": timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp,
        })

    return normalized


def build_workflow_response(report: dict) -> AlertWorkflowResponse:
    actions = [
        ActionEntry(
            comment=entry["comment"],
            created_at_utc=entry["created_at_utc"],
        )
        for entry in normalize_actions(report.get("actions", []))
        if entry.get("comment") and entry.get("created_at_utc")
    ]

    return AlertWorkflowResponse(
        report_id=str(report["_id"]),
        reviewed=bool(report.get("reviewed", False)),
        resolved=bool(report.get("resolved", False)),
        actions=actions,
    )


@router.get("/analytics/logs_row_telemetry")
@limiter.limit("5/minute")
async def get_logs_row_telemetry(
        request: Request,
        page: int = Query(default=1, ge=1, description="Número de la página (mínimo 1)"),
        limit: int = Query(default=10, ge=1, le=100, description="Cantidad de registros por página (máximo 100)")
):
    collection = get_raw_telemetry_collection()

    # Calcular cuántos documentos saltar
    skip = (page - 1) * limit

    # 1. Obtener los datos paginados
    cursor = collection.find({}, {"_id": 0}).skip(skip).limit(limit)
    logs = await cursor.to_list(length=limit)

    # 2. (Opcional pero recomendado) Contar el total de documentos para el frontend
    total_records = await collection.count_documents({})

    return {
        "info": {
            "total_records": total_records,
            "page": page,
            "limit": limit,
            "next_page": f"/analytics/logs_row_telemetry?page={page + 1}&limit={limit}" if (skip + limit) < total_records else None,
            "prev_page": f"/analytics/logs_row_telemetry?page={page - 1}&limit={limit}" if page > 1 else None
        },
        "results": logs
    }

@router.patch("/analytics/reports/{report_id}/review", response_model=AlertWorkflowResponse)
async def mark_report_reviewed(report_id: str):
    collection = get_reports_collection()
    report_object_id = parse_report_object_id(report_id)

    update_result = await collection.update_one(
        {"_id": report_object_id},
        {"$set": {"reviewed": True}}
    )

    if update_result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Report not found")

    report = await collection.find_one({"_id": report_object_id})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return build_workflow_response(report)


@router.post("/analytics/reports/{report_id}/actions", response_model=AlertWorkflowResponse)
async def add_report_action(report_id: str, request: ActionRequest):
    collection = get_reports_collection()
    report_object_id = parse_report_object_id(report_id)

    report = await collection.find_one({"_id": report_object_id})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if bool(report.get("resolved", False)):
        raise HTTPException(status_code=409, detail="Report is resolved. No more actions can be added")

    if not bool(report.get("reviewed", False)):
        raise HTTPException(status_code=409, detail="Report must be reviewed before adding actions")

    await collection.update_one(
        {"_id": report_object_id},
        {
            "$push": {
                "actions": {
                    "comment": request.comment.strip(),
                    "timestamp": datetime.now(timezone.utc),
                }
            }
        }
    )

    updated_report = await collection.find_one({"_id": report_object_id})
    if not updated_report:
        raise HTTPException(status_code=404, detail="Report not found")

    return build_workflow_response(updated_report)


@router.patch("/analytics/reports/{report_id}/resolve", response_model=AlertWorkflowResponse)
async def mark_report_resolved(report_id: str):
    collection = get_reports_collection()
    report_object_id = parse_report_object_id(report_id)

    update_result = await collection.update_one(
        {"_id": report_object_id},
        {
            "$set": {
                "reviewed": True,
                "resolved": True,
                "resolved_at_utc": datetime.now(timezone.utc),
            }
        }
    )

    if update_result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Report not found")

    report = await collection.find_one({"_id": report_object_id})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return build_workflow_response(report)


@router.get("/analytics/source_ids")
async def get_source_ids():
    """
    Get a list of all unique source_ids from the analysis_reports collection.
    """
    collection = get_reports_collection()
    source_ids = await collection.distinct("source_id")
    return source_ids

@router.get("/analytics/reports", response_model=dict)
@limiter.limit("5/minute")
async def get_reports(
    request: Request,
    source_id: str | None = None,
    time_range: str | None = None,
    page: int = Query(default=1, ge=1, description="Numero de pagina (minimo 1)"),
    limit: int = Query(default=10, ge=1, le=100, description="Cantidad de reportes por pagina (maximo 100)"),
):
    """
    Get analysis reports, optionally filtered by source_id and time_range.
    """
    query = {}
    if source_id:
        query["source_id"] = source_id
    # TODO: Implement time_range filtering
    
    collection = get_reports_collection()
    skip = (page - 1) * limit
    total_records = await collection.count_documents(query)
    reports_cursor = collection.find(query).sort("_id", -1).skip(skip).limit(limit)
    reports = await reports_cursor.to_list(length=limit)
    
    # Convert ObjectId to string for JSON serialization
    for report in reports:
        if "_id" in report and isinstance(report["_id"], ObjectId):
            report["_id"] = str(report["_id"])

        fallback_created_at = None
        object_id_value = report.get("_id")
        if isinstance(object_id_value, str) and ObjectId.is_valid(object_id_value):
            fallback_created_at = ObjectId(object_id_value).generation_time.isoformat()

        report["created_at_utc"] = serialize_timestamp(report.get("created_at_utc"), fallback_created_at)
        report["resolved_at_utc"] = serialize_timestamp(report.get("resolved_at_utc"))

        report["reviewed"] = bool(report.get("reviewed", False))
        report["resolved"] = bool(report.get("resolved", False))
        report["actions"] = normalize_actions(report.get("actions", []))
            
    return {
        "info": {
            "total_records": total_records,
            "page": page,
            "limit": limit,
            "next_page": f"/analytics/reports?page={page + 1}&limit={limit}" if (skip + limit) < total_records else None,
            "prev_page": f"/analytics/reports?page={page - 1}&limit={limit}" if page > 1 else None,
        },
        "results": reports,
    }

@router.get("/analytics/stats")
async def get_stats(source_id: str = None, time_range: str = None):
    """
    Get aggregated statistics, optionally filtered by source_id and time_range.
    """
    pipeline = []
    match_stage = {}
    if source_id:
        match_stage["source_id"] = source_id
    
    if match_stage:
        pipeline.append({"$match": match_stage})

    # TODO: Implement time_range filtering

    facet_stage = {
        "$facet": {
            "threat_levels": [{"$group": {"_id": "$threat_level", "count": {"$sum": 1}}}],
            "kill_chain_phases": [{"$group": {"_id": "$kill_chain_phase", "count": {"$sum": 1}}}],
            "top_attackers": [
                {"$match": {"threat_actor.ip_address": {"$ne": None}}},
                {"$group": {"_id": "$threat_actor.ip_address", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ]
        }
    }
    pipeline.append(facet_stage)
    
    collection = get_reports_collection()
    stats_cursor = await collection.aggregate(pipeline)
    stats = await stats_cursor.to_list(length=1)
    
    if stats and isinstance(stats[0], dict):
        for key in stats[0]:
            for item in stats[0][key]:
                if "_id" in item and isinstance(item["_id"], ObjectId):
                    item["_id"] = str(item["_id"])

    return stats[0] if stats else {}

@router.get("/analytics/debug_reports")
async def debug_reports():
    """
    Debug endpoint to get a few sample documents from the analysis_reports collection.
    """
    print("DEBUG: /analytics/debug_reports endpoint called.")
    collection = get_reports_collection()
    
    # Fetch the first 5 documents from the collection
    reports_cursor = collection.find({}).limit(5)
    reports = await reports_cursor.to_list(length=5)
    
    print(f"DEBUG: Found {len(reports)} sample documents.")

    # Convert ObjectId to string for JSON serialization
    for report in reports:
        if "_id" in report and isinstance(report["_id"], ObjectId):
            report["_id"] = str(report["_id"])
            
    return reports

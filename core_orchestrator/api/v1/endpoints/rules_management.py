"""
REST API endpoints for heuristic rules administration.

Provides CRUD, versioning, validation, audit log, and health endpoints
for managing threat detection rules stored in MongoDB with Redis cache.
"""


import logging
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Body, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from core_orchestrator.models.rule_schema import (
    HeuristicRule,
    HeuristicRuleUpdate,
    RuleVersion,
    hash_version,
)
from core_orchestrator.services.database import db
from core_orchestrator.services.limiter import limiter
from core_orchestrator.services.rule_validator import RuleValidator
from core_orchestrator.services.rules_engine import get_rules_engine

logger = logging.getLogger("core_orchestrator.api.rules")

router = APIRouter()


# ---------------------------------------------------------------------------
# Response / request schemas
# ---------------------------------------------------------------------------

class RulesListResponse(BaseModel):
    rules: List[HeuristicRule]
    version_hash: str
    total: int


class RuleCreateResponse(BaseModel):
    rule_id: str
    message: str
    version_hash: str
    created_at: datetime


class RuleUpdateResponse(BaseModel):
    message: str
    rule_id: str
    updated_at: datetime


class RuleDeleteResponse(BaseModel):
    message: str
    rule_id: str


class ValidateRulesRequest(BaseModel):
    rules: List[HeuristicRule]


class ValidateRulesResponse(BaseModel):
    valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    tests_passed: Optional[int] = None
    tests_total: Optional[int] = None


class ActivateVersionResponse(BaseModel):
    message: str
    active_version: str
    deployed_at: datetime
    rules_included: List[str]


class RulesHealthResponse(BaseModel):
    status: str
    cached: bool
    version_hash: str
    last_updated: Optional[datetime] = None
    source: str
    total_active_rules: int


class CreateVersionRequest(BaseModel):
    rules_included: List[str]
    changelog: str = ""
    deployed_by: str = "admin"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "127.0.0.1"


def _serialize_datetime(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return None


# ---------------------------------------------------------------------------
# Static routes (must be declared before /{rule_id})
# ---------------------------------------------------------------------------

@router.get("/health", response_model=RulesHealthResponse, tags=["Rules Health"])
async def rules_health():
    engine = get_rules_engine()
    health = await engine.health_check()
    stats = await engine.get_rules_stats()
    return RulesHealthResponse(
        status=health.status,
        cached=health.cached,
        version_hash=health.version_hash,
        last_updated=health.last_updated,
        source=health.source,
        total_active_rules=stats.total_active_rules,
    )


@router.get("/audit-log", tags=["Rules Audit"])
async def get_audit_log(
    rule_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    logs = await db.get_audit_logs(rule_id=rule_id, limit=limit + offset)
    return {"total": len(logs), "offset": offset, "limit": limit, "entries": logs[offset:offset + limit]}


@router.post("/validate", response_model=ValidateRulesResponse, tags=["Rules Validation"])
@limiter.limit("20/minute")
async def validate_rules(request: Request, body: ValidateRulesRequest = Body(...)):
    validation = RuleValidator.validate_rule_bundle(body.rules)
    test_result = RuleValidator.test_rules_with_patterns(body.rules)
    all_valid = validation.valid and test_result.passed
    errors = list(validation.errors)
    if not test_result.passed:
        errors.extend(test_result.failures)
    return ValidateRulesResponse(
        valid=all_valid,
        errors=errors,
        warnings=validation.warnings,
        tests_passed=test_result.passed_count,
        tests_total=test_result.total,
    )


@router.get("/versions", response_model=List[RuleVersion], tags=["Rule Versions"])
async def list_versions(limit: int = Query(default=50, ge=1, le=200)):
    return await db.list_versions(limit=limit)


@router.get("/versions/{version_hash}", response_model=RuleVersion, tags=["Rule Versions"])
async def get_version(version_hash: str):
    version = await db.get_version(version_hash)
    if not version:
        raise HTTPException(status_code=404, detail=f"Version not found: {version_hash}")
    return version


@router.post(
    "/versions",
    response_model=RuleVersion,
    status_code=status.HTTP_201_CREATED,
    tags=["Rule Versions"],
)
@limiter.limit("10/minute")
async def create_version(request: Request, body: CreateVersionRequest = Body(...)):
    rules = await db.get_rules_by_ids(body.rules_included)
    found = {r.rule_id for r in rules}
    missing = [rid for rid in body.rules_included if rid not in found]
    if missing:
        raise HTTPException(status_code=400, detail=f"Rules not found: {', '.join(missing)}")

    validation = RuleValidator.validate_rules(rules)
    if not validation.valid:
        raise HTTPException(status_code=422, detail={"errors": validation.errors})

    version_hash = hash_version(rules)
    version = RuleVersion(
        version_hash=version_hash,
        created_at=datetime.now(timezone.utc),
        is_active=False,
        rules_included=body.rules_included,
        changelog=body.changelog,
        deployed_by=body.deployed_by,
    )
    await db.create_version(version)
    await db.log_rule_action(
        action="CREATE",
        rule_id=version_hash,
        user=body.deployed_by,
        changes={"after": version.model_dump(mode="json")},
        reason=body.changelog or "New rule version created",
        ip_address=_client_ip(request),
    )
    return version


@router.post(
    "/versions/activate/{version_hash}",
    response_model=ActivateVersionResponse,
    tags=["Rule Versions"],
)
@limiter.limit("10/minute")
async def activate_version(request: Request, version_hash: str):
    engine = get_rules_engine()
    version = await db.get_version(version_hash)
    if not version:
        raise HTTPException(status_code=404, detail=f"Version not found: {version_hash}")

    previous = await db.get_active_version()
    try:
        bundle = await engine.deploy_version(version_hash)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    await db.log_rule_action(
        action="ACTIVATE",
        rule_id=version_hash,
        user=version.deployed_by,
        changes={
            "before": previous.model_dump(mode="json") if previous else None,
            "after": version.model_dump(mode="json"),
        },
        reason=f"Activated version {version_hash}",
        ip_address=_client_ip(request),
    )

    deployed_at = datetime.now(timezone.utc)
    return ActivateVersionResponse(
        message="Version activated successfully",
        active_version=bundle.version_hash,
        deployed_at=deployed_at,
        rules_included=version.rules_included,
    )


# ---------------------------------------------------------------------------
# Rule CRUD
# ---------------------------------------------------------------------------

@router.get("", response_model=RulesListResponse, tags=["Rules Management"])
async def list_rules(include_inactive: bool = Query(default=False)):
    rules = await db.list_all_rules(include_inactive=include_inactive)
    active_version = await db.get_active_version()
    version_hash = active_version.version_hash if active_version else hash_version(rules)
    return RulesListResponse(rules=rules, version_hash=version_hash, total=len(rules))


@router.get("/{rule_id}", response_model=HeuristicRule, tags=["Rules Management"])
async def get_rule(rule_id: str):
    rule = await db.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule not found: {rule_id}")
    return rule


@router.post("", response_model=RuleCreateResponse, status_code=status.HTTP_201_CREATED, tags=["Rules Management"])
@limiter.limit("10/minute")
async def create_rule(request: Request, rule: HeuristicRule = Body(...)):
    if await db.rule_exists(rule.rule_id):
        raise HTTPException(status_code=409, detail=f"Rule already exists: {rule.rule_id}")

    validation = RuleValidator.validate_rule(rule)
    if not validation.valid:
        raise HTTPException(status_code=422, detail={"errors": validation.errors})

    await db.create_rule(rule)
    version_hash = hash_version([rule])

    await db.log_rule_action(
        action="CREATE",
        rule_id=rule.rule_id,
        user=rule.metadata.changed_by,
        changes={"before": None, "after": rule.model_dump(mode="json")},
        reason=rule.metadata.change_reason,
        ip_address=_client_ip(request),
    )

    logger.info("Rule created: %s by %s", rule.rule_id, rule.metadata.changed_by)
    return RuleCreateResponse(
        rule_id=rule.rule_id,
        message="Rule created successfully",
        version_hash=version_hash,
        created_at=rule.created_at,
    )


@router.patch("/{rule_id}", response_model=RuleUpdateResponse, tags=["Rules Management"])
@limiter.limit("20/minute")
async def update_rule(request: Request, rule_id: str, updates: HeuristicRuleUpdate = Body(...)):
    existing = await db.get_rule(rule_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Rule not found: {rule_id}")

    before = existing.model_dump(mode="json")
    update_data = updates.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")

    merged = HeuristicRule.model_validate({**existing.model_dump(), **update_data})
    validation = RuleValidator.validate_rule(merged)
    if not validation.valid:
        raise HTTPException(status_code=422, detail={"errors": validation.errors})

    success = await db.update_rule(rule_id, update_data)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update rule")

    updated = await db.get_rule(rule_id)
    await db.log_rule_action(
        action="UPDATE",
        rule_id=rule_id,
        user=merged.metadata.changed_by,
        changes={"before": before, "after": updated.model_dump(mode="json") if updated else update_data},
        reason=merged.metadata.change_reason,
        ip_address=_client_ip(request),
    )

    updated_at = _serialize_datetime(updated.updated_at if updated else datetime.now(timezone.utc))
    return RuleUpdateResponse(
        message="Rule updated successfully",
        rule_id=rule_id,
        updated_at=updated_at or datetime.now(timezone.utc),
    )


@router.delete("/{rule_id}", response_model=RuleDeleteResponse, tags=["Rules Management"])
@limiter.limit("10/minute")
async def delete_rule(
    request: Request,
    rule_id: str,
    user: str = Query(default="admin"),
    reason: str = Query(default="Rule deactivated"),
):
    existing = await db.get_rule(rule_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Rule not found: {rule_id}")
    if not existing.is_active:
        raise HTTPException(status_code=409, detail=f"Rule already inactive: {rule_id}")

    before = existing.model_dump(mode="json")
    success = await db.delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to deactivate rule")

    await db.log_rule_action(
        action="DELETE",
        rule_id=rule_id,
        user=user,
        changes={"before": before, "after": {"is_active": False}},
        reason=reason,
        ip_address=_client_ip(request),
    )

    return RuleDeleteResponse(message="Rule deactivated successfully", rule_id=rule_id)

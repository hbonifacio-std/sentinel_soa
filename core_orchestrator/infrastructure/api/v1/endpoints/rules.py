"""
REST API endpoints for heuristic rules administration.

Provides CRUD, versioning, validation, audit log, and health endpoints
for managing threat detection rules stored in MongoDB with Redis cache.
"""
import logging
from dataclasses import asdict, replace
from datetime import datetime, timezone
from typing import Annotated, Any, List, Optional

from fastapi import APIRouter, Body, HTTPException, Query, Request, status, Depends

# New imports for refactored architecture
from core_orchestrator.application.modules.rules_heuristics.rule_service import RuleService
from core_orchestrator.application.modules.rules_heuristics.rules_engine_service import RulesEngineService
from core_orchestrator.domain.ports.rules.rule_validator_port import RuleValidatorPort


from core_orchestrator.domain.entities.rule_engine.rules import RuleVersion, hash_version
from core_orchestrator.domain.entities.auth.user import UserInDB
from core_orchestrator.infrastructure.api.dependencies.general_dependencies import get_rules_engine_service, \
    get_rule_service, get_rule_validator

# DTOs and mappers
from core_orchestrator.infrastructure.dto.rules_heuristics.rules_heuristics_dto import (
    ActivateVersionResponseDTO,
    CreateVersionRequestDTO,
    RuleCreateDTO,
    RuleCreateResponseDTO,
    RuleDeleteResponseDTO,
    RuleResponseDTO,
    RuleUpdateDTO,
    RuleUpdateResponseDTO,
    RuleVersionDTO,
    RulesHealthResponseDTO,
    RulesListResponseDTO,
    ValidateRulesRequestDTO,
    ValidateRulesResponseDTO,
)
from core_orchestrator.infrastructure.mappers.mappers import rule_mapper, GenericMapper

# Mapper instance for versions
version_mapper = GenericMapper(dataclass_cls=RuleVersion, dto_cls=RuleVersionDTO)

from core_orchestrator.infrastructure.rate_limit.rate_limiter import limiter
from core_orchestrator.infrastructure.api.dependencies.user_auth import get_admin_user, get_analyst_user_with_client

logger = logging.getLogger("core_orchestrator.api.rules")

router = APIRouter()

# ============================================================================
# Helpers
# ============================================================================

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


def _require_client_scope(user: UserInDB) -> str:
    if not user.client_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Client scope required")
    return user.client_id


async def _raise_if_cross_tenant_rule_mutation(
    rule_service: RuleService,
    rule_id: str,
    client_id: str,
) -> None:
    in_scope = await rule_service.fetch_rule_by_id(rule_id, client_id)
    if in_scope:
        return
    if await rule_service.rule_exists_any(rule_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant rule mutation is not allowed")
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule not found: {rule_id}")


# ============================================================================
# Endpoints de la API
# ============================================================================

@router.get("/health", response_model=RulesHealthResponseDTO, tags=["Rules Health"])
async def rules_health(
    rules_engine_service: Annotated[RulesEngineService, Depends(get_rules_engine_service)],
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
):
    """Health check for rules engine (requires analyst/admin role)."""
    _require_client_scope(current_user)
    health = await rules_engine_service.health_check()
    stats = await rules_engine_service.get_rules_stats()
    return RulesHealthResponseDTO(
        status=health.status,
        cached=health.cached,
        version_hash=health.version_hash,
        last_updated=health.last_updated,
        source=health.source,
        total_active_rules=stats.total_active_rules,
    )


@router.get("/audit-log", tags=["Rules Audit"])
async def get_audit_log(
    rule_service: Annotated[RuleService, Depends(get_rule_service)],
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
    rule_id: Annotated[Optional[str], Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Get audit log (requires analyst/admin role)."""
    logs = await rule_service.get_audit_logs(
        client_id=_require_client_scope(current_user),
        rule_id=rule_id,
        limit=limit,
        offset=offset,
    )
    return {"total": len(logs), "offset": offset, "limit": limit, "entries": logs}


@router.post("/validate", response_model=ValidateRulesResponseDTO, tags=["Rules Validation"])
@limiter.limit("20/minute")
async def validate_rules(
    request: Request,
    body: Annotated[ValidateRulesRequestDTO, Body(...)],
    validator: Annotated[RuleValidatorPort, Depends(get_rule_validator)],
    _: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
):
    """Validate rules (requires analyst/admin role)."""
    domain_rules = rule_mapper.to_dataclass_list(body.rules)
    validation = validator.validate_rule_bundle(domain_rules)
    test_result = validator.test_rules_with_patterns(domain_rules)
    all_valid = validation.valid and test_result.passed
    errors = list(validation.errors)
    if not test_result.passed:
        errors.extend(test_result.failures)
    return ValidateRulesResponseDTO(
        valid=all_valid,
        errors=errors,
        warnings=validation.warnings,
        tests_passed=test_result.passed_count,
        tests_total=test_result.total,
    )


@router.get("/versions", response_model=List[RuleVersionDTO], tags=["Rule Versions"])
async def list_versions(
    rule_service: Annotated[RuleService, Depends(get_rule_service)],
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
):
    """List rule versions (requires analyst/admin role)."""
    versions = await rule_service.list_versions(client_id=_require_client_scope(current_user), limit=limit)
    return version_mapper.to_dto_list(versions)


@router.get("/versions/{version_hash}", response_model=RuleVersionDTO, tags=["Rule Versions"])
async def get_version(
    version_hash: str,
    rule_service: Annotated[RuleService, Depends(get_rule_service)],
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
):
    """Get specific rule version (requires analyst/admin role)."""
    version = await rule_service.get_version(version_hash, _require_client_scope(current_user))
    if not version:
        raise HTTPException(status_code=404, detail=f"Version not found: {version_hash}")
    return version_mapper.to_dto(version)


@router.post(
    "/versions",
    response_model=RuleVersionDTO,
    status_code=status.HTTP_201_CREATED,
    tags=["Rule Versions"],
)
@limiter.limit("10/minute")
async def create_version(
    request: Request,
    body: Annotated[CreateVersionRequestDTO, Body(...)],
    rule_service: Annotated[RuleService, Depends(get_rule_service)],
    current_user: Annotated[UserInDB, Depends(get_admin_user)],
):
    """Create new rule version (requires admin role)."""
    client_id = _require_client_scope(current_user)
    try:
        version = await rule_service.create_new_version(
            rule_ids=body.rules_included,
            changelog=body.changelog,
            deployed_by=body.deployed_by,
            client_id=client_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    await rule_service.log_rule_action(
        action="CREATE",
        rule_id=version.version_hash,
        user=body.deployed_by,
        changes={"after": asdict(version)},
        reason=body.changelog or "New rule version created",
        ip_address=_client_ip(request),
        client_id=client_id,
    )
    return version_mapper.to_dto(version)


@router.post(
    "/versions/activate/{version_hash}",
    response_model=ActivateVersionResponseDTO,
    tags=["Rule Versions"],
)
@limiter.limit("10/minute")
async def activate_version(
    request: Request,
    version_hash: str,
    rule_service: Annotated[RuleService, Depends(get_rule_service)],
    current_user: Annotated[UserInDB, Depends(get_admin_user)],
):
    """Activate rule version (requires admin role)."""
    client_id = _require_client_scope(current_user)
    version = await rule_service.get_version(version_hash, client_id)
    if not version:
        raise HTTPException(status_code=404, detail=f"Version not found: {version_hash}")

    previous = await rule_service.get_active_version(client_id)
    try:
        bundle = await rule_service.deploy_version(version_hash, client_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    await rule_service.log_rule_action(
        action="ACTIVATE",
        rule_id=version_hash,
        user=version.deployed_by,
        changes={
            "before": asdict(previous) if previous else None,
            "after": asdict(version),
        },
        reason=f"Activated version {version_hash}",
        ip_address=_client_ip(request),
        client_id=client_id,
    )

    deployed_at = datetime.now(timezone.utc)
    return ActivateVersionResponseDTO(
        message="Version activated successfully",
        active_version=bundle.version_hash,
        deployed_at=deployed_at,
        rules_included=version.rules_included,
    )


@router.get("", response_model=RulesListResponseDTO, tags=["Rules Management"])
async def list_rules(
    rule_service: Annotated[RuleService, Depends(get_rule_service)],
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
    include_inactive: Annotated[bool, Query()] = False,
):
    """List all rules (requires analyst/admin role)."""
    client_id = _require_client_scope(current_user)
    rules = await rule_service.fetch_all_rules(include_inactive=include_inactive, client_id=client_id)
    active_version = await rule_service.get_active_version(client_id)
    version_hash = active_version.version_hash if active_version else hash_version(rules)

    dto_rules = rule_mapper.to_dto_list(rules)
    return RulesListResponseDTO(rules=dto_rules, version_hash=version_hash, total=len(rules))


@router.get("/{rule_id}", response_model=RuleResponseDTO, tags=["Rules Management"])
async def get_rule(
    rule_id: str,
    rule_service: Annotated[RuleService, Depends(get_rule_service)],
    current_user: Annotated[UserInDB, Depends(get_analyst_user_with_client)],
):
    """Get specific rule (requires analyst/admin role)."""
    rule = await rule_service.fetch_rule_by_id(rule_id, _require_client_scope(current_user))
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule not found: {rule_id}")
    return rule_mapper.to_dto(rule)


@router.post("", response_model=RuleCreateResponseDTO, status_code=status.HTTP_201_CREATED, tags=["Rules Management"])
@limiter.limit("10/minute")
async def create_rule(
    request: Request,
    rule: Annotated[RuleCreateDTO, Body(...)],
    rule_service: Annotated[RuleService, Depends(get_rule_service)],
    validator: Annotated[RuleValidatorPort, Depends(get_rule_validator)],
    current_user: Annotated[UserInDB, Depends(get_admin_user)],
):
    """Create new rule (requires admin role)."""
    client_id = _require_client_scope(current_user)
    domain_rule = rule_mapper.to_dataclass(rule)
    scoped_rule = replace(domain_rule, client_id=client_id)
    if await rule_service.rule_exists(scoped_rule.rule_id, client_id):
        raise HTTPException(status_code=409, detail=f"Rule already exists: {scoped_rule.rule_id}")

    validation = validator.validate_rule(scoped_rule)
    if not validation.valid:
        raise HTTPException(status_code=422, detail={"errors": validation.errors})

    new_rule = await rule_service.create_rule(scoped_rule)
    version_hash = hash_version([new_rule])

    await rule_service.log_rule_action(
        action="CREATE",
        rule_id=new_rule.rule_id,
        user=new_rule.metadata.changed_by,
        changes={"before": None, "after": asdict(new_rule)},
        reason=new_rule.metadata.change_reason,
        ip_address=_client_ip(request),
        client_id=client_id,
    )

    logger.info("Rule created: %s by %s", new_rule.rule_id, new_rule.metadata.changed_by)
    return RuleCreateResponseDTO(
        rule_id=new_rule.rule_id,
        message="Rule created successfully",
        version_hash=version_hash,
        created_at=new_rule.created_at,
    )


@router.patch("/{rule_id}", response_model=RuleUpdateResponseDTO, tags=["Rules Management"])
@limiter.limit("20/minute")
async def update_rule(
    request: Request,
    rule_id: str,
    updates: Annotated[RuleUpdateDTO, Body(...)],
    rule_service: Annotated[RuleService, Depends(get_rule_service)],
    validator: Annotated[RuleValidatorPort, Depends(get_rule_validator)],
    current_user: Annotated[UserInDB, Depends(get_admin_user)],
):
    """Update rule (requires admin role)."""
    client_id = _require_client_scope(current_user)
    await _raise_if_cross_tenant_rule_mutation(rule_service, rule_id, client_id)
    existing = await rule_service.fetch_rule_by_id(rule_id, client_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Rule ownership validation failed")

    before = asdict(existing)
    update_data = updates.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")

    merged = rule_mapper.to_dataclass(RuleCreateDTO(**{**before, **update_data}))
    validation = validator.validate_rule(merged)
    if not validation.valid:
        raise HTTPException(status_code=422, detail={"errors": validation.errors})

    success = await rule_service.update_rule(rule_id, client_id, update_data)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update rule")

    updated = await rule_service.fetch_rule_by_id(rule_id, client_id)
    await rule_service.log_rule_action(
        action="UPDATE",
        rule_id=rule_id,
        user=merged.metadata.changed_by,
        changes={"before": before, "after": asdict(updated) if updated else update_data},
        reason=merged.metadata.change_reason,
        ip_address=_client_ip(request),
        client_id=client_id,
    )

    updated_at = _serialize_datetime(updated.updated_at if updated else datetime.now(timezone.utc))
    return RuleUpdateResponseDTO(
        message="Rule updated successfully",
        rule_id=rule_id,
        updated_at=updated_at,
    )


@router.delete("/{rule_id}", response_model=RuleDeleteResponseDTO, tags=["Rules Management"])
@limiter.limit("10/minute")
async def delete_rule(
    request: Request,
    rule_id: str,
    rule_service: Annotated[RuleService, Depends(get_rule_service)],
    current_user: Annotated[UserInDB, Depends(get_admin_user)],
    user: Annotated[str, Query()] = "admin",
    reason: Annotated[str, Query()] = "Rule deactivated",
):
    """Delete/deactivate rule (requires admin role)."""
    client_id = _require_client_scope(current_user)
    await _raise_if_cross_tenant_rule_mutation(rule_service, rule_id, client_id)
    existing = await rule_service.fetch_rule_by_id(rule_id, client_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Rule ownership validation failed")
    if not existing.is_active:
        raise HTTPException(status_code=409, detail=f"Rule already inactive: {rule_id}")

    before = asdict(existing)
    success = await rule_service.delete_rule(rule_id, client_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to deactivate rule")

    await rule_service.log_rule_action(
        action="DELETE",
        rule_id=rule_id,
        user=user,
        changes={"before": before, "after": {"is_active": False}},
        reason=reason,
        ip_address=_client_ip(request),
        client_id=client_id,
    )

    return RuleDeleteResponseDTO(message="Rule deactivated successfully", rule_id=rule_id)

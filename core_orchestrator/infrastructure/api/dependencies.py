"""
Dependency providers for the FastAPI application.

This module provides functions that the FastAPI dependency injection system
can use to provide instances of services, repositories, etc., to the
API endpoints. All instances are sourced from the centralized container.
"""

from fastapi import Depends, Header, HTTPException, status
from core_orchestrator.infrastructure.api.container import Container, get_container

# Import types for type hinting
from core_orchestrator.infrastructure.agent.runner import AgentRunner
from core_orchestrator.application.modules.analysis_reports.services.analytics_service import ReportTelemetryService
from core_orchestrator.application.modules.auth_clients.services.auth_service import AuthService
from core_orchestrator.application.modules.auth_clients.services.tenant_service import TenantService
from core_orchestrator.application.modules.analysis_reports.services.rules_engine_service import RulesEngineService
from core_orchestrator.application.modules.analysis_reports.services.rule_service import RuleService
from core_orchestrator.domain.ports.rules.rule_validator_port import RuleValidatorPort
from core_orchestrator.application.modules.auth_clients.services.telemetry_client_service import TelemetryClientService
from core_orchestrator.application.modules.telemetry.services.telemetry_processing_service import TelemetryProcessingService
from core_orchestrator.application.modules.telemetry.services.telemetry_service import TelemetryService
from core_orchestrator.application.modules.forensic.services.forensic_service import ForensicService
from core_orchestrator.application.modules.auth_clients.services.user_service import UserService
from core_orchestrator.infrastructure.config.database import DatabaseManager


def get_db_manager(container: Container = Depends(get_container)) -> DatabaseManager:
    return container.db_manager

def get_analytics_service(container: Container = Depends(get_container)) -> ReportTelemetryService:
    return container.analytics_service

def get_auth_service(container: Container = Depends(get_container)) -> AuthService:
    return container.auth_service

def get_rule_service(container: Container = Depends(get_container)) -> RuleService:
    return container.rule_service


def get_rules_engine_service(container: Container = Depends(get_container)) -> RulesEngineService:
    return container.rules_engine_service

def get_rule_validator(container: Container = Depends(get_container)) -> RuleValidatorPort:
    return container.rule_validator

def get_telemetry_client_service(container: Container = Depends(get_container)) -> TelemetryClientService:
    return container.telemetry_client_service

def get_telemetry_service(container: Container = Depends(get_container)) -> TelemetryService:
    return container.telemetry_service

def get_telemetry_processing_service(container: Container = Depends(get_container)) -> TelemetryProcessingService:
    return container.telemetry_processing_service

def get_user_service(container: Container = Depends(get_container)) -> UserService:
    return container.user_service

def get_tenant_service(container: Container = Depends(get_container)) -> TenantService:
    return container.tenant_service

def get_tenant_provider_service(container: Container = Depends(get_container)):
    return container.tenant_provider_service

def get_forensic_service(container: Container = Depends(get_container)) -> ForensicService:
    return container.forensic_service

def get_agent_runner(container: Container = Depends(get_container)) -> AgentRunner:
    return container.agent_runner

def get_limiter(container: Container = Depends(get_container)):
    return container.limiter


# ============================================================================
# TELEMETRY INGESTION DEPENDENCIES
# ============================================================================

async def get_source_id(
    x_sentinel_source_id: str = Header(..., alias="x-sentinel-source-id", description="Unique identifier of the telemetry source")
) -> str:
    """Extract and validate source_id from request headers.
    
    Required for multitenant batch ingestion to segregate telemetry by data source.
    Ensures the header is not empty (whitespace-trimmed).
    """
    if not x_sentinel_source_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Sentinel-Source-ID header cannot be empty"
        )
    return x_sentinel_source_id

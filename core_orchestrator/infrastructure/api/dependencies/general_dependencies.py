"""
Dependency providers for the FastAPI application.

This module provides functions that the FastAPI dependency injection system
can use to provide instances of services, repositories, etc., to the
API endpoints. All instances are sourced from the centralized container.
"""

from fastapi import Depends

from core_orchestrator.application.modules.auth_clients.auth_service import AuthService
from core_orchestrator.application.modules.auth_clients.user_service import UserService
from core_orchestrator.infrastructure.api.container import Container, get_container


from core_orchestrator.infrastructure.adapters.workers.telemetry_processing_worker import TelemetryProcessingWorker
from core_orchestrator.application.modules.analysis_reports.services.analytics_service import ReportTelemetryService

from core_orchestrator.application.modules.auth_clients.tenant_service import TenantService
from core_orchestrator.application.modules.analysis_reports.services.rules_engine_service import RulesEngineService
from core_orchestrator.application.modules.analysis_reports.services.rule_service import RuleService
from core_orchestrator.domain.ports.rules.rule_validator_port import RuleValidatorPort
from core_orchestrator.application.modules.telemetry.telemetry_window_manager_service import TelemetryProcessingService
from core_orchestrator.application.modules.telemetry.telemetry_service import TelemetryService
from core_orchestrator.application.modules.forensic.forensic_service import ForensicService

from core_orchestrator.infrastructure.database.database_manager import DatabaseManager


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

def get_agent_runner(container: Container = Depends(get_container)) -> TelemetryProcessingWorker:
    return container.agent_runner

def get_limiter(container: Container = Depends(get_container)):
    return container.limiter


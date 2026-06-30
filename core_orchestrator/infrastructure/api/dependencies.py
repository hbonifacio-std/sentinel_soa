"""
Dependency providers for the FastAPI application.

This module provides functions that the FastAPI dependency injection system
can use to provide instances of services, repositories, etc., to the
API endpoints. All instances are sourced from the centralized container.
"""

from fastapi import Depends
from core_orchestrator.infrastructure.api.container import Container, get_container

# Import types for type hinting
from core_orchestrator.agent.runner import AgentRunner
from core_orchestrator.application.services.analytics_service import AnalyticsService
from core_orchestrator.application.services.auth_service import AuthService
from core_orchestrator.application.services.rule_service import RuleService
from core_orchestrator.domain.ports.rule_validator_port import RuleValidatorPort
from core_orchestrator.application.services.telemetry_client_service import TelemetryClientService
from core_orchestrator.application.services.telemetry_processing_service import TelemetryProcessingService
from core_orchestrator.application.services.telemetry_service import TelemetryService
from core_orchestrator.application.services.user_service import UserService
from core_orchestrator.infrastructure.config.database import DatabaseManager


def get_db_manager(container: Container = Depends(get_container)) -> DatabaseManager:
    return container.db_manager

def get_analytics_service(container: Container = Depends(get_container)) -> AnalyticsService:
    return container.analytics_service

def get_auth_service(container: Container = Depends(get_container)) -> AuthService:
    return container.auth_service

def get_rule_service(container: Container = Depends(get_container)) -> RuleService:
    return container.rule_service

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

def get_agent_runner(container: Container = Depends(get_container)) -> AgentRunner:
    return container.agent_runner

def get_limiter(container: Container = Depends(get_container)):
    return container.limiter

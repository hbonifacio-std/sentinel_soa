from functools import lru_cache
from typing import Optional

from fastapi import Depends
from redis.asyncio import Redis

# Application services
from core_orchestrator.application.services.rule_service import RuleService
from core_orchestrator.application.services.analytics_service import AnalyticsService
from core_orchestrator.application.services.auth_service import AuthService

# Domain ports
from core_orchestrator.domain.ports.audit_repository import AuditRepository
from core_orchestrator.domain.ports.rule_repository import RuleRepository
from core_orchestrator.domain.ports.analytics_repository import AnalyticsRepository
from core_orchestrator.domain.ports.token_blacklist_repository import TokenBlacklistRepository
from core_orchestrator.domain.ports.telemetry_repository import TelemetryRepository

# Infrastructure components
from core_orchestrator.infrastructure.config.database import DatabaseManager
from core_orchestrator.infrastructure.persistence.mongo_audit_repository import MongoAuditRepository
from core_orchestrator.infrastructure.persistence.mongo_rule_repository import MongoRuleRepository
from core_orchestrator.infrastructure.persistence.mongo_analytics_repository import MongoAnalyticsRepository
from core_orchestrator.infrastructure.cache.redis_token_blacklist_repository import RedisTokenBlacklistRepository
from core_orchestrator.infrastructure.persistence.mongo_telemetry_repository import MongoTelemetryRepository

from core_orchestrator.infrastructure.cache.cache_service import CacheService
from core_orchestrator.application.services.telemetry_service import TelemetryService
from core_orchestrator.application.services.telemetry_processing_service import TelemetryProcessingService
from core_orchestrator.domain.ports.user_repository import UserRepository
from core_orchestrator.infrastructure.persistence.mongo_user_repository import MongoUserRepository
from core_orchestrator.domain.ports.telemetry_client_repository import TelemetryClientRepository
from core_orchestrator.infrastructure.persistence.mongo_telemetry_client_repository import MongoTelemetryClientRepository
from core_orchestrator.application.services.telemetry_client_service import TelemetryClientService
from core_orchestrator.infrastructure.api.rate_limiter import limiter
from core_orchestrator.agent.runner import AgentRunner
from core_orchestrator.application.services.user_service import UserService

# Config
from core_orchestrator.infrastructure.config.config import orchestrator_settings


@lru_cache(maxsize=1)
def get_db_manager() -> DatabaseManager:
    """
    Creates and returns a DatabaseManager instance.
    Using lru_cache ensures that only one instance is created.
    """
    db_manager = DatabaseManager()
    db_manager.connect()  # Connect to databases
    return db_manager

def get_redis_client(db_manager: DatabaseManager = Depends(get_db_manager)) -> Optional[Redis]:
    """Provides the Redis client from the database manager."""
    return db_manager.redis_client

# New Hexagonal Architecture dependencies
def get_rule_repository(db_manager: DatabaseManager = Depends(get_db_manager)) -> RuleRepository:
    """Provides a concrete implementation of the RuleRepository port."""
    return MongoRuleRepository(db_manager)

def get_audit_repository(db_manager: DatabaseManager = Depends(get_db_manager)) -> AuditRepository:
    """Provides a concrete implementation of the AuditRepository port."""
    return MongoAuditRepository(db_manager)

def get_analytics_repository(db_manager: DatabaseManager = Depends(get_db_manager)) -> AnalyticsRepository:
    """Provides a concrete implementation of the AnalyticsRepository port."""
    return MongoAnalyticsRepository(db_manager)
    
def get_telemetry_repository(db_manager: DatabaseManager = Depends(get_db_manager)) -> TelemetryRepository:
    """Provides a concrete implementation of the TelemetryRepository port."""
    return MongoTelemetryRepository(db_manager)

def get_token_blacklist_repository(redis: Optional[Redis] = Depends(get_redis_client)) -> TokenBlacklistRepository:
    """Provides a concrete implementation of the TokenBlacklistRepository port."""
    return RedisTokenBlacklistRepository(redis)

def get_user_repository(db_manager: DatabaseManager = Depends(get_db_manager)) -> UserRepository:
    """Provides a concrete implementation of the UserRepository port."""
    return MongoUserRepository(db_manager)

def get_telemetry_client_repository(db_manager: DatabaseManager = Depends(get_db_manager)) -> TelemetryClientRepository:
    """Provides a concrete implementation of the TelemetryClientRepository port."""
    return MongoTelemetryClientRepository(db_manager)

def get_rule_service(
    rule_repo: RuleRepository = Depends(get_rule_repository),
    audit_repo: AuditRepository = Depends(get_audit_repository),
    redis: Optional[Redis] = Depends(get_redis_client)
) -> RuleService:
    """Provides an instance of the RuleService with its dependencies."""
    return RuleService(
        rule_repository=rule_repo,
        audit_repository=audit_repo,
        redis_rules_client=redis
    )

def get_analytics_service(
    analytics_repo: AnalyticsRepository = Depends(get_analytics_repository)
) -> AnalyticsService:
    """Provides an instance of the AnalyticsService with its dependencies."""
    return AnalyticsService(analytics_repository=analytics_repo)

def get_user_service(user_repo: UserRepository = Depends(get_user_repository)) -> UserService:
    return UserService(user_repository=user_repo)

def get_auth_service(
    user_service: UserService = Depends(get_user_service),
    blacklist_repo: TokenBlacklistRepository = Depends(get_token_blacklist_repository)
) -> AuthService:
    """Provides an instance of the AuthService with its dependencies."""
    return AuthService(user_service=user_service, token_blacklist_repository=blacklist_repo)


@lru_cache(maxsize=1)
def get_cache_service(db_manager: DatabaseManager = Depends(get_db_manager)) -> CacheService:
    return CacheService(db_manager=db_manager)

@lru_cache(maxsize=1)
def get_telemetry_service(repo: TelemetryRepository = Depends(get_telemetry_repository)) -> TelemetryService:
    return TelemetryService(repository=repo)

@lru_cache(maxsize=1)
def get_telemetry_processing_service(cache_service: CacheService = Depends(get_cache_service)) -> TelemetryProcessingService:
    return TelemetryProcessingService(
        window_duration_seconds=orchestrator_settings.window_duration_seconds,
        cache_service=cache_service,
    )

def get_telemetry_client_service(
    repo: TelemetryClientRepository = Depends(get_telemetry_client_repository),
    cache: CacheService = Depends(get_cache_service)
) -> TelemetryClientService:
    return TelemetryClientService(telemetry_client_repository=repo, cache_service=cache)

@lru_cache(maxsize=1)
def get_agent_runner(
    telemetry_processing_service: TelemetryProcessingService = Depends(get_telemetry_processing_service),
    redis_client: Optional[Redis] = Depends(get_redis_client)
) -> AgentRunner:
    agent_runner = AgentRunner(
        telemetry_processing_service=telemetry_processing_service,
        redis_client=redis_client
    )
    return agent_runner

def get_limiter():
    return limiter

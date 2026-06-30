"""
Centralized dependency injection container for the Core Orchestrator.
"""

# Import all necessary services, repositories, and managers.
# This looks long, but it's the single place where concrete classes are wired together.

from functools import lru_cache

# Services
from core_orchestrator.application.services.analysis_service import AnalysisService
from core_orchestrator.application.services.analytics_service import AnalyticsService
from core_orchestrator.application.services.auth_service import AuthService
from core_orchestrator.application.services.rule_service import RuleService
from core_orchestrator.application.services.rules_engine_service import RulesEngineService, init_rules_engine
from core_orchestrator.application.services.telemetry_client_service import TelemetryClientService
from core_orchestrator.application.services.telemetry_processing_service import TelemetryProcessingService
from core_orchestrator.application.services.telemetry_service import TelemetryService
from core_orchestrator.application.services.threat_context_service import ThreatContextService
from core_orchestrator.application.services.user_service import UserService
from core_orchestrator.application.services.default_rule_validator import DefaultRuleValidator


# Repositories (Ports) and their Implementations
from core_orchestrator.domain.ports.analytics_repository import AnalyticsRepository
from core_orchestrator.infrastructure.persistence.mongo_analytics_repository import MongoAnalyticsRepository
from core_orchestrator.domain.ports.audit_repository import AuditRepository
from core_orchestrator.infrastructure.persistence.mongo_audit_repository import MongoAuditRepository
from core_orchestrator.domain.ports.rule_repository import RuleRepository
from core_orchestrator.infrastructure.persistence.mongo_rule_repository import MongoRuleRepository
from core_orchestrator.domain.ports.telemetry_client_repository import TelemetryClientRepository
from core_orchestrator.infrastructure.persistence.mongo_telemetry_client_repository import MongoTelemetryClientRepository
from core_orchestrator.infrastructure.persistence.caching_telemetry_client_repository import CachingTelemetryClientRepository
from core_orchestrator.domain.ports.telemetry_repository import TelemetryRepository
from core_orchestrator.infrastructure.persistence.mongo_telemetry_repository import MongoTelemetryRepository
from core_orchestrator.domain.ports.token_blacklist_repository import TokenBlacklistRepository
from core_orchestrator.infrastructure.cache.redis_token_blacklist_repository import RedisTokenBlacklistRepository
from core_orchestrator.domain.ports.user_repository import UserRepository
from core_orchestrator.infrastructure.persistence.mongo_user_repository import MongoUserRepository

# Core Infrastructure
from core_orchestrator.agent.mcp_client import MCPClientManager
from core_orchestrator.agent.runner import AgentRunner
from core_orchestrator.infrastructure.cache.cache_service import CacheService
from core_orchestrator.infrastructure.cache.redis_cache import RedisCache
from core_orchestrator.infrastructure.cache.redis_rules_bundle_cache import RedisRulesBundleCache
from core_orchestrator.infrastructure.cache.redis_telemetry_window_cache import RedisTelemetryWindowCache
from core_orchestrator.infrastructure.config.config import orchestrator_settings
from core_orchestrator.infrastructure.config.database import DatabaseManager
from core_orchestrator.infrastructure.api.rate_limiter import limiter


class Container:
    """
    Singleton container for managing and providing application-wide dependencies.
    """

    def __init__(self):
        # 1. En el constructor SOLO inicializamos la infraestructura base síncrona
        self.db_manager = DatabaseManager()
        self.mcp_client_manager = MCPClientManager()
        self.limiter = limiter

        # 2. Dejamos preparados los espacios para lo que necesita base de datos activa
        self.cache_service = None
        self.redis_cache = None
        self.telemetry_window_cache = None
        self.analytics_repository = None
        self.audit_repository = None
        self.rule_repository = None
        self.telemetry_client_repository = None
        self.telemetry_repository = None
        self.token_blacklist_repository = None
        self.user_repository = None
        self.rules_bundle_cache = None
        self.rule_validator = None

        self.analytics_service = None
        self.user_service = None
        self.auth_service = None
        self.rule_service = None
        self.rules_engine_service = None
        self.telemetry_service = None
        self.telemetry_client_service = None
        self.telemetry_processing_service = None
        self.threat_context_service = None
        self.analysis_service = None
        self.agent_runner = None

    async def startup(self):
        """Connects to databases and initializes long-running services."""
        # === PASO 1: Establecer las conexiones reales ===
        self.db_manager.connect()

        # === PASO 2: Instanciar Repositorios y Servicios (Ahora que hay conexión) ===
        self.cache_service = CacheService(db_manager=self.db_manager) # Will be removed soon
        self.redis_cache = RedisCache(redis_client=self.db_manager.redis_client)
        self.telemetry_window_cache = RedisTelemetryWindowCache(redis_client=self.db_manager.redis_client)

        # Repositories
        self.analytics_repository = MongoAnalyticsRepository(db_manager=self.db_manager)
        self.audit_repository = MongoAuditRepository(db_manager=self.db_manager)
        self.rule_repository = MongoRuleRepository(db_manager=self.db_manager)
        
        mongo_telemetry_client_repo = MongoTelemetryClientRepository(db_manager=self.db_manager)
        self.telemetry_client_repository = CachingTelemetryClientRepository(
            primary_repository=mongo_telemetry_client_repo,
            cache=self.redis_cache
        )

        self.telemetry_repository = MongoTelemetryRepository(db_manager=self.db_manager)
        self.token_blacklist_repository = RedisTokenBlacklistRepository(redis_client=self.db_manager.redis_client)
        self.user_repository = MongoUserRepository(db_manager=self.db_manager)

        # Services
        self.analytics_service = AnalyticsService(analytics_repository=self.analytics_repository)
        self.user_service = UserService(user_repository=self.user_repository)
        self.auth_service = AuthService(user_provider=self.user_service,
                                        token_blacklist_repository=self.token_blacklist_repository)
        
        self.rules_bundle_cache = RedisRulesBundleCache(redis_client=self.db_manager.redis_client)
        self.rule_validator = DefaultRuleValidator()

        self.rule_service = RuleService(
            rule_repository=self.rule_repository,
            audit_repository=self.audit_repository,
            rules_bundle_cache=self.rules_bundle_cache,
            rule_validator=self.rule_validator
        )
        self.rules_engine_service = init_rules_engine(rules_service=self.rule_service)
        self.telemetry_service = TelemetryService(repository=self.telemetry_repository)
        self.telemetry_client_service = TelemetryClientService(
            telemetry_client_repository=self.telemetry_client_repository
        )
        self.telemetry_processing_service = TelemetryProcessingService(
            window_cache=self.telemetry_window_cache,
            window_duration_seconds=orchestrator_settings.window_duration_seconds
        )
        self.threat_context_service = ThreatContextService(mcp_manager=self.mcp_client_manager)
        self.analysis_service = AnalysisService(
            mcp_manager=self.mcp_client_manager,
            rules_engine_service=self.rules_engine_service
        )

        # Agent Runner
        self.agent_runner = AgentRunner(
            telemetry_processing_service=self.telemetry_processing_service,
            cache_service=self.cache_service,
            telemetry_service=self.telemetry_service,
            analytics_service=self.analytics_service,
            analysis_service=self.analysis_service
        )

        # === PASO 3: Inicializar Subsistemas Internos ===
        await self.rules_engine_service.initialize()
        await self.agent_runner.initialize_subsystem()

    async def shutdown(self):
        """Cleans up resources, closing connections and stopping services."""
        if self.agent_runner:
            await self.agent_runner.shutdown_subsystem()
        if self.db_manager.mongo_client:
            await self.db_manager.mongo_client.close()
        if self.db_manager.redis_client:
            await self.db_manager.redis_client.close()

# Use lru_cache to ensure the container is a singleton
@lru_cache(maxsize=1)
def get_container() -> Container:
    return Container()

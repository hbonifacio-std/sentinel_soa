"""
Centralized dependency injection container for the Core Orchestrator.
"""

from functools import lru_cache
from datetime import timedelta

# Services
from core_orchestrator.application.modules.analysis_reports.services.analysis_service import AnalysisService
from core_orchestrator.application.modules.analysis_reports.services.analytics_service import ReportTelemetryService
from core_orchestrator.application.modules.auth_clients.services.auth_service import AuthService
from core_orchestrator.application.modules.analysis_reports.services.rule_service import RuleService
from core_orchestrator.application.modules.analysis_reports.services.rules_engine_service import RulesEngineService
from core_orchestrator.application.modules.auth_clients.services.telemetry_client_service import TelemetryClientService
from core_orchestrator.application.modules.telemetry.services.telemetry_processing_service import TelemetryProcessingService
from core_orchestrator.application.modules.telemetry.services.telemetry_service import TelemetryService
from core_orchestrator.application.modules.analysis_reports.services.threat_context_service import ThreatContextService
from core_orchestrator.application.modules.auth_clients.services.user_service import UserService
from core_orchestrator.application.modules.analysis_reports.services.default_rule_validator_service import DefaultRuleValidatorService

# Repositories and their Implementations
from core_orchestrator.infrastructure.persistence.mongo_analytics_repository import MongoAnalyticsRepository
from core_orchestrator.infrastructure.persistence.mongo_audit_repository import MongoAuditRepository
from core_orchestrator.infrastructure.persistence.mongo_rule_repository import MongoRuleRepository
from core_orchestrator.infrastructure.persistence.mongo_telemetry_client_repository import MongoTelemetryClientRepository
from core_orchestrator.infrastructure.persistence.caching_telemetry_client_repository import CachingTelemetryClientRepository
from core_orchestrator.infrastructure.persistence.mongo_telemetry_repository import MongoTelemetryRepository
from core_orchestrator.infrastructure.cache.redis_token_blacklist_repository import RedisTokenBlacklistRepository
from core_orchestrator.infrastructure.persistence.mongo_user_repository import MongoUserRepository

# Core Infrastructure
from core_orchestrator.infrastructure.agent.mcp_client import MCPClientManager
from core_orchestrator.infrastructure.agent.mcp_llm_analysis_adapter import MCPLlmAnalysisAdapter
from core_orchestrator.infrastructure.agent.mcp_threat_context_adapter import MCPThreatContextAdapter
from core_orchestrator.infrastructure.agent.orchestrator import OrchestratorAgent
from core_orchestrator.infrastructure.agent.runner import AgentRunner
from core_orchestrator.infrastructure.cache.cache_service import CacheService
from core_orchestrator.infrastructure.cache.redis_cache import RedisCache
from core_orchestrator.infrastructure.cache.redis_rules_bundle_cache import RedisRulesBundleCache
from core_orchestrator.infrastructure.cache.redis_telemetry_window_cache import RedisTelemetryWindowCache
from core_orchestrator.infrastructure.config.config import orchestrator_settings
from core_orchestrator.infrastructure.config.database import DatabaseManager
from core_orchestrator.infrastructure.api.rate_limiter import limiter
from core_orchestrator.infrastructure.security.password_hasher import BcryptPasswordHasher
from core_orchestrator.infrastructure.security.signature_verifier import HmacSignatureVerifier
from core_orchestrator.infrastructure.security.token_service import JwtTokenService


class Container:
    """
    Singleton container for managing and providing application-wide dependencies.
    """

    def __init__(self):
        # 1. En el constructor SOLO inicializamos la infraestructura base síncrona
        self.db_manager = DatabaseManager()
        self.mcp_client_manager = MCPClientManager()
        self.limiter = limiter

        # 2. Espacios para dependencias que necesitan conexión activa
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
        self.password_hasher = None
        self.token_service = None
        self.signature_verifier = None

        self.analytics_service = None
        self.user_service = None
        self.auth_service = None
        self.rule_service = None
        self.rules_engine_service = None
        self.telemetry_service = None
        self.telemetry_client_service = None
        self.telemetry_processing_service = None
        self.agent_runner = None

    async def startup(self):
        """Connects to databases and initializes long-running services."""
        # === PASO 1: Conexiones reales ===
        self.db_manager.connect()
        if self.db_manager.redis_client is None:
            raise RuntimeError("Redis client is not connected")

        redis_client = self.db_manager.redis_client

        # === PASO 2: Repositorios y Servicios ===
        self.cache_service = CacheService(db_manager=self.db_manager)
        self.redis_cache = RedisCache(redis_client=redis_client)
        self.telemetry_window_cache = RedisTelemetryWindowCache(redis_client=redis_client)

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
        self.token_blacklist_repository = RedisTokenBlacklistRepository(redis_client=redis_client)
        self.user_repository = MongoUserRepository(db_manager=self.db_manager)

        # Services
        self.analytics_service = ReportTelemetryService(analytics_repository=self.analytics_repository)
        self.password_hasher = BcryptPasswordHasher()
        self.token_service = JwtTokenService()
        self.signature_verifier = HmacSignatureVerifier()
        self.user_service = UserService(
            user_repository=self.user_repository,
            password_hasher=self.password_hasher,
        )
        self.auth_service = AuthService(
            user_provider=self.user_service,
            token_blacklist_repository=self.token_blacklist_repository,
            token_service=self.token_service,
            access_token_expires_delta=timedelta(minutes=orchestrator_settings.jwt_expiration_minutes),
        )

        self.rules_bundle_cache = RedisRulesBundleCache(redis_client=redis_client)
        self.rule_validator = DefaultRuleValidatorService()

        self.rule_service = RuleService(
            rule_repository=self.rule_repository,
            audit_repository=self.audit_repository,
            rules_bundle_cache=self.rules_bundle_cache,
            rule_validator=self.rule_validator
        )
        self.rules_engine_service = RulesEngineService(rules_service=self.rule_service)
        self.telemetry_service = TelemetryService(repository=self.telemetry_repository)
        self.telemetry_client_service = TelemetryClientService(
            telemetry_client_repository=self.telemetry_client_repository,
            signature_verifier=self.signature_verifier,
        )
        self.telemetry_processing_service = TelemetryProcessingService(
            window_cache=self.telemetry_window_cache,
            window_duration_seconds=orchestrator_settings.window_duration_seconds,
            window_threshold_requests=orchestrator_settings.window_threshold_requests,
        )

        # Agent Runner — agent_factory centraliza el wiring MCP en cada reconexión
        self.agent_runner = AgentRunner(
            telemetry_processing_service=self.telemetry_processing_service,
            cache_service=self.cache_service,
            telemetry_service=self.telemetry_service,
            analytics_service=self.analytics_service,
            agent_factory=self._create_mcp_agent,
        )

        # === PASO 3: Inicializar Subsistemas Internos ===
        await self.rules_engine_service.initialize()
        self.agent_runner.initialize_subsystem()

    def _create_mcp_agent(self, mcp_manager: MCPClientManager) -> OrchestratorAgent:
        """Factory centralizada para construir el agente con sus dependencias MCP."""
        llm_adapter = MCPLlmAnalysisAdapter(mcp_manager=mcp_manager)
        threat_adapter = MCPThreatContextAdapter(mcp_manager=mcp_manager)
        analysis_svc = AnalysisService(
            llm_analysis_port=llm_adapter,
            rules_engine_service=self.rules_engine_service,
        )
        threat_ctx_svc = ThreatContextService(threat_context_port=threat_adapter)
        return OrchestratorAgent(
            cache_port=self.cache_service,
            analytics_service=self.analytics_service,
            threat_context_service=threat_ctx_svc,
            analysis_service=analysis_svc,
        )

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

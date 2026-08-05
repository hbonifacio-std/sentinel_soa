"""
Centralized dependency injection container for the Core Orchestrator.
"""

from functools import lru_cache
from datetime import timedelta

# Services
from core_orchestrator.application.modules.analysis_reports.services.analysis_service import AiAnalysis
from core_orchestrator.application.modules.analysis_reports.services.analytics_service import ReportTelemetryService
from core_orchestrator.application.modules.auth_clients.auth_service import AuthService
from core_orchestrator.application.modules.auth_clients.tenant_service import TenantService
from core_orchestrator.application.modules.analysis_reports.services.rule_service import RuleService
from core_orchestrator.application.modules.analysis_reports.services.rules_engine_service import RulesEngineService
from core_orchestrator.application.modules.auth_clients.user_service import UserService
from core_orchestrator.application.modules.telemetry.telemetry_window_manager_service import TelemetryProcessingService
from core_orchestrator.application.modules.telemetry.telemetry_service import TelemetryService
from core_orchestrator.application.modules.analysis_reports.services.threat_context_service import ThreatContextService
from core_orchestrator.application.modules.analysis_reports.services.default_rule_validator_service import DefaultRuleValidatorService
from core_orchestrator.application.modules.forensic.forensic_service import ForensicService
from core_orchestrator.infrastructure.adapters.redis.redis_black_list_adapter import \
    RedisTokenBlacklistAdapter
from core_orchestrator.infrastructure.adapters.redis.redis_keyspace_notification_adapter import \
    RedisKeyspaceNotificationAdapter
from core_orchestrator.infrastructure.adapters.security.password_hasher_adapter import PasswordHasherAdapter
from core_orchestrator.infrastructure.config.settings import orchestrator_settings

# Repositories and their Implementations
from core_orchestrator.infrastructure.adapters.mongodb.mongo_analytics_repository_adapter import MongoAnalyticsReportsAdapter
from core_orchestrator.infrastructure.persistence.mongo_audit_repository import MongoAuditRepository
from core_orchestrator.infrastructure.persistence.mongo_rule_repository import MongoRuleRepository
from core_orchestrator.infrastructure.persistence.caching_telemetry_client_repository import CachingTelemetryClientRepositoryPort
from core_orchestrator.infrastructure.adapters.mongodb.mongo_telemetry_repository_adapter import MongoTelemetryRepositoryPortAdapter
from core_orchestrator.infrastructure.adapters.mongodb.mongo_user_repository_adapter import MongoUserRepositoryAdapter
from core_orchestrator.infrastructure.adapters.mongodb.mongo_tenant_repository_adapter import MongoTenantRepositoryAdapter
from core_orchestrator.infrastructure.adapters.mongodb.mongo_forensic_analysis_repository_adapter import MongoForensicAnalysisRepositoryAdapter

# Core Infrastructure
from core_orchestrator.infrastructure.adapters.mpc_server.mcp_client_adapter import MCPClientManagerAdapter
from core_orchestrator.infrastructure.agent.mcp_forensic_intelligence_adapter import MCPForensicIntelligenceAdapter
from core_orchestrator.infrastructure.agent.mcp_llm_analysis_adapter import MCPLlmAnalysisAdapter
from core_orchestrator.infrastructure.agent.mcp_threat_context_adapter import MCPThreatContextAdapter
from core_orchestrator.application.modules.telemetry.telemetry_analysis_service import TelemetryAnalysisService
from core_orchestrator.infrastructure.adapters.workers.telemetry_processing_worker import TelemetryProcessingWorker
from core_orchestrator.infrastructure.cache.cache_service import CacheService
from core_orchestrator.infrastructure.adapters.redis.base_redis_adapter import BaseRedisCacheAdapter
from core_orchestrator.infrastructure.cache.redis_rules_bundle_cache import RedisRulesBundleCache
from core_orchestrator.infrastructure.adapters.redis.redis_telemetry_window_adapter import RedisTelemetryWindowAdapter
from core_orchestrator.infrastructure.config.config import orchestrator_settings_deprecated
from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
from core_orchestrator.infrastructure.rate_limit.rate_limiter import  limiter


from core_orchestrator.infrastructure.adapters.security.jwt_token_provider_adapter import JwtTokenProviderAdapter
from core_orchestrator.infrastructure.adapters.security.api_key_cipher_adapter import ApiKeyCipher
from core_orchestrator.infrastructure.cache.redis_tenant_provider_cache import RedisTenantProviderCache
from core_orchestrator.application.modules.auth_clients.tenant_provider_ai_service import TenantProviderAiService



class Container:
    """
    Singleton container for managing and providing application-wide dependencies.
    """

    def __init__(self):
        # 1. En el constructor SOLO inicializamos la infraestructura base síncrona
        self.db_manager = DatabaseManager()
        self.mcp_client_manager = MCPClientManagerAdapter()
        self.limiter = limiter

        # 2. Espacios para dependencias que necesitan conexión activa
        self.cache_service = None
        self.redis_cache = None
        self.telemetry_window_cache = None
        self.telemetry_window_notification_expiratory = None
        self.analytics_repository = None
        self.audit_repository = None
        self.rule_repository = None
        self.telemetry_client_repository = None
        self.telemetry_repository = None
        self.token_blacklist_repository = None
        self.user_repository = None
        self.tenant_repository = None
        self.rules_bundle_cache = None
        self.forensic_repository = None
        self.rule_validator = None
        self.password_hasher = None
        self.token_service = None
        self.signature_verifier = None

        self.analytics_service = None
        self.user_service = None
        self.tenant_service = None
        self.auth_service = None
        self.rule_service = None
        self.rules_engine_service = None
        self.telemetry_service = None
        self.telemetry_client_service = None
        self.telemetry_processing_service = None
        self.forensic_service = None
        self.forensic_intelligence_adapter = None
        self.agent_runner = None

    async def startup(self):
        """Connects to databases and initializes long-running services."""
        # === PASO 1: Conexiones reales ===
        self.db_manager.connect()
        if self.db_manager.redis_client_window_telemetry is None:
            raise RuntimeError("Redis client is not connected")

        redis_client_telemetry = self.db_manager.redis_client_window_telemetry
        redis_client_auth = self.db_manager.redis_client_auth
        redis_client_rules = self.db_manager.redis_client_rules

        # === PASO 2: Repositorios y Servicios ===
        self.telemetry_window_notification_expiratory = RedisKeyspaceNotificationAdapter(redis_client=redis_client_telemetry)
        await self.telemetry_window_notification_expiratory.start_listening()

        self.cache_service = CacheService(db_manager=self.db_manager)
        self.redis_cache = BaseRedisCacheAdapter(redis_client=redis_client_telemetry)
        self.telemetry_window_cache = RedisTelemetryWindowAdapter(redis_client=redis_client_telemetry)

        # Repositories
        self.analytics_repository = MongoAnalyticsReportsAdapter(db_manager=self.db_manager)
        self.audit_repository = MongoAuditRepository(db_manager=self.db_manager)
        self.rule_repository = MongoRuleRepository(db_manager=self.db_manager)

        mongo_telemetry_client_repo = MongoTenantRepositoryAdapter(db_manager=self.db_manager)
        self.telemetry_client_repository = CachingTelemetryClientRepositoryPort(
            primary_repository=mongo_telemetry_client_repo,
            cache=self.redis_cache
        )

        self.telemetry_repository = MongoTelemetryRepositoryPortAdapter(db_manager=self.db_manager)
        self.token_blacklist_repository = RedisTokenBlacklistAdapter(redis_client=redis_client_auth)
        self.user_repository = MongoUserRepositoryAdapter(db_manager=self.db_manager)
        self.tenant_repository = MongoTenantRepositoryAdapter(db_manager=self.db_manager)
        self.forensic_repository = MongoForensicAnalysisRepositoryAdapter(db_manager=self.db_manager)

        await self.rule_repository.ensure_indexes()
        await self.audit_repository.ensure_indexes()

        # Services
        self.analytics_service = ReportTelemetryService(analytics_repository=self.analytics_repository,
                                                        redis_client= redis_client_telemetry)

        self.token_service = JwtTokenProviderAdapter()

        self.password_hasher = PasswordHasherAdapter()
        self.user_service = UserService(
            user_repository=self.user_repository,
            password_hasher=self.password_hasher,
        )
        self.tenant_service = TenantService(tenant_repository=self.tenant_repository)
        self.api_key_cipher = ApiKeyCipher(
            orchestrator_settings_deprecated.tenant_api_key_encryption_key.get_secret_value()
        )
        self.tenant_provider_cache = RedisTenantProviderCache(redis_client=redis_client_auth)
        self.tenant_provider_service = TenantProviderAiService(
            tenant_repository=self.tenant_repository,
            cipher=self.api_key_cipher,
            cache_repository=redis_client_auth,
        )
        self.auth_service = AuthService(
            user_service=self.user_service,
            token_blacklist_repo=self.token_blacklist_repository,
            token_service=self.token_service,
            access_token_expires_delta=timedelta(minutes=orchestrator_settings.security.jwt_expiration_minutes),
            refresh_token_expires_delta=timedelta(minutes=orchestrator_settings.security.jwt_expiration_refresh_days)
        )

        self.rules_bundle_cache = RedisRulesBundleCache(redis_client=redis_client_rules)
        self.rule_validator = DefaultRuleValidatorService()

        self.rule_service = RuleService(
            rule_repository=self.rule_repository,
            audit_repository=self.audit_repository,
            rules_bundle_cache=self.rules_bundle_cache,
            rule_validator=self.rule_validator
        )
        self.rules_engine_service = RulesEngineService(rules_service=self.rule_service)
        self.telemetry_service = TelemetryService(repository=self.telemetry_repository)

        self.telemetry_processing_service = TelemetryProcessingService(
            window_cache=self.telemetry_window_cache,
            window_duration_seconds=orchestrator_settings.detection.window_duration_seconds,
            window_threshold_requests=orchestrator_settings.detection.window_threshold_requests,
        )
        self.forensic_intelligence_adapter = MCPForensicIntelligenceAdapter(mcp_manager=self.mcp_client_manager)
        self.forensic_service = ForensicService(
            forensic_repository=self.forensic_repository,
            forensic_intelligence_port=self.forensic_intelligence_adapter,
            tenant_provider_service=self.tenant_provider_service,
        )

        # Agent Runner — agent_factory centraliza el wiring MCP en cada reconexión
        self.agent_runner = TelemetryProcessingWorker(
            telemetry_processing_service=self.telemetry_processing_service,
            cache_service=self.cache_service,
            telemetry_service=self.telemetry_service,
            analytics_service=self.analytics_service,
            agent_factory=self._create_mcp_agent,
        )

        # === PASO 3: Inicializar Subsistemas Internos ===
        await self.rules_engine_service.initialize()
        self.agent_runner.initialize_subsystem()

    def _create_mcp_agent(self, mcp_manager: MCPClientManagerAdapter) -> TelemetryAnalysisService:
        """Factory centralizada para construir el agente con sus dependencias MCP."""
        llm_adapter = MCPLlmAnalysisAdapter(mcp_manager=mcp_manager)
        threat_adapter = MCPThreatContextAdapter(mcp_manager=mcp_manager)
        analysis_svc = AiAnalysis(
            llm_analysis_port=llm_adapter,
            rules_engine_service=self.rules_engine_service,
            tenant_provider_service=self.tenant_provider_service,
        )
        threat_ctx_svc = ThreatContextService(threat_context_port=threat_adapter)
        return TelemetryAnalysisService(
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
        if self.db_manager.redis_client_window_telemetry:
            await self.db_manager.redis_client_window_telemetry.close()


# Use lru_cache to ensure the container is a singleton
@lru_cache(maxsize=1)
def get_container() -> Container:
    return Container()

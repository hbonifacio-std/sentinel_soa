"""
Centralized dependency injection container for the Core Orchestrator.
"""

from functools import lru_cache
from datetime import timedelta

from core_orchestrator.infrastructure.adapters.ai_providers.Ai_analysis_adapter import AiAnalysisAdapter
from core_orchestrator.application.modules.telemetry.telemetry_report_service import TelemetryReportService
from core_orchestrator.application.modules.auth_clients.auth_service import AuthService
from core_orchestrator.application.modules.auth_clients.tenant_service import TenantService
from core_orchestrator.application.modules.rules_heuristics.rule_service import RuleService
from core_orchestrator.application.modules.rules_heuristics.rules_engine_service import RulesEngineService
from core_orchestrator.application.modules.auth_clients.user_service import UserService
from core_orchestrator.application.modules.telemetry.telemetry_window_manager_service import TelemetryManagerWindowService
from core_orchestrator.application.modules.telemetry.telemetry_service import TelemetryService
from core_orchestrator.infrastructure.adapters.ai_providers.provider_factory import ProviderFactory
from core_orchestrator.infrastructure.adapters.helper.default_rule_validator_adapter import DefaultRuleValidatorAdapter
from core_orchestrator.application.modules.forensic.forensic_service import ForensicService
from core_orchestrator.infrastructure.adapters.mongodb.mongo_audit_repository import MongoAuditRepositoryAdapter
from core_orchestrator.infrastructure.adapters.redis.redis_black_list_adapter import \
    RedisTokenBlacklistAdapter
from core_orchestrator.infrastructure.adapters.redis.redis_telemetry_tenant_adapter import \
    RedisTelemetryTenantRepositoryAdapter
from core_orchestrator.infrastructure.adapters.workers.redis_telemetry_window_analysis_worker import (
    RedisTelemetryWindowAnalysisWorker,
)
from core_orchestrator.infrastructure.adapters.security.password_hasher_adapter import PasswordHasherAdapter
from core_orchestrator.infrastructure.config.settings import orchestrator_settings
from core_orchestrator.infrastructure.adapters.mongodb.mongo_analytics_repository_adapter import MongoAnalyticsReportsAdapter
from core_orchestrator.infrastructure.adapters.mongodb.mongo_rule_repository import MongoAuditRulesAdapter
from core_orchestrator.infrastructure.adapters.mongodb.mongo_telemetry_repository_adapter import MongoTelemetryAdapter
from core_orchestrator.infrastructure.adapters.mongodb.mongo_user_repository_adapter import MongoUserRepositoryAdapter
from core_orchestrator.infrastructure.adapters.mongodb.mongo_tenant_repository_adapter import MongoTenantRepositoryAdapter
from core_orchestrator.infrastructure.adapters.mongodb.mongo_forensic_analysis_repository_adapter import MongoForensicAnalysisRepositoryAdapter
from core_orchestrator.infrastructure.adapters.neo4j.neo4j_telemetry_graph_repository_adapter import (
    Neo4jTelemetryGraphRepositoryAdapter,
)
from core_orchestrator.infrastructure.adapters.mpc_server.mcp_client_adapter import MCPClientManagerAdapter
from core_orchestrator.infrastructure.agent.mcp_forensic_intelligence_adapter import MCPForensicIntelligenceAdapter
from core_orchestrator.infrastructure.adapters.ai_providers.llm_executer_analysis_adapter import LlmExecuterAnalysisAdapter
from core_orchestrator.application.modules.telemetry.telemetry_analysis_service import TelemetryAnalysisService
from core_orchestrator.application.modules.telemetry.telemetry_analysis_orchestrator_service import TelemetryAnalysisOrchestratorService
from core_orchestrator.infrastructure.adapters.redis.base_redis_adapter import RedisBaseCacheAdapter
from core_orchestrator.infrastructure.adapters.redis.redis_rules_bundle_adapter import RedisRulesBundleAdapter
from core_orchestrator.infrastructure.adapters.redis.redis_telemetry_window_adapter import RedisBaseTelemetryWindowAdapter
from core_orchestrator.infrastructure.config.config import orchestrator_settings_deprecated
from core_orchestrator.infrastructure.database.database_manager import DatabaseManager
from core_orchestrator.infrastructure.rate_limit.rate_limiter import  limiter
from core_orchestrator.infrastructure.adapters.security.jwt_token_provider_adapter import JwtTokenProviderAdapter
from core_orchestrator.infrastructure.adapters.security.api_key_cipher_adapter import ApiKeyCipherAdapter
from core_orchestrator.application.modules.auth_clients.tenant_provider_ai_service import TenantProviderAiService



class Container:
    """
    Singleton container for managing and providing application-wide dependencies.
    """

    def __init__(self):
        # 1. In the constructor, we ONLY initialize the synchronous base infrastructure
        self.db_manager = DatabaseManager()
        self.mcp_client_manager = MCPClientManagerAdapter()
        self.limiter = limiter

        # 2 Basic Redis connections pointing to each database.
        self.redis_base_telemetry_cache = None
        self.redis_base_rules_cache = None
        self.redis_base_auth_cache = None

        self.telemetry_window_cache_adapter = None
        self.redis_telemetry_tenant_repository_adapter = None
        self.token_blacklist_repository_adapter = None
        self.redis_rules_bundle_adapter = None

        self.default_rule_validator_adapter = None

        # 3. adapters for MongoDB databases
        self.mongo_analytics_report_adapter = None
        self.mongo_rule_repository_adapter = None
        self.mongo_audit_rules_repository_adapter = None
        self.mongo_telemetry_adapter = None
        self.mongo_user_repository_adapter = None
        self.mongo_tenant_repository_adapter = None
        self.mongo_forensic_repository_adapter = None
        self.neo4j_telemetry_graph_repository = None

        # AI provider
        self.ia_provider_client = None
        self.llm_adapter = None
        self.analysis_svc = None

        # password hasher and token service
        self.password_hasher_adapter = None
        self.jwt_token_provider_adapter = None
        self.api_key_cipher_adapter = None

        # 4. services

        self.user_service = None
        self.tenant_service = None
        self.auth_service = None
        self.tenant_provider_ai_service = None

        self.rule_service = None
        self.rules_engine_service = None

        self.telemetry_service = None
        self.telemetry_reports_service = None
        self.telemetry_manager_window_service = None
        self.telemetry_analysis_orchestrator_service = None
        self.telemetry_window_analysis_worker = None

        self.forensic_service = None

        ## adapters to be replaced
        self.forensic_intelligence_adapter = None


    async def startup(self):
        """Connects to databases and initializes long-running services."""
        # === STEP 1: Real connections ===
        self.db_manager.connect()
        if self.db_manager.redis_client_window_telemetry is None:
            raise RuntimeError("Redis client is not connected")

        if self.mcp_client_manager:
            await  self.mcp_client_manager.start_server_session()

        redis_client_telemetry = self.db_manager.redis_client_window_telemetry
        redis_client_auth = self.db_manager.redis_client_auth
        redis_client_rules = self.db_manager.redis_client_rules

        # === STEP 2: Repositories and Services ===
        self.redis_base_telemetry_cache = RedisBaseCacheAdapter(redis_client=redis_client_telemetry)
        self.redis_base_auth_cache = RedisBaseCacheAdapter(redis_client=redis_client_auth)
        self.redis_base_rules_cache = RedisBaseCacheAdapter(redis_client=redis_client_rules)
        self.telemetry_window_cache_adapter = RedisBaseTelemetryWindowAdapter(redis_client=redis_client_telemetry)

        # Repositories
        self.neo4j_telemetry_graph_repository = Neo4jTelemetryGraphRepositoryAdapter(
            db_manager=self.db_manager
        )
        self.mongo_analytics_report_adapter = MongoAnalyticsReportsAdapter(
            db_manager=self.db_manager,
            graph_repository=self.neo4j_telemetry_graph_repository,
        )

        self.mongo_audit_rules_repository_adapter = MongoAuditRepositoryAdapter(db_manager=self.db_manager)
        self.mongo_rule_repository_adapter = MongoAuditRulesAdapter(db_manager=self.db_manager)


        self.mongo_telemetry_adapter = MongoTelemetryAdapter(
            db_manager=self.db_manager,
            graph_repository=self.neo4j_telemetry_graph_repository,
        )
        self.token_blacklist_repository_adapter = RedisTokenBlacklistAdapter(redis_client=redis_client_auth)
        self.mongo_user_repository_adapter = MongoUserRepositoryAdapter(db_manager=self.db_manager)
        self.mongo_tenant_repository_adapter = MongoTenantRepositoryAdapter(db_manager=self.db_manager)
        self.mongo_forensic_repository_adapter = MongoForensicAnalysisRepositoryAdapter(db_manager=self.db_manager)


        # Services
        self.telemetry_reports_service = TelemetryReportService(
            analytics_repository=self.mongo_analytics_report_adapter
        )

        self.jwt_token_provider_adapter = JwtTokenProviderAdapter()

        self.password_hasher_adapter = PasswordHasherAdapter()
        self.user_service = UserService(
            user_repository=self.mongo_user_repository_adapter,
            password_hasher=self.password_hasher_adapter,
        )
        self.tenant_service = TenantService(tenant_repository=self.mongo_tenant_repository_adapter)
        self.api_key_cipher_adapter = ApiKeyCipherAdapter(
            orchestrator_settings_deprecated.tenant_api_key_encryption_key.get_secret_value()
        )
        self.redis_telemetry_tenant_repository_adapter= RedisTelemetryTenantRepositoryAdapter(
            redis_client=redis_client_auth
        )
        self.tenant_provider_ai_service = TenantProviderAiService(
            tenant_repository=self.mongo_tenant_repository_adapter,
            cipher=self.api_key_cipher_adapter,
            redis_tenant=self.tenant_provider_ai_service,
        )
        self.auth_service = AuthService(
            user_service=self.user_service,
            token_blacklist_repo=self.token_blacklist_repository_adapter,
            token_service=self.jwt_token_provider_adapter,
            access_token_expires_delta=timedelta(minutes=orchestrator_settings.security.jwt_expiration_minutes),
            refresh_token_expires_delta=timedelta(minutes=orchestrator_settings.security.jwt_expiration_refresh_days)
        )

        self.redis_rules_bundle_adapter = RedisRulesBundleAdapter(redis_client=redis_client_rules)
        self.default_rule_validator_adapter = DefaultRuleValidatorAdapter()

        self.rule_service = RuleService(
            rule_repository=self.mongo_rule_repository_adapter,
            audit_repository=self.mongo_audit_rules_repository_adapter,
            rules_bundle_cache=self.redis_rules_bundle_adapter,
            rule_validator=self.default_rule_validator_adapter
        )
        self.rules_engine_service = RulesEngineService(rules_service=self.rule_service)
        self.telemetry_service = TelemetryService(repository=self.mongo_telemetry_adapter)

        self.telemetry_manager_window_service = TelemetryManagerWindowService(
            window_cache=self.telemetry_window_cache_adapter,
            window_duration_seconds=orchestrator_settings.detection.window_duration_seconds,
            window_threshold_requests=orchestrator_settings.detection.window_threshold_requests,
        )


        self.forensic_intelligence_adapter = MCPForensicIntelligenceAdapter(mcp_manager=self.mcp_client_manager)


        self.llm_adapter = LlmExecuterAnalysisAdapter(
            mcp_manager=self.mcp_client_manager
        )

        self.analysis_svc = AiAnalysisAdapter(
            llm_analysis=self.llm_adapter,
            rules_engine_service=self.rules_engine_service,
            tenant_provider_service=self.tenant_provider_ai_service,
            provider_factory=ProviderFactory(cipher_adapter=self.api_key_cipher_adapter)
        )

        self.forensic_service = ForensicService(
            forensic_repository=self.mongo_forensic_repository_adapter,
            provider_ai_factory=ProviderFactory(self.api_key_cipher_adapter),
            tenant_provider_service=self.tenant_provider_ai_service,
            llm_analysis=self.llm_adapter
        )

        # Agent Runner — agent_factory centralizes MCP wiring upon each reconnection.
        self.telemetry_analysis_orchestrator_service = TelemetryAnalysisOrchestratorService(
            telemetry_service=self.telemetry_service,
            telemetry_analysis_service=TelemetryAnalysisService(
                    analytics_report=self.mongo_analytics_report_adapter,
                    ia_analysis=self.analysis_svc,
            )
        )
        await self.telemetry_manager_window_service.start_listening()
        self.telemetry_window_analysis_worker = RedisTelemetryWindowAnalysisWorker(
            redis_client=redis_client_telemetry,
            telemetry_analysis_orchestrator_service=self.telemetry_analysis_orchestrator_service,
        )
        self.telemetry_window_analysis_worker.start()
        # === STEP 3: Initialize Internal Subsystems ===
        await self.rules_engine_service.initialize()
        self.telemetry_analysis_orchestrator_service.initialize_subsystem()


    async def shutdown(self):
        """Cleans up resources, closing connections, and stopping services."""
        if self.telemetry_window_analysis_worker:
            await self.telemetry_window_analysis_worker.stop()
        if self.telemetry_analysis_orchestrator_service:
            await self.telemetry_analysis_orchestrator_service.shutdown_subsystem()
        if self.db_manager.mongo_client:
            await self.db_manager.mongo_client.close()
        if self.db_manager.neo4j_driver:
            await self.db_manager.neo4j_driver.close()
        if self.db_manager.redis_client_window_telemetry:
            await self.db_manager.redis_client_window_telemetry.close()
        if self.mcp_client_manager:
            await self.mcp_client_manager.close()


# Use lru_cache to ensure the container is a singleton
@lru_cache(maxsize=1)
def get_container() -> Container:
    return Container()

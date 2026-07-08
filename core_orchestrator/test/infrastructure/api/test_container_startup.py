import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from core_orchestrator.infrastructure.api.container import Container, get_container

# Fixtures to mock heavy dependencies
@pytest.fixture
def mock_db_manager():
    with patch('core_orchestrator.infrastructure.api.container.DatabaseManager') as MockDBManager:
        instance = MockDBManager.return_value
        instance.connect.return_value = None
        # Provide dummy redis and mongo clients
        instance.redis_client = MagicMock()
        instance.mongo_client = MagicMock()
        yield instance

@pytest.fixture
def mock_cache_and_services():
    with patch('core_orchestrator.infrastructure.api.container.CacheService') as MockCacheService, \
         patch('core_orchestrator.infrastructure.api.container.RedisCache') as MockRedisCache, \
         patch('core_orchestrator.infrastructure.api.container.RedisTelemetryWindowCache') as MockTelemetryWindowCache:
        yield (MockCacheService, MockRedisCache, MockTelemetryWindowCache)

@pytest.fixture
def mock_repositories_and_services():
    # Patch all repository and service constructors used in Container.startup
    patches = [
        patch('core_orchestrator.infrastructure.api.container.MongoAnalyticsRepository'),
        patch('core_orchestrator.infrastructure.api.container.MongoAuditRepository'),
        patch('core_orchestrator.infrastructure.api.container.MongoRuleRepository'),
        patch('core_orchestrator.infrastructure.api.container.MongoTelemetryClientRepository'),
        patch('core_orchestrator.infrastructure.api.container.CachingTelemetryClientRepository'),
        patch('core_orchestrator.infrastructure.api.container.MongoTelemetryRepository'),
        patch('core_orchestrator.infrastructure.api.container.RedisTokenBlacklistRepository'),
        patch('core_orchestrator.infrastructure.api.container.MongoUserRepository'),
        patch('core_orchestrator.infrastructure.api.container.MongoForensicAnalysisRepository'),
        patch('core_orchestrator.infrastructure.api.container.ReportTelemetryService'),
        patch('core_orchestrator.infrastructure.api.container.BcryptPasswordHasher'),
        patch('core_orchestrator.infrastructure.api.container.JwtTokenService'),
        patch('core_orchestrator.infrastructure.api.container.HmacSignatureVerifier'),
        patch('core_orchestrator.infrastructure.api.container.UserService'),
        patch('core_orchestrator.infrastructure.api.container.AuthService'),
        patch('core_orchestrator.infrastructure.api.container.RuleService'),
        patch('core_orchestrator.infrastructure.api.container.RulesEngineService'),
        patch('core_orchestrator.infrastructure.api.container.TelemetryService'),
        patch('core_orchestrator.infrastructure.api.container.TelemetryClientService'),
        patch('core_orchestrator.infrastructure.api.container.TelemetryProcessingService'),
        patch('core_orchestrator.infrastructure.api.container.ForensicService'),
        patch('core_orchestrator.infrastructure.api.container.MCPForensicIntelligenceAdapter'),
        patch('core_orchestrator.infrastructure.api.container.AgentRunner'),
    ]
    for p in patches:
        p.start()
    # Ensure RulesEngineService.initialize is an async mock (awaitable)
    from core_orchestrator.infrastructure.api import container as container_mod
    container_mod.RulesEngineService.return_value.initialize = AsyncMock()
    yield
    for p in patches:
        p.stop()

@pytest.mark.asyncio
async def test_container_startup(mock_db_manager, mock_cache_and_services, mock_repositories_and_services):
    """Container.startup should initialize all dependencies without raising."""
    container = Container()
    await container.startup()
    # Verify that key attributes are no longer None after startup
    assert container.cache_service is not None
    assert container.redis_cache is not None
    assert container.analytics_repository is not None
    assert container.auth_service is not None
    assert container.agent_runner is not None
    # Ensure DatabaseManager.connect was called
    mock_db_manager.connect.assert_called_once()

def test_get_container_is_singleton():
    """get_container should return the same Container instance each call (singleton)."""
    c1 = get_container()
    c2 = get_container()
    assert c1 is c2

@pytest.mark.asyncio
async def test_container_startup_no_redis_raises(mock_db_manager):
    """If redis_client is None, startup should raise RuntimeError."""
    mock_db_manager.redis_client = None
    container = Container()
    with pytest.raises(RuntimeError, match="Redis client is not connected"):
        await container.startup()

@pytest.mark.asyncio
async def test_container_shutdown(mock_db_manager):
    container = Container()
    container.agent_runner = AsyncMock()
    container.db_manager.mongo_client = AsyncMock()
    container.db_manager.redis_client = AsyncMock()

    await container.shutdown()
    container.agent_runner.shutdown_subsystem.assert_awaited_once()
    container.db_manager.mongo_client.close.assert_awaited_once()
    container.db_manager.redis_client.close.assert_awaited_once()

@pytest.mark.asyncio
async def test_create_mcp_agent():
    container = Container()
    container.cache_service = MagicMock()
    container.analytics_service = MagicMock()
    container.rules_engine_service = MagicMock()
    
    mock_mcp_mgr = MagicMock()
    agent = container._create_mcp_agent(mock_mcp_mgr)
    from core_orchestrator.infrastructure.agent.orchestrator import OrchestratorAgent
    assert isinstance(agent, OrchestratorAgent)


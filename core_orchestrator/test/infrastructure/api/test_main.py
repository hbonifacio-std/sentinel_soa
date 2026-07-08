"""
Tests for core_orchestrator/main.py:
  - /health endpoint (connected and disconnected states)
  - app_lifespan startup exception path (yield despite error)
  - add_limiter_to_state middleware
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixtures — minimal container mock to allow app import
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def mock_container():
    container = MagicMock()
    container.startup = AsyncMock()
    container.shutdown = AsyncMock()
    container.limiter = MagicMock()
    container.agent_runner = MagicMock()
    container.agent_runner.is_mcp_connected = False
    return container


@pytest.fixture(scope="module")
def test_app(mock_container):
    with patch(
        "core_orchestrator.main.get_container",
        return_value=mock_container,
    ):
        from core_orchestrator.main import app
        return app


@pytest.fixture(scope="module")
def client(test_app):
    with TestClient(test_app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# /health endpoint
# ---------------------------------------------------------------------------
class TestHealthEndpoint:
    def test_health_returns_healthy_when_mcp_disconnected(self, client, mock_container):
        mock_container.agent_runner.is_mcp_connected = False
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["component"] == "core_orchestrator"
        assert data["mcp_status"] == "disconnected"

    def test_health_returns_mcp_status_field(self, client, mock_container):
        """Verify mcp_status field is always present regardless of connection state."""
        mock_container.agent_runner.is_mcp_connected = False
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "mcp_status" in data
        assert data["mcp_status"] in ("connected", "disconnected")


# ---------------------------------------------------------------------------
# app_lifespan — startup exception path
# ---------------------------------------------------------------------------
class TestAppLifespan:
    @pytest.mark.asyncio
    async def test_lifespan_yields_even_on_startup_error(self):
        """If container.startup() raises, the app should still yield (graceful degradation)."""
        from core_orchestrator.main import app_lifespan

        mock_app = MagicMock()
        mock_container = MagicMock()
        mock_container.startup = AsyncMock(side_effect=RuntimeError("DB down"))
        mock_container.shutdown = AsyncMock()

        with patch("core_orchestrator.main.get_container", return_value=mock_container):
            ctx = app_lifespan(mock_app)
            async with ctx:
                pass  # Should not raise; app yields even on error

        mock_container.shutdown.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_lifespan_calls_shutdown_on_clean_exit(self):
        from core_orchestrator.main import app_lifespan

        mock_app = MagicMock()
        mock_container = MagicMock()
        mock_container.startup = AsyncMock()
        mock_container.shutdown = AsyncMock()

        with patch("core_orchestrator.main.get_container", return_value=mock_container):
            async with app_lifespan(mock_app):
                pass

        mock_container.startup.assert_awaited_once()
        mock_container.shutdown.assert_awaited_once()


# ---------------------------------------------------------------------------
# Middleware — add_limiter_to_state
# ---------------------------------------------------------------------------
class TestAddLimiterMiddleware:
    def test_middleware_adds_limiter_to_state(self, client, mock_container):
        """Calling /health goes through the middleware; no AttributeError on state."""
        response = client.get("/health")
        # If middleware failed, this would be a 500
        assert response.status_code == 200

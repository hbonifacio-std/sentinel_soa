import pytest

from mcp_servers.log_analysis_server.security import (
    get_user_role,
    set_user_role,
    validate_bearer_token_with_role,
)
from mcp_servers.log_analysis_server.tool_access_control import require_tool_permission


def test_validate_bearer_token_uses_legacy_token_as_analyst(monkeypatch):
    monkeypatch.setenv("MCP_INTERNAL_TOKEN", "legacy-analyst-token")
    monkeypatch.delenv("MCP_INTERNAL_TOKEN_ANALYST", raising=False)
    monkeypatch.delenv("MCP_INTERNAL_TOKENS_ANALYST", raising=False)
    set_user_role(None)

    assert validate_bearer_token_with_role("Bearer legacy-analyst-token") is True
    assert get_user_role() == "analyst"


def test_validate_bearer_token_maps_role_specific_tokens(monkeypatch):
    monkeypatch.setenv("MCP_INTERNAL_TOKEN_ADMIN", "admin-token-1")
    monkeypatch.delenv("MCP_INTERNAL_TOKEN", raising=False)
    set_user_role(None)

    assert validate_bearer_token_with_role("Bearer admin-token-1") is True
    assert get_user_role() == "admin"


def test_validate_bearer_token_fails_closed_without_config(monkeypatch):
    monkeypatch.delenv("MCP_INTERNAL_TOKEN", raising=False)
    monkeypatch.delenv("MCP_INTERNAL_TOKEN_ADMIN", raising=False)
    monkeypatch.delenv("MCP_INTERNAL_TOKEN_ANALYST", raising=False)
    monkeypatch.delenv("MCP_INTERNAL_TOKEN_VIEWER", raising=False)
    monkeypatch.delenv("MCP_INTERNAL_TOKENS", raising=False)
    monkeypatch.delenv("MCP_INTERNAL_TOKENS_ADMIN", raising=False)
    monkeypatch.delenv("MCP_INTERNAL_TOKENS_ANALYST", raising=False)
    monkeypatch.delenv("MCP_INTERNAL_TOKENS_VIEWER", raising=False)
    set_user_role(None)

    assert validate_bearer_token_with_role("Bearer any-token") is False


@require_tool_permission("get_available_models")
async def _secured_tool() -> str:
    return "ok"


@pytest.mark.asyncio
async def test_tool_permission_denies_missing_role():
    set_user_role(None)
    with pytest.raises(PermissionError):
        await _secured_tool()

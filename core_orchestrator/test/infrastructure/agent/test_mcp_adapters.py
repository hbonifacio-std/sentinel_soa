import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from core_orchestrator.infrastructure.adapters.mpc_server.mcp_client_adapter import MCPClientManagerAdapter
from core_orchestrator.infrastructure.agent.mcp_llm_analysis_adapter import MCPLlmAnalysisAdapter
from core_orchestrator.infrastructure.agent.mcp_forensic_intelligence_adapter import MCPForensicIntelligenceAdapter
from core_orchestrator.infrastructure.agent.mcp_threat_context_adapter import MCPThreatContextAdapter
from core_orchestrator.infrastructure.agent.orchestrator import OrchestratorAgent

@pytest.fixture
def mock_mcp_manager():
    return AsyncMock()

@pytest.mark.asyncio
async def test_llm_analysis_adapter(mock_mcp_manager):
    adapter = MCPLlmAnalysisAdapter(mock_mcp_manager)
    
    # Text content result case
    mock_content = MagicMock()
    mock_content.text = '{"threat_detected": true, "threat_score": 85}'
    mock_result = MagicMock()
    mock_result.content = [mock_content]
    mock_mcp_manager.call_tool.return_value = mock_result
    
    res = await adapter.analyze_web_activity({"ip": "1.2.3.4"})
    assert res["threat_detected"] is True
    assert res["threat_score"] == 85
    
    # Dict fallback case
    mock_mcp_manager.call_tool.return_value = {"threat_detected": False}
    res = await adapter.analyze_web_activity({"ip": "1.2.3.4"})
    assert res["threat_detected"] is False


@pytest.mark.asyncio
async def test_llm_analysis_adapter_timeout_returns_fallback(mock_mcp_manager):
    adapter = MCPLlmAnalysisAdapter(mock_mcp_manager)

    async def slow_call_tool(*args, **kwargs):
        await asyncio.sleep(0.05)

    mock_mcp_manager.call_tool.side_effect = slow_call_tool

    with patch("core_orchestrator.infrastructure.agent.mcp_llm_analysis_adapter._MCP_TOOL_TIMEOUT_S", 0.01):
        result = await adapter.analyze_web_activity({"source_ip": "1.2.3.4"})

    assert result["source_ip"] == "1.2.3.4"
    assert result["threat_detected"] is False
    assert result["threat_score"] == 0
    assert result["error"] == "MCP analysis timed out"

@pytest.mark.asyncio
async def test_forensic_intelligence_adapter(mock_mcp_manager):
    adapter = MCPForensicIntelligenceAdapter(mock_mcp_manager)
    
    mock_content = MagicMock()
    mock_content.text = '{"mongo_filter": {"ip": "1.2.3.4"}}'
    mock_result = MagicMock()
    mock_result.content = [mock_content]
    mock_mcp_manager.call_tool.return_value = mock_result
    
    res = await adapter.generate_mongo_query_from_nl("query", "src-1")
    assert res["mongo_filter"] == {"ip": "1.2.3.4"}
    
    mock_content.text = '{"report": "forensic data"}'
    res = await adapter.generate_forensic_report_from_logs("query", "src-1", 10, [{"log": 1}])
    assert res["report"] == "forensic data"

@pytest.mark.asyncio
async def test_threat_context_adapter(mock_mcp_manager):
    adapter = MCPThreatContextAdapter(mock_mcp_manager)
    
    mock_content = MagicMock()
    mock_content.text = '{"threat_history": []}'
    mock_result = MagicMock()
    mock_result.content = [mock_content]
    mock_mcp_manager.call_tool.return_value = mock_result
    
    res = await adapter.get_threat_context("1.2.3.4")
    assert "threat_history" in res

@pytest.mark.asyncio
async def test_orchestrator_agent():
    cache_port = AsyncMock()
    analysis_service = AsyncMock()
    analytics_service = AsyncMock()
    threat_context_service = AsyncMock()
    
    agent = OrchestratorAgent(cache_port, analysis_service, analytics_service, threat_context_service)
    
    # Cache hit case
    cache_port.get.return_value = '{"cached": true}'
    payload = {"source_ip": "1.2.3.4"}
    res = await agent.process_telemetry_window(payload)
    assert res == '{"cached": true}'
    
    # Cache miss + No threat case
    cache_port.get.return_value = None
    analysis_result = {"source_ip": "1.2.3.4", "threat_detected": False}
    analysis_service.analyze_activity.return_value = analysis_result
    
    res = await agent.process_telemetry_window(payload)
    assert "threat_detected" in res
    threat_context_service.get_historical_context.assert_not_called()
    
    # Cache miss + Threat detected case
    analysis_result = {
        "source_ip": "1.2.3.4",
        "source_id": "victim-app",
        "client_id": "tenant-42",
        "threat_detected": True,
    }
    analysis_service.analyze_activity.return_value = analysis_result
    threat_context_service.get_historical_context.return_value = {"threat_history": ["prev"]}

    res = await agent.process_telemetry_window(payload)
    assert "threat_history" in res
    threat_context_service.get_historical_context.assert_called_once_with("1.2.3.4")
    analytics_service.create_analysis_report.assert_called()
    assert analytics_service.create_analysis_report.await_args.kwargs["report_data"].source_id == "victim-app"
    assert analytics_service.create_analysis_report.await_args.kwargs["report_data"].client_id == "tenant-42"

@pytest.mark.asyncio
@patch("core_orchestrator.infrastructure.agent.mcp_client._sse_client")
@patch("core_orchestrator.infrastructure.agent.mcp_client.ClientSession")
async def test_mcp_client_manager(mock_session_cls, mock_streamable_client):
    manager = MCPClientManagerAdapter()
    
    # Setup mock transport & session
    mock_transport = AsyncMock()
    mock_transport.__aenter__.return_value = (AsyncMock(), AsyncMock())
    mock_streamable_client.return_value = mock_transport
    
    mock_session = AsyncMock()
    mock_session_cls.return_value = mock_session
    mock_session.__aenter__.return_value = mock_session
    
    # Connect
    with patch.dict(
        "os.environ",
        {"MCP_TRANSPORT": "sse", "MCP_SERVER_HOST": "localhost", "MCP_INTERNAL_TOKEN": "test-token"},
    ):
        session = await manager.start_server_session()
        assert session == mock_session
        
        # Call tool
        mock_session.call_tool.return_value = {"ok": True}
        res = await manager.call_tool("my_tool", {"arg": 1})
        assert res == {"ok": True}
        
        # Close
        await manager.close()

"""
Tests for MCP adapter _parse_result fallback paths (lines 28-30 / 47-50):
  - Invalid JSON in content[0].text → error fallback dict
  - Empty content list → fallback
  - Non-dict raw_result without content attr → empty dict
These are the lines NOT covered by the existing test_mcp_adapters.py.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


# ---------------------------------------------------------------------------
# MCPLlmAnalysisAdapter — _parse_result fallback paths (lines 28-30)
# ---------------------------------------------------------------------------
class TestMcpLlmAnalysisAdapterFallbacks:
    @pytest.fixture
    def adapter(self):
        from core_orchestrator.infrastructure.adapters.ai_providers.llm_executer_analysis_adapter import LlmExecuterAnalysisAdapter
        return LlmExecuterAnalysisAdapter(AsyncMock())

    def test_parse_invalid_json_returns_default(self, adapter):
        mock_content = MagicMock()
        mock_content.text = "NOT-JSON{"
        mock_result = MagicMock()
        mock_result.content = [mock_content]
        result = adapter._parse_result(mock_result)
        assert result == {"threat_detected": False, "threat_score": 0}

    def test_parse_empty_content_list_returns_raw_if_dict(self, adapter):
        mock_result = MagicMock()
        mock_result.content = []  # hasattr but empty → falsy
        # Falls through to: return raw_result if isinstance(raw_result, dict) else {}
        # mock_result is NOT a dict
        result = adapter._parse_result(mock_result)
        assert result == {}

    def test_parse_plain_dict_returns_it(self, adapter):
        result = adapter._parse_result({"threat_detected": True, "threat_score": 90})
        assert result["threat_detected"] is True

    def test_parse_non_dict_no_content_returns_empty(self, adapter):
        result = adapter._parse_result("plain string")
        assert result == {"response": "plain string"}

    def test_parse_json_code_fence_returns_dict(self, adapter):
        mock_content = MagicMock()
        mock_content.text = """```json
{"threat_detected": true, "threat_score": 88, "reasoning_summary": "Detected SQLi pattern"}
```"""
        mock_result = MagicMock()
        mock_result.content = [mock_content]
        result = adapter._parse_result(mock_result)
        assert result["threat_detected"] is True
        assert result["threat_score"] == 88

    def test_parse_wrapped_text_with_embedded_json(self, adapter):
        mock_content = MagicMock()
        mock_content.text = (
            "Threat decision generated:\n"
            '{"threat_detected": true, "threat_score": 72, "recommendation": "Enable WAF"}\n'
            "End of decision"
        )
        mock_result = MagicMock()
        mock_result.content = [mock_content]
        result = adapter._parse_result(mock_result)
        assert result["threat_detected"] is True
        assert result["threat_score"] == 72

    @pytest.mark.asyncio
    async def test_analyze_web_activity_invalid_json_fallback(self, adapter):
        mock_content = MagicMock()
        mock_content.text = "{invalid}"
        mock_result = MagicMock()
        mock_result.content = [mock_content]
        provider = AsyncMock()
        provider.call_model = AsyncMock(return_value=mock_result)

        result = await adapter.ask_llm(provider, "test prompt")
        assert result == {"threat_detected": False, "threat_score": 0}


# ---------------------------------------------------------------------------
# MCPForensicIntelligenceAdapter — _parse_result fallback paths (lines 47-50)
# ---------------------------------------------------------------------------
class TestMcpForensicAdapterFallbacks:
    @pytest.fixture
    def adapter(self):
        from core_orchestrator.infrastructure.agent.mcp_forensic_intelligence_adapter import MCPForensicIntelligenceAdapter
        return MCPForensicIntelligenceAdapter(AsyncMock())

    def test_parse_invalid_json_returns_empty(self, adapter):
        mock_content = MagicMock()
        mock_content.text = "{{bad json"
        mock_result = MagicMock()
        mock_result.content = [mock_content]
        result = adapter._parse_result(mock_result)
        assert result == {}

    def test_parse_empty_content_returns_empty_dict(self, adapter):
        mock_result = MagicMock()
        mock_result.content = []
        result = adapter._parse_result(mock_result)
        assert result == {}

    def test_parse_plain_dict_returns_it(self, adapter):
        result = adapter._parse_result({"mongo_filter": {"ip": "x"}})
        assert "mongo_filter" in result

    def test_parse_non_dict_no_content_returns_empty(self, adapter):
        result = adapter._parse_result(42)
        assert result == {}

    @pytest.mark.asyncio
    async def test_generate_mongo_query_invalid_json_fallback(self, adapter):
        """generate_mongo_query_from_nl returns {mongo_filter:{}} when parse fails."""
        mock_content = MagicMock()
        mock_content.text = "bad json"
        mock_result = MagicMock()
        mock_result.content = [mock_content]
        adapter.mcp_manager.call_tool = AsyncMock(return_value=mock_result)

        result = await adapter.generate_mongo_query_from_nl("find bots", "src-1")
        assert result == {"mongo_filter": {}}

    @pytest.mark.asyncio
    async def test_generate_forensic_report_invalid_json_fallback(self, adapter):
        mock_content = MagicMock()
        mock_content.text = "bad json"
        mock_result = MagicMock()
        mock_result.content = [mock_content]
        adapter.mcp_manager.call_tool = AsyncMock(return_value=mock_result)

        result = await adapter.generate_forensic_report_from_logs("q", "s", 5, [])
        assert result == {}


# ---------------------------------------------------------------------------
# MCPThreatContextAdapter — _parse_result fallback paths (lines 28-31)
# ---------------------------------------------------------------------------
class TestMcpThreatContextAdapterFallbacks:
    @pytest.fixture
    def adapter(self):
        from core_orchestrator.infrastructure.agent.mcp_threat_context_adapter import MCPThreatContextAdapter
        return MCPThreatContextAdapter(AsyncMock())

    def test_parse_invalid_json_returns_history_fallback(self, adapter):
        mock_content = MagicMock()
        mock_content.text = "{bad}"
        mock_result = MagicMock()
        mock_result.content = [mock_content]
        result = adapter._parse_result(mock_result)
        assert result == {"history": []}

    def test_parse_empty_content_list_returns_empty_dict(self, adapter):
        mock_result = MagicMock()
        mock_result.content = []
        result = adapter._parse_result(mock_result)
        assert result == {}

    def test_parse_plain_dict_returns_it(self, adapter):
        result = adapter._parse_result({"threat_history": ["event1"]})
        assert "threat_history" in result

    def test_parse_non_dict_no_content_returns_empty(self, adapter):
        result = adapter._parse_result(None)
        assert result == {}

    @pytest.mark.asyncio
    async def test_get_threat_context_invalid_json_fallback(self, adapter):
        mock_content = MagicMock()
        mock_content.text = "<<<bad>>>"
        mock_result = MagicMock()
        mock_result.content = [mock_content]
        adapter.mcp_manager.call_tool = AsyncMock(return_value=mock_result)

        result = await adapter.get_threat_context("10.0.0.1")
        assert result == {"history": []}

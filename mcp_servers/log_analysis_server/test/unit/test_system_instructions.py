"""Tests for system_instructions consolidation module."""

import pytest

from mcp_servers.log_analysis_server.services.system_instructions import (
    get_analysis_system_instructions,
    get_analysis_detailed_instructions,
)


def test_get_analysis_system_instructions_returns_string():
    """Verify system instructions is a non-empty string."""
    instructions = get_analysis_system_instructions()
    
    assert isinstance(instructions, str)
    assert len(instructions) > 0
    assert "SOC" in instructions
    assert "OWASP" in instructions
    assert "MITRE" in instructions


def test_get_analysis_detailed_instructions_returns_string():
    """Verify detailed instructions is a non-empty string."""
    instructions = get_analysis_detailed_instructions()
    
    assert isinstance(instructions, str)
    assert len(instructions) > 0
    assert "forensic analyst" in instructions
    assert "NIST" in instructions


def test_system_instructions_mention_key_frameworks():
    """Verify both instruction sets reference key security frameworks."""
    basic = get_analysis_system_instructions()
    detailed = get_analysis_detailed_instructions()
    
    for instructions in [basic, detailed]:
        assert "Cyber Kill Chain" in instructions or "ATT&CK" in instructions
        assert "threat_score" in instructions
        assert "JSON" in instructions


def test_deprecated_prompt_builder_get_system_instructions_shows_warning():
    """Verify deprecated method shows deprecation warning."""
    from mcp_servers.log_analysis_server.services.prompt_builder import AnalysisPromptBuilder
    
    with pytest.warns(DeprecationWarning, match="deprecated"):
        instructions = AnalysisPromptBuilder.get_system_instructions()
    
    # Should still return the same instructions
    assert instructions == get_analysis_system_instructions()

from unittest.mock import AsyncMock

import pytest

from core_orchestrator.application.modules.analysis_reports.services.rules_engine_service import RulesEngineService
from core_orchestrator.domain.entities.rule_engine.rules import RulesBundle


@pytest.mark.asyncio
async def test_rules_engine_service_instances_keep_independent_state() -> None:
    rule_service_a = AsyncMock()
    rule_service_b = AsyncMock()

    rule_service_a.get_cached_rules_for_tenant.return_value = RulesBundle(
        malicious_ua_keywords={"scanner-a": 90},
        version_hash="v-a",
    )
    rule_service_b.get_cached_rules_for_tenant.return_value = RulesBundle(
        malicious_ua_keywords={"scanner-b": 70},
        version_hash="v-b",
    )

    engine_a = RulesEngineService(rule_service_a)
    engine_b = RulesEngineService(rule_service_b)

    bundle_a = await engine_a.get_active_rules()
    bundle_b = await engine_b.get_active_rules()

    assert bundle_a.version_hash == "v-a"
    assert bundle_b.version_hash == "v-b"
    assert engine_a is not engine_b

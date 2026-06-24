from __future__ import annotations

import pytest

from core_orchestrator.models.telemetry_client import TelemetryBootstrapSummary
from core_orchestrator.services.bootstrap_service import BootstrapService


@pytest.mark.asyncio
async def test_run_startup_bootstrap_aggregates_summaries(monkeypatch):
    service = BootstrapService()

    async def fake_ensure_indexes():
        return None

    async def fake_seed_users(*args, **kwargs):
        return TelemetryBootstrapSummary(users_created=1, users_skipped=0, users_updated=0)

    async def fake_seed_clients(*args, **kwargs):
        return TelemetryBootstrapSummary(clients_created=1, clients_skipped=0, clients_updated=0)

    async def fake_warm_cache():
        return TelemetryBootstrapSummary(cache_warmed_clients=1)

    monkeypatch.setattr(service, "ensure_indexes", fake_ensure_indexes)
    monkeypatch.setattr(service, "seed_users", fake_seed_users)
    monkeypatch.setattr(service, "seed_telemetry_clients", fake_seed_clients)
    monkeypatch.setattr(service, "warm_authorized_clients_cache", fake_warm_cache)

    summary = await service.run_startup_bootstrap()

    assert summary.users_created == 1
    assert summary.clients_created == 1
    assert summary.cache_warmed_clients == 1
    assert summary.rules_seeded is False


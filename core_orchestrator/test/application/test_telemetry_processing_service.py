from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from core_orchestrator.application.modules.telemetry.services.telemetry_processing_service import TelemetryProcessingService
from core_orchestrator.domain.models.telemetry.log_event import LogEvent


@pytest.mark.asyncio
async def test_add_log_event_uses_injected_window_duration() -> None:
    window_cache = AsyncMock()
    service = TelemetryProcessingService(
        window_cache=window_cache,
        window_duration_seconds=45,
        window_threshold_requests=10,
    )
    event = LogEvent(
        source_id="victim-app",
        source_ip="1.1.1.1",
        timestamp_utc=datetime.now(timezone.utc),
    )

    await service.add_log_event(event)

    window_cache.add_to_window.assert_called_once()
    key, serialized, duration = window_cache.add_to_window.call_args.args
    assert key == "window:1.1.1.1"
    assert isinstance(serialized, str)
    assert duration == 45


@pytest.mark.asyncio
async def test_process_window_builds_telemetry_window() -> None:
    window_cache = AsyncMock()
    service = TelemetryProcessingService(
        window_cache=window_cache,
        window_duration_seconds=45,
        window_threshold_requests=10,
    )
    event = LogEvent(
        source_id="victim-app",
        source_ip="1.1.1.1",
        timestamp_utc=datetime.now(timezone.utc),
    )
    window_cache.get_and_clear_window.return_value = [event.model_dump_json()]

    window = await service.process_window("window:1.1.1.1")

    assert window is not None
    assert window.total_requests == 1
    assert window.source_ip == "1.1.1.1"


@pytest.mark.asyncio
async def test_is_window_full_honors_configured_threshold() -> None:
    window_cache = AsyncMock()
    service = TelemetryProcessingService(
        window_cache=window_cache,
        window_duration_seconds=45,
        window_threshold_requests=3,
    )
    window_cache.get_window_size.return_value = 3

    assert await service.is_window_full("window:1.1.1.1") is True


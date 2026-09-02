from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from core_orchestrator.application.modules.telemetry.telemetry_window_manager_service import TelemetryManagerWindowService
from core_orchestrator.domain.entities.telemetry.logs_event import LogEvent
from core_orchestrator.infrastructure.dto.telemetry.log_event_dto import LogEventDTO


@pytest.mark.asyncio
async def test_add_log_event_uses_injected_window_duration() -> None:
    window_cache = AsyncMock()
    service = TelemetryManagerWindowService(
        window_cache=window_cache,
        window_duration_seconds=45,
        window_threshold_requests=10,
    )
    event = LogEventDTO(
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
    service = TelemetryManagerWindowService(
        window_cache=window_cache,
        window_duration_seconds=45,
        window_threshold_requests=10,
    )
    event = LogEventDTO(
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
    service = TelemetryManagerWindowService(
        window_cache=window_cache,
        window_duration_seconds=45,
        window_threshold_requests=3,
    )
    window_cache.get_window_size.return_value = 3

    assert await service.is_window_full("window:1.1.1.1") is True


@pytest.mark.asyncio
async def test_add_multiple_logs_events_rotates_full_windows() -> None:
    window_cache = AsyncMock()
    service = TelemetryManagerWindowService(
        window_cache=window_cache,
        window_duration_seconds=45,
        window_threshold_requests=10,
    )
    logs = [
        LogEvent(source_ip="1.1.1.1", timestamp_utc=datetime.now(timezone.utc), source_id="victim-app")
        for _ in range(5)
    ]
    window_cache.get_active_window_keys.side_effect = [
        ["window:default:1.1.1.1"],
        ["window:default:1.1.1.1", "window:default:1.1.1.1:2"],
    ]
    window_cache.get_window_size.side_effect = [8, 0]

    await service.add_multiple_logs_events(logs)

    assert window_cache.add_multiple_to_window.call_count == 2
    first_call = window_cache.add_multiple_to_window.call_args_list[0].args
    second_call = window_cache.add_multiple_to_window.call_args_list[1].args
    assert first_call[0] == "window:default:1.1.1.1"
    assert len(first_call[1]) == 2
    assert second_call[0] == "window:default:1.1.1.1:2"
    assert len(second_call[1]) == 3
    window_cache.force_expire_window.assert_called_once_with("window:default:1.1.1.1", 1)

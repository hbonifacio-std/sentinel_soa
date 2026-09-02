import asyncio
from unittest.mock import AsyncMock

import pytest

from core_orchestrator.infrastructure.adapters.workers.redis_telemetry_window_analysis_worker import (
    RedisTelemetryWindowAnalysisWorker,
)


@pytest.mark.asyncio
async def test_worker_starts_parallel_consumers():
    redis = AsyncMock()
    redis.blpop = AsyncMock(return_value=None)
    analysis_service = AsyncMock()
    worker = RedisTelemetryWindowAnalysisWorker(
        redis_client=redis,
        telemetry_analysis_orchestrator_service=analysis_service,
        parallel_workers=2,
    )

    await worker.start()
    assert len(worker._tasks) == 2

    await worker.stop()


@pytest.mark.asyncio
async def test_worker_delegates_decoded_payload():
    redis = AsyncMock()
    analysis_service = AsyncMock()
    worker = RedisTelemetryWindowAnalysisWorker(
        redis_client=redis,
        telemetry_analysis_orchestrator_service=analysis_service,
        parallel_workers=1,
    )

    async def message_stream():
        yield (b"queue:telemetry:window:analysis", b'{"window_id":"win-7","event_count":4}')

    worker._message_stream = message_stream

    await worker._worker_loop(1)

    analysis_service.process_telemetry_window.assert_awaited_once_with(
        {"window_id": "win-7", "event_count": 4}
    )

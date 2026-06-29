"""
Aggregated Time Window Manager Module.

Groups individual HTTP telemetry events by time windows
based on the source IP address, consolidating traffic distribution metrics.
"""
import logging
from typing import List, Optional, cast

from core_orchestrator.infrastructure.config.config import orchestrator_settings
from core_orchestrator.domain.models import telemetry_window
from core_orchestrator.domain.models.log_event import LogEvent as LogLine
from core_orchestrator.domain.models.telemetry_window import TelemetryWindow
from core_orchestrator.infrastructure.cache.cache_service import CacheService

logger = logging.getLogger(__name__)


class TelemetryProcessingService:
    def __init__(self, cache_service: CacheService, window_duration_seconds: int | None = 50):
        self.window_duration = window_duration_seconds or orchestrator_settings.window_duration_seconds
        self.cache_service = cache_service

    async def add_log_event(self, log_line: LogLine) -> None:
        key = f"window:{log_line.source_ip}"
        await self.cache_service.redis.rpush(key, log_line.model_dump_json())
        await self.cache_service.redis.expire(key, self.window_duration)

    async def add_multiple_logs_events(self, log_lines: List[LogLine]) -> None:
        if not log_lines:
            return
        key = f"window:{log_lines[0].source_ip}"
        pipe = self.cache_service.redis.pipeline()
        for log_line in log_lines:
            pipe.rpush(key, log_line.model_dump_json())
        pipe.expire(key, self.window_duration)
        await pipe.execute()

    async def get_active_windows(self) -> List[str]:
        return await self.cache_service.redis.keys("window:*")

    async def get_window_size(self, key: str) -> int:
        if not key:
            return 0
        return await self.cache_service.redis.llen(key)

    async def process_window(self, key: str) -> Optional[TelemetryWindow]:
        """Extrae los eventos y limpia la ventana de Redis de forma atómica."""
        events_json = await self.cache_service.redis.lrange(key, 0, -1)
        if not events_json:
            return None

        await self.cache_service.redis.delete(key)
        events = [LogLine.model_validate_json(e) for e in events_json]

        return cast(TelemetryWindow, telemetry_window.build_web_activity_window(events))

    async def is_window_full(self, key: str) -> bool:
        """Determina si la ventana superó el umbral configurado."""
        current_size = await self.get_window_size(key)
        return current_size >= orchestrator_settings.window_threshold_requests

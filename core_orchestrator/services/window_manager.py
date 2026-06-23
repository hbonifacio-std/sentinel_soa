"""
Aggregated Time Window Manager Module.

Groups individual HTTP telemetry events by time windows
based on the source IP address, consolidating traffic distribution metrics.
"""

import logging
from typing import List, Optional, cast

from core_orchestrator.models import telemetry_window
from core_orchestrator.models.log_event import LogEvent as LogLine
from core_orchestrator.models.telemetry_window import TelemetryWindow
from core_orchestrator.config import orchestrator_settings
from core_orchestrator.services.database import db

logger = logging.getLogger("core_orchestrator.services.window_manager")


class WindowManager:
    """
    HTTP telemetry temporal aggregation manager in Redis.
    """

    def __init__(self, window_duration_seconds: int | None = None):
        self.window_duration = window_duration_seconds or orchestrator_settings.window_duration_seconds

    async def add_log_event(self, log_line: LogLine) -> None:
        """
        Inserts a processed log event into the corresponding Redis list for its IP.
        """
        key = f"window:{log_line.source_ip}"
        # If the list does not exist, Redis creates it automatically with RPUSH
        # and the EXPIRE command will mark it for deletion if there is no activity
        await db.redis_client.rpush(key, log_line.model_dump_json())
        await db.redis_client.expire(key, self.window_duration)

    def get_window_key(self, log_line: LogLine) -> str:
        """
        Generates the Redis key for the window of a log event.
        """
        return f"window:{log_line.source_ip}"

    async def get_window_size(self, key: str) -> int:
        """
        Gets the number of events in a window (the size of the Redis list).
        """
        if not key:
            return 0
        return await db.redis_client.llen(key)

    async def get_active_windows(self) -> List[str]:
        """
        Gets all active window keys.
        """
        return await db.redis_client.keys("window:*")

    async def process_window(self, key: str) -> Optional[TelemetryWindow]:
        """
        Processes a telemetry window from a Redis key, aggregating HTTP metrics
        from the nested sub-models of each LogEvent.
        """
        events_json = await db.redis_client.lrange(key, 0, -1)
        await db.redis_client.delete(key)  # Clear the Redis window

        events = [LogLine.model_validate_json(e) for e in events_json]
        if not events:
            return None

        window_model = cast(TelemetryWindow, telemetry_window.build_web_activity_window(events))
        return window_model


# Create a global instance to be used across the application
window_manager = WindowManager()

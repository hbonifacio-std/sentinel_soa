"""
Aggregated Time Window Manager Module.

Groups individual HTTP telemetry events by time windows
based on the source IP address, consolidating traffic distribution metrics.
"""
import logging
from dataclasses import asdict
from typing import List, Optional, cast

from core_orchestrator.domain.entities.telemetry import telemetry_window
from core_orchestrator.domain.entities.telemetry.logs_event import LogEvent
from core_orchestrator.infrastructure.adapters.helper.map_to_dataclass import dataclass_to_string_json
from core_orchestrator.infrastructure.dto.telemetry.log_event_dto import LogEventDTO as LogLine
from core_orchestrator.domain.entities.telemetry.telemetry_window import TelemetryWindow
from core_orchestrator.domain.ports.telemetry.telemetry_window_cache_port import TelemetryWindowCachePort

logger = logging.getLogger(__name__)


class TelemetryProcessingService:
    def __init__(self, window_cache: TelemetryWindowCachePort, window_duration_seconds: int, window_threshold_requests: int):
        self.window_duration = window_duration_seconds
        self.window_threshold_requests = window_threshold_requests
        self._window_cache = window_cache

    async def add_log_event(self, log_line: LogLine) -> None:
        """
        Asynchronously adds a log event to the appropriate window in the cache.

        Adds the specified log event to a time-specific window specific to the client
        and source IP address. The window key is constructed based on the client ID and
        source IP. The log event data is serialized and stored in the cache where it
        will be retained for a duration equal to the configured window duration.

        Parameters:
        log_line (LogLine): The log event to be added to the window. This includes
        information such as client ID, source IP, and event data.

        Returns:
        None
        """
        key = self._build_window_key(log_line.client_id, log_line.source_ip)
        await self._window_cache.add_to_window(key, log_line.model_dump_json(), self.window_duration)

    async def add_multiple_logs_events(self, logs_event: List[LogEvent]) -> None:
        """
        Adds multiple log events to the window cache for batching and processing.

        This method processes a list of log events by converting each event to its
        JSON representation and adding them to a cache window. Each cache window is
        uniquely identified by a key derived from the client ID and source IP of the
        first log event in the list. This operation is asynchronous and returns
        immediately after the events are added to the cache.

        Arguments:
            logs_event: A list of LogEvent objects representing the log events to be
                batched and cached. The list must not be empty.

        Returns:
            None
        """
        if not logs_event:
            return
        key = self._build_window_key(logs_event[0].client_id, logs_event[0].source_ip)
        payloads = [dataclass_to_string_json(line) for line in logs_event]
        await self._window_cache.add_multiple_to_window(key, payloads, self.window_duration)

    async def get_active_windows(self) -> List[str]:
        """
        Asynchronously retrieves a list of active window keys.

        This method interacts with an internal cache to obtain the active window
        keys matching the specified pattern. It performs the retrieval
        operation asynchronously.

        Returns:
            List[str]: A list of active window keys as strings.
        """
        return await self._window_cache.get_active_window_keys("window:*")

    async def get_window_size(self, key: str) -> int:
        """
        Gets the size of a specific window from the window cache.

        This method retrieves the size of the window referenced by the provided
        key from an asynchronous window cache.

        Parameters:
        key: str
            The key identifying the specific window in the window cache.

        Returns:
        int
            The size of the window associated with the given key.

        """
        return await self._window_cache.get_window_size(key)

    async def process_window(self, key: str) -> Optional[TelemetryWindow]:
        """
        Processes a window of telemetry events and returns a constructed telemetry window.

        This asynchronous method retrieves and clears a collection of telemetry events from the
        window cache associated with the provided key. If no events are found, it returns None.
        Otherwise, it parses and validates each event and builds a telemetry window object using
        the provided events.

        Parameters:
        key: str
            The key used to identify the telemetry events in the window cache.

        Returns:
        Optional[TelemetryWindow]
            A telemetry window object constructed from the validated events, or None if no events
            are found.
        """
        events_json = await self._window_cache.get_and_clear_window(key)
        if not events_json:
            return None

        events = [LogLine.model_validate_json(e) for e in events_json]

        return telemetry_window.build_web_activity_window(events)

    async def is_window_full(self, key: str) -> bool:
        """
        Checks if the sliding window for a given key is full.

        This method evaluates whether the current size of the sliding window for the
        specified key has reached or exceeded the configured threshold.

        Parameters:
        key: str
            The unique identifier for which the sliding window size needs to
            be checked.

        Returns:
        bool
            True if the sliding window size for the given key is greater than or equal
            to the threshold, otherwise False.
        """
        current_size = await self.get_window_size(key)
        return current_size >= self.window_threshold_requests

    @staticmethod
    def _build_window_key(tenant_id: Optional[str], source_ip: str) -> str:
        """
        Builds a unique key for identifying rate-limiting windows.

        This static method is used to construct a key for rate-limiting purposes
        based on tenant information and source IP. If no tenant_id is provided,
        a default value is used.

        Args:
            tenant_id (Optional[str]): The identifier of the tenant. If None, the
                default value "default" is used.
            source_ip (str): The source IP address for which the key is being built.

        Returns:
            str: A unique string key for rate-limiting purposes.
        """
        safe_tenant = tenant_id or "default"
        return f"window:{safe_tenant}:{source_ip}"
"""
Aggregated Time Window Manager Module.

Groups individual HTTP telemetry events by time windows
based on the source IP address, consolidating traffic distribution metrics.
"""
import logging
import re
from dataclasses import asdict
from typing import List, Optional, cast

from core_orchestrator.domain.entities.telemetry import telemetry_window
from core_orchestrator.domain.entities.telemetry.logs_event import LogEvent
from core_orchestrator.infrastructure.adapters.helper.map_to_dataclass import dataclass_to_string_json
from core_orchestrator.infrastructure.dto.telemetry.log_event_dto import LogEventDTO as LogLine
from core_orchestrator.domain.entities.telemetry.telemetry_window import TelemetryWindow
from core_orchestrator.domain.ports.telemetry.telemetry_window_cache_port import TelemetryWindowCachePort

logger = logging.getLogger(__name__)


class TelemetryManagerWindowService:
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
        await self._store_log_payloads(
            client_id=log_line.client_id,
            source_ip=log_line.source_ip,
            payloads=[log_line.model_dump_json()],
        )

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
        payloads = [dataclass_to_string_json(line) for line in logs_event]
        await self._store_log_payloads(
            client_id=logs_event[0].client_id,
            source_ip=logs_event[0].source_ip,
            payloads=payloads,
        )

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

    async def start_listening(self) -> None:
        """
        Starts listening for messages from the window cache.

        This method initiates the listening process for incoming messages from the
        window cache. It is an asynchronous operation that will continue to listen
        for messages until the process is stopped.

        Returns:
            None
        """
        await self._window_cache.start_listening()

    async def _store_log_payloads(self, client_id: Optional[str], source_ip: str, payloads: List[str]) -> None:
        remaining_payloads = list(payloads)
        while remaining_payloads:
            key = await self._resolve_window_key(client_id, source_ip)
            current_size = await self.get_window_size(key)
            remaining_capacity = self.window_threshold_requests - current_size
            if remaining_capacity <= 0:
                await self._window_cache.force_expire_window(key, 1)
                continue

            chunk = remaining_payloads[:remaining_capacity]
            await self._window_cache.add_multiple_to_window(key, chunk, self.window_duration)
            remaining_payloads = remaining_payloads[len(chunk):]

            if current_size + len(chunk) >= self.window_threshold_requests:
                await self._window_cache.force_expire_window(key, 1)

    async def _resolve_window_key(self, client_id: Optional[str], source_ip: str) -> str:
        base_key = self._build_window_key(client_id, source_ip)
        pattern = self._build_window_pattern(client_id, source_ip)
        active_keys = await self._window_cache.get_active_window_keys(pattern)
        key_regex = self._build_window_regex(client_id, source_ip)
        active_keys = [key for key in active_keys if key_regex.match(key)]
        if not active_keys:
            return base_key

        key_suffix = self._extract_window_suffix(base_key)
        latest_key = base_key
        latest_suffix = key_suffix
        for active_key in active_keys:
            suffix = self._extract_window_suffix(active_key)
            if suffix >= latest_suffix:
                latest_suffix = suffix
                latest_key = active_key

        if await self.get_window_size(latest_key) >= self.window_threshold_requests:
            return self._build_window_key(client_id, source_ip, latest_suffix + 1)
        return latest_key

    @staticmethod
    def _build_window_key(tenant_id: Optional[str], source_ip: str, suffix: Optional[int] = None) -> str:
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
        base_key = f"window:{safe_tenant}:{source_ip}"
        if suffix and suffix > 1:
            return f"{base_key}:{suffix}"
        return base_key

    @staticmethod
    def _build_window_pattern(tenant_id: Optional[str], source_ip: str) -> str:
        safe_tenant = tenant_id or "default"
        return f"window:{safe_tenant}:{source_ip}*"

    @staticmethod
    def _build_window_regex(tenant_id: Optional[str], source_ip: str) -> re.Pattern[str]:
        safe_tenant = re.escape(tenant_id or "default")
        safe_source = re.escape(source_ip)
        return re.compile(rf"^window:{safe_tenant}:{safe_source}(?::(\d+))?$")

    @staticmethod
    def _extract_window_suffix(key: str) -> int:
        match = re.match(r"^window:[^:]+:[^:]+(?::(\d+))?$", key)
        if not match:
            return 1
        suffix = match.group(1)
        return int(suffix) if suffix else 1
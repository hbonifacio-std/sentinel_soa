import asyncio
import json
import logging
from typing import Any, AsyncGenerator, Awaitable, cast
from redis.asyncio import Redis

from core_orchestrator.application.modules.telemetry.telemetry_analysis_orchestrator_service import (
    TelemetryAnalysisOrchestratorService,
)

logger = logging.getLogger(__name__)
_DEFAULT_QUEUE_KEY = "queue:telemetry:window:analysis"


class RedisTelemetryWindowAnalysisWorker:

    def __init__(
        self,
        redis_client: Redis,
        telemetry_analysis_orchestrator_service: TelemetryAnalysisOrchestratorService,
        queue_key: str = _DEFAULT_QUEUE_KEY,
        parallel_workers: int = 4,
    ) -> None:
        if parallel_workers < 1:
            raise ValueError("parallel_workers must be greater than zero")
        self._redis = redis_client
        self._telemetry_analysis_orchestrator_service = telemetry_analysis_orchestrator_service
        self._queue_key = queue_key
        self._parallel_workers = parallel_workers
        self._stop_event = asyncio.Event()
        self._tasks: list[asyncio.Task] = []
        self._background_tasks: set[asyncio.Task] = set()

    def start(self) -> None:
        if not self._redis:
            raise RuntimeError("Redis client is not initialized")
        if self._tasks:
            return

        self._stop_event.clear()
        for index in range(self._parallel_workers):
            task = asyncio.create_task(self._worker_loop(index + 1))
            self._tasks.append(task)

    async def stop(self) -> None:
        self._stop_event.set()
        if not self._tasks:
            return

        for task in self._tasks:
            task.cancel()

        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    async def _message_stream(self) -> AsyncGenerator[list, None]:
        """
        Asynchronous generator for streaming messages from a Redis queue.

        Yields
        -------
        tuple[bytes, bytes]
            A tuple containing the queue name and the payload data as bytes.

        Notes
        -----
        This method retrieves messages from a Redis queue using the `blpop` command,
        which waits for an element to be available in the list of specified keys. If
        a message is received, it yields the message to the caller in the form of a
        tuple (queue_name, payload). In case of failure in reading from the Redis
        queue, the process will retry after a short delay.

        Raises
        ------
        asyncio.CancelledError
            If the coroutine is explicitly canceled while waiting for an item in the
            queue, the operation is stopped cleanly.
        """
        while not self._stop_event.is_set():
            try:
                result = await cast(
                    Awaitable[Any],
                    self._redis.blpop([self._queue_key], timeout=1)
                )
                if result:
                    yield result
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.exception(f"Error reading from Redis queue: {e}")
                await asyncio.sleep(1)

    async def _worker_loop(self, worker_index: int) -> None:
        """
        Handles the worker execution loop for processing messages from a message stream.

        The method is responsible for consuming messages from a message stream, decoding
        payloads, and logging decoded information about the telemetry data being processed.
        Each worker operates independently, and this function is designed to execute within
        an asynchronous context to handle concurrent message processing.

        Parameters:
        worker_index: int
            The index identifying the worker instance currently executing the loop. This is
            used for logging purposes.

        Returns:
        None
            This function does not return any value as it runs asynchronously and performs
            its operations through side effects such as logging.

        Raises:
        None
        """
        async for queue_name, payload in self._message_stream():
            decoded_payload = self._decode_payload(payload)
            logger.info(
                f"[telemetry-window-worker:{worker_index}] queue={self._decode_text(queue_name)} "
                f"window={decoded_payload.get('window_id', 'unknown')} "
                f"events={decoded_payload.get('event_count', 0)}"
            )
            await self._telemetry_analysis_orchestrator_service.process_telemetry_window(decoded_payload)


    @staticmethod
    def _decode_payload(payload: bytes | str | dict[str, Any]) -> dict[str, Any]:
        if isinstance(payload, dict):
            return payload
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode("utf-8", errors="ignore")
        if isinstance(payload, str):
            try:
                data = json.loads(payload)
                return data if isinstance(data, dict) else {"data": data}
            except (json.JSONDecodeError, TypeError):
                return {"raw": payload}
        return {}

    @staticmethod
    def _decode_text(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        return str(value)
"""
This module handles the orchestration of telemetry window processing, queue
management, and analysis execution. It integrates with several services for
data processing and communication with an AI agent, ensuring reliability and
robustness with retry mechanisms and resource management.

Classes:
- AgentRunner: Orchestrates the telemetry processing pipeline, including queue
  management and agent communication.

Dataclasses:
- _PendingAnalysis: Represents an envelope for telemetry data with metadata
  for analysis retries and logging.
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import Callable, Dict, Any, Optional

from core_orchestrator.application.modules.analysis_reports.services.analytics_service import ReportTelemetryService
from core_orchestrator.infrastructure.adapters.mpc_server.mcp_client_adapter import MCPClientManagerAdapter
from core_orchestrator.application.modules.telemetry.telemetry_analysis_service import TelemetryAnalysisService
from core_orchestrator.application.modules.telemetry.telemetry_window_manager_service import TelemetryProcessingService
from core_orchestrator.application.modules.telemetry.telemetry_service import TelemetryService
from core_orchestrator.infrastructure.cache.cache_service import CacheService

logger = logging.getLogger("core_orchestrator.agent.runner")

# ── MCP Reconnect tunable ─────────────────────────────────────────────────
_MCP_RETRY_INITIAL_DELAY_S = 5
_MCP_RETRY_MAX_DELAY_S = 60
_MCP_RETRY_BACKOFF_FACTOR = 2
_MCP_CONNECT_TIMEOUT_S = 15

# ── Analysis queue tunable ────────────────────────────────────────────────
_ANALYSIS_QUEUE_MAXSIZE = 1000   # Maximum number of pending windows in the queue
_ANALYSIS_RETRY_DELAY_S = 3      # Wait between retries if MCP is not ready.
_ANALYSIS_MAX_RETRIES = 5        # Maximum retries per window before discarding


@dataclass
class _PendingAnalysis:
    """
    Represents an analysis process pending completion.

    This class holds data related to a pending analysis status. It tracks window
    data tied to an identifier along with the number of attempts made to process
    the associated analysis. The class provides functionality to increment the
    attempt counter and return an updated instance.
    """
    window_data: Dict[str, Any]
    attempts: int = 0
    window_key: str = ""         # Log identifier

    def increment(self) -> "_PendingAnalysis":
        self.attempts += 1
        return self


class TelemetryProcessingWorker:
    def __init__(
        self,
        telemetry_processing_service: TelemetryProcessingService,
        cache_service: CacheService,
        telemetry_service: TelemetryService,
        analytics_service: ReportTelemetryService,
        agent_factory: Callable[[MCPClientManagerAdapter], TelemetryAnalysisService],
    ):
        self.telemetry_processing_service = telemetry_processing_service
        self.cache_service = cache_service
        self.telemetry_service = telemetry_service
        self.analytics_service = analytics_service
        self._agent_factory = agent_factory
        self.mcp_manager: Optional[MCPClientManagerAdapter] = None
        self.agent: Optional[TelemetryAnalysisService] = None

        self._analysis_queue: asyncio.Queue[_PendingAnalysis] = asyncio.Queue(
            maxsize=_ANALYSIS_QUEUE_MAXSIZE
        )


        self._window_processor_handle: Optional[asyncio.Task] = None
        self._analysis_consumer_handle: Optional[asyncio.Task] = None
        self._mcp_reconnect_handle: Optional[asyncio.Task] = None


        self._inflight_tasks: set = set()

        self._stop_event = asyncio.Event()

    @property
    def is_mcp_connected(self) -> bool:
        """
        Determine if an MCP session is currently connected.

        This property returns a boolean value indicating the connection
        status of the MCP (Message Conversion Protocol) session. It checks
        whether the MCP session is active and maintains the connection.

        Returns:
            bool: True if the MCP session is alive and connected; False otherwise.
        """
        return self._is_mcp_session_alive()

    async def is_mcp_healthy(self) -> bool:
        """
        Checks the health status of the MCP (Multi-Channel Processor) session.

        This asynchronous method verifies if the MCP session managed by the
        mcp_manager object is in a healthy state or not. If no mcp_manager
        instance is present, it assumes the session is not healthy.

        Returns:
            bool: True if the MCP session is healthy, otherwise False.
        """
        if self.mcp_manager is None:
            return False
        return await self.mcp_manager.is_session_healthy()

    async def run_analysis(self, telemetry_window: Dict[str, Any]) -> str:
        """
        Runs an analysis for a completed telemetry window.

        When the MCP agent is available, the window is analyzed immediately.
        Otherwise, the window is re-queued so the background consumer can
        process it once the MCP session is restored.
        """
        if self.agent is None:
            window_key = str(telemetry_window.get("window_id", "manual-window"))
            logger.warning(
                "MCP agent unavailable during manual analysis request. Re-queuing window '%s'.",
                window_key,
            )
            await self._enqueue_analysis(telemetry_window, window_key=window_key)
            return ""

        return await self.agent.process_telemetry_window(telemetry_window)


    async def _window_processor_task(self) -> None:
        """
        Handles window processing tasks within an asynchronous loop.

        This method continuously retrieves active windows from the telemetry processing service,
        processes each retrieved window, and handles any errors that occur during processing.
        The loop runs until the stop event is triggered. A delay is introduced between iterations
        for efficient resource utilization.

        Raises:
            asyncio.CancelledError: Raised when the task is canceled to handle cleanup.

        """
        logger.info("Window processor started.")
        while not self._stop_event.is_set():
            try:
                keys = await self.telemetry_processing_service.get_active_windows()
                for key in keys:
                    decoded_key = key.decode("utf-8") if isinstance(key, bytes) else key
                    await self._process_single_window(decoded_key)
            except asyncio.CancelledError:
                logger.info("Window processor cancelled.")
                raise
            except Exception as e:
                logger.exception("Error in window processor: %s", e)

            await asyncio.sleep(5)

        logger.info("Window processor stopped.")

    async def _process_single_window(self, decoded_key: str) -> None:
        """
        Processes a single telemetry data window asynchronously.

        The method checks whether the telemetry data window associated with
        the given decoded key is full, or if its Time-To-Live (TTL) is within
        a critical threshold. If either condition is true, it attempts to acquire
        a lock to prevent concurrent processing. Once the lock is secured,
        it processes the telemetry window and enqueues the extracted data
        for further analysis. The lock is safely released after processing.

        Parameters:
        decoded_key: str
            The decoded key identifying the telemetry data window to be processed.
        """
        is_full = await self.telemetry_processing_service.is_window_full(decoded_key)
        ttl = await self.cache_service.get_ttl(decoded_key)

        if is_full or (0 < ttl < 10):
            lock = self.cache_service.lock(f"lock:{decoded_key}", timeout=10)
            if await lock.acquire(blocking=False):
                try:
                    telemetry_window = await self.telemetry_processing_service.process_window(decoded_key)
                    if telemetry_window:
                        await self._enqueue_analysis(
                            telemetry_window.model_dump(),
                            window_key=decoded_key
                        )
                finally:
                    await lock.release()

    async def _enqueue_analysis(self, window_data: Dict[str, Any], window_key: str = "") -> None:
        """
        Enqueues a window of data for analysis, dropping the oldest data if the queue is full.

        This method adds a data window to the analysis queue for further processing. If the
        queue is full, it attempts to remove the oldest item to make space for the newly
        queued data. Debug logs are provided for enqueueing and when items are dropped
        from the queue.

        Args:
            window_data (Dict[str, Any]): The data associated with the analysis window
            window_key (str, optional): An identifier for the analysis window. Defaults to an
            empty string.

        Returns:
            None
        """
        item = _PendingAnalysis(window_data=window_data, window_key=window_key)
        if self._analysis_queue.full():
            try:
                dropped = self._analysis_queue.get_nowait()
                logger.warning(
                    f"Analysis queue full ({_ANALYSIS_QUEUE_MAXSIZE}). "
                    f"Dropped oldest window '{dropped.window_key}' to make room."
                )
            except asyncio.QueueEmpty:
                pass
        await self._analysis_queue.put(item)
        logger.debug(
            f"Enqueued window '{window_key}' for analysis. "
            f"Queue size: {self._analysis_queue.qsize()}"
        )


    async def _analysis_consumer_task(self) -> None:
        """
        Asynchronous task for consuming analysis jobs from a queue and processing them.

        This task continuously retrieves jobs from the analysis queue, processes them,
        and handles failure scenarios. It ensures that incomplete or failed tasks are
        reprocessed and maintains inflight tasks until they are completed or canceled.

        Raises:
            asyncio.CancelledError: Raised when the task is explicitly canceled.

        Notes:
            - The task retries processing jobs if the components required for the
              analysis are not ready, with a delay.
            - All inflight tasks are awaited before complete shutdown to ensure
              clean resource handling.
            - Any remaining jobs in the queue at shutdown are logged for
              reprocessing upon restart.
        """
        logger.info("Analysis consumer started.")
        while not self._stop_event.is_set():
            try:

                try:
                    pending = await asyncio.wait_for(
                        self._analysis_queue.get(),
                        timeout=2.0
                    )
                except asyncio.TimeoutError:
                    continue

                if self.agent is None:
                    wait_time = _ANALYSIS_RETRY_DELAY_S
                    logger.info(
                        f"MCP not ready. Holding window '{pending.window_key}' "
                        f"(attempt {pending.attempts + 1}). "
                        f"Re-checking in {wait_time}s..."
                    )
                    await asyncio.sleep(wait_time)

                    await self._analysis_queue.put(pending)
                    self._analysis_queue.task_done()
                    continue


                task = asyncio.create_task(
                    self._run_and_handle_failure(pending)
                )
                self._inflight_tasks.add(task)
                task.add_done_callback(self._inflight_tasks.discard)
                self._analysis_queue.task_done()

            except asyncio.CancelledError:
                logger.info("Analysis consumer cancelled.")
                raise
            except Exception as e:
                logger.exception("Unexpected error in analysis consumer: %s", e)


        if self._inflight_tasks:
            logger.info(f"Waiting for {len(self._inflight_tasks)} in-flight analysis(es) to complete...")
            await asyncio.gather(*self._inflight_tasks, return_exceptions=True)

        pending_count = self._analysis_queue.qsize()
        if pending_count:
            logger.warning(
                f"{pending_count} window(s) still pending in queue at shutdown. "
                "They will be re-processed on next startup if their keys are still in Redis."
            )
        logger.info("Analysis consumer stopped.")

    async def _run_and_handle_failure(self, pending: _PendingAnalysis) -> None:
        """
        Handles the asynchronous execution of telemetry window analysis and manages failure
        scenarios by implementing retry logic with exponential backoff.

        This method runs the analysis for a given pending telemetry window object and attempts
        to recover from failures up to a defined maximum retry limit. If all retry attempts
        are exhausted, the pending analysis is discarded to avoid blocking further processing.

        Arguments:
            pending: _PendingAnalysis
                An object containing telemetry window data, retry attempt tracking, and
                the key associated with the window being analyzed.

        Raises:
            Does not explicitly raise any exceptions outside the local scope of the method.
        """
        pending.increment()
        window_key = pending.window_key or "unknown"
        try:
            await self.agent.process_telemetry_window(pending.window_data)
            logger.info(f"Analysis completed for window '{window_key}' ...")
        except Exception as e:

            logger.warning(
                f"Analysis failed for window '{window_key}' "
                f"(attempt {pending.attempts}/{_ANALYSIS_MAX_RETRIES}): {e}"
            )
            if pending.attempts < _ANALYSIS_MAX_RETRIES:
                delay = min(
                    _ANALYSIS_RETRY_DELAY_S * (2 ** (pending.attempts - 1)),
                    _MCP_RETRY_MAX_DELAY_S
                )
                logger.info(f"Re-enqueueing window '{window_key}' in {delay}s.")
                await asyncio.sleep(delay)
                await self._enqueue_analysis(pending.window_data, window_key=window_key)
            else:
                logger.error(
                    f"Window '{window_key}' exhausted {_ANALYSIS_MAX_RETRIES} retries. "
                    "Discarding to prevent queue starvation."
                )

    async def _mcp_reconnect_loop(self) -> None:
        """
        Handles the MCP reconnection loop to ensure a persistent connection with
        the MCP (Message Client Protocol) server. The method continuously checks
        the status of the active agent, attempts to reconnect upon session loss,
        and reinitialize the necessary parts.

        The reconnection attempts to involve creating a new MCP client manager,
        establishing a new server session, and resetting the backoff delay.
        Upon successful reconnection, pending tasks in the analysis queue
        are processed. On failure, the method increases the delay between
        reconnection attempts exponentially within a defined limit.

        This method operates asynchronously and is designed to run until stopped.

        Raises:
            asyncio.TimeoutError: Raised when the attempt to start a new MCP server
                session exceeds the specified timeout duration.
            Exception: Any general exception that occurs during the connection
                process.

        Returns:
            None
        """
        delay = _MCP_RETRY_INITIAL_DELAY_S

        while not self._stop_event.is_set():

            if self.agent is not None and self._is_mcp_session_alive():
                await asyncio.sleep(delay)
                delay = _MCP_RETRY_INITIAL_DELAY_S  # reset backoff
                continue

            if self.agent is not None:
                logger.warning("MCP session lost. Tearing down and reconnecting...")
                await self._teardown_mcp()

            logger.info("MCP Reconnect Loop: attempting connection...")
            try:
                new_manager = MCPClientManagerAdapter()
                await asyncio.wait_for(
                    new_manager.start_server_session(),
                    timeout=_MCP_CONNECT_TIMEOUT_S
                )
                self.mcp_manager = new_manager

                self.agent = self._agent_factory(new_manager)
                queue_size = self._analysis_queue.qsize()
                logger.info(
                    f"✅ MCP connected. AI Agent ACTIVE. "
                    f"{queue_size} window(s) waiting in queue will now be processed."
                )
                delay = _MCP_RETRY_INITIAL_DELAY_S  # reset backoff

            except asyncio.TimeoutError:
                logger.warning(
                    f"MCP connect timed out ({_MCP_CONNECT_TIMEOUT_S}s). "
                    f"Retry in {delay}s..."
                )
                await self._teardown_mcp()
                await asyncio.sleep(delay)
                delay = min(delay * _MCP_RETRY_BACKOFF_FACTOR, _MCP_RETRY_MAX_DELAY_S)

            except Exception as e:
                logger.warning(
                    "MCP connect failed: %s: %s. Retry in %ss...",
                    type(e).__name__, e, delay,
                )
                await self._teardown_mcp()
                await asyncio.sleep(delay)
                delay = min(delay * _MCP_RETRY_BACKOFF_FACTOR, _MCP_RETRY_MAX_DELAY_S)

    def _is_mcp_session_alive(self) -> bool:
        if self.mcp_manager is None:
            return False
        return getattr(self.mcp_manager, "_session", None) is not None

    async def _teardown_mcp(self) -> None:
        if self.mcp_manager is not None:
            try:
                await self.mcp_manager.close()
            except Exception as e:
                logger.exception("Error tearing down MCP: %s", e)

        self.mcp_manager = None
        self.agent = None


    def initialize_subsystem(self) -> None:
        """
        Initializes the Agent subsystem and starts its associated background tasks.

        This method clears the stop event and creates multiple asynchronous tasks, each assigned
        to a specific function within the subsystem. The purpose of these tasks is to handle
        reconnection logic, consume analysis data, and process window segments. Each task is
        registered with a callback to handle completion.

        Raises:
            Any exceptions raised within the tasks will need to be handled by the associated
            callbacks or during task execution.
        """
        logger.info("Initializing Agent subsystem...")
        self._stop_event.clear()

        self._mcp_reconnect_handle = asyncio.create_task(
            self._mcp_reconnect_loop(), name="mcp-reconnect"
        )
        if self._mcp_reconnect_handle:
            self._mcp_reconnect_handle.add_done_callback(self._on_background_task_done)

        self._analysis_consumer_handle = asyncio.create_task(
            self._analysis_consumer_task(), name="analysis-consumer"
        )
        if self._analysis_consumer_handle:
            self._analysis_consumer_handle.add_done_callback(self._on_background_task_done)

        self._window_processor_handle = asyncio.create_task(
            self._window_processor_task(), name="window-processor"
        )
        if self._window_processor_handle:
            self._window_processor_handle.add_done_callback(self._on_background_task_done)

        logger.info(
            "Agent subsystem started: "
            "[window-processor] → [analysis-queue] → [analysis-consumer] → [mcp-agent]"
        )

    async def shutdown_subsystem(self) -> None:
        """
        Asynchronously shuts down the Agent subsystem, ensuring all ongoing processes and tasks are canceled
        and cleaned up properly.

        The method completes a graceful shutdown by triggering the stop event, canceling existing async
        tasks, and handling in-flight processes. It also executes the teardown logic for the MCP component
        before concluding the shutdown.

        Raises:
            asyncio.CancelledError: Propagated if a cancellation occurs during task cancellation.
            Exception: Catches and suppresses non-critical exceptions during task cancellations.
        """
        logger.info("Shutting down Agent subsystem...")
        self._stop_event.set()

        handles = [
            self._window_processor_handle,
            self._mcp_reconnect_handle,
            self._analysis_consumer_handle,  # Este espera los in-flight
        ]
        for handle in handles:
            if handle and not handle.done():
                handle.cancel()
                try:
                    await handle
                except (asyncio.CancelledError, Exception):
                    pass

        await self._teardown_mcp()
        logger.info("Agent subsystem shut down cleanly.")

    @staticmethod
    def _on_background_task_done(task: asyncio.Task) -> None:
        if task.cancelled():
            return
        try:
            exc = task.exception()
            if exc is not None:
                logger.error(
                    f"Background task '{task.get_name()}' ended unexpectedly: "
                    f"{type(exc).__name__}: {exc}",
                    exc_info=exc,
                )
        except asyncio.CancelledError:
            pass

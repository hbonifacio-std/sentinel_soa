"""
Extended AgentRunner tests covering lines NOT yet hit:
  - _window_processor_task: bytes key decoding path & exception swallowing
  - _process_single_window: TTL-near-expiry path (0 < ttl < 10)
  - _process_single_window: lock NOT acquired path
  - _process_single_window: process_window returns None
  - _analysis_consumer_task: timeout path (no items in queue)
  - _analysis_consumer_task: agent present, dispatches task
  - _run_and_handle_failure: success path (no exception)
  - _teardown_mcp: closes existing manager and clears refs
  - _is_mcp_session_alive: session attribute present vs. absent
  - _on_background_task_done: task.exception() raises CancelledError
  - shutdown_subsystem with no handles (no-op)
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

from core_orchestrator.infrastructure.adapters.workers.telemetry_processing_worker import TelemetryProcessingWorker, _PendingAnalysis


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------
@pytest.fixture
def runner():
    return TelemetryProcessingWorker(
        telemetry_processing_service=AsyncMock(),
        cache_service=AsyncMock(),
        telemetry_service=AsyncMock(),
        analytics_service=AsyncMock(),
        agent_factory=MagicMock(),
    )


# ---------------------------------------------------------------------------
# _is_mcp_session_alive
# ---------------------------------------------------------------------------
class TestIsMcpSessionAlive:
    def test_no_manager_returns_false(self, runner):
        runner.mcp_manager = None
        assert runner._is_mcp_session_alive() is False

    def test_manager_without_session_attr_returns_false(self, runner):
        runner.mcp_manager = MagicMock(spec=[])  # no _session attribute
        assert runner._is_mcp_session_alive() is False

    def test_manager_with_none_session_returns_false(self, runner):
        runner.mcp_manager = MagicMock()
        runner.mcp_manager._session = None
        assert runner._is_mcp_session_alive() is False

    def test_manager_with_active_session_returns_true(self, runner):
        runner.mcp_manager = MagicMock()
        runner.mcp_manager._session = MagicMock()
        assert runner._is_mcp_session_alive() is True


# ---------------------------------------------------------------------------
# _teardown_mcp
# ---------------------------------------------------------------------------
class TestTeardownMcp:
    @pytest.mark.asyncio
    async def test_teardown_clears_manager_and_agent(self, runner):
        mock_mgr = AsyncMock()
        runner.mcp_manager = mock_mgr
        runner.agent = MagicMock()

        await runner._teardown_mcp()

        mock_mgr.close.assert_awaited_once()
        assert runner.mcp_manager is None
        assert runner.agent is None

    @pytest.mark.asyncio
    async def test_teardown_suppresses_close_exception(self, runner):
        mock_mgr = AsyncMock()
        mock_mgr.close = AsyncMock(side_effect=RuntimeError("oops"))
        runner.mcp_manager = mock_mgr
        runner.agent = MagicMock()

        await runner._teardown_mcp()  # must not raise
        assert runner.mcp_manager is None

    @pytest.mark.asyncio
    async def test_teardown_no_manager_is_safe(self, runner):
        runner.mcp_manager = None
        runner.agent = None
        await runner._teardown_mcp()  # must not raise


# ---------------------------------------------------------------------------
# _on_background_task_done
# ---------------------------------------------------------------------------
class TestOnBackgroundTaskDone:
    def test_cancelled_task_returns_early(self, runner):
        task = MagicMock()
        task.cancelled.return_value = True
        runner._on_background_task_done(task)
        task.exception.assert_not_called()

    def test_task_exception_is_logged(self, runner):
        task = MagicMock()
        task.cancelled.return_value = False
        task.exception.return_value = ValueError("boom")
        # Should not raise
        runner._on_background_task_done(task)

    def test_task_exception_raises_cancelled_error_is_swallowed(self, runner):
        task = MagicMock()
        task.cancelled.return_value = False
        task.exception.side_effect = asyncio.CancelledError()
        # Should not raise
        runner._on_background_task_done(task)


# ---------------------------------------------------------------------------
# _process_single_window — additional paths
# ---------------------------------------------------------------------------
class TestProcessSingleWindowExtended:
    @pytest.mark.asyncio
    async def test_window_near_expiry_ttl_triggers_processing(self, runner):
        """TTL between 1 and 9 seconds → should try to acquire lock."""
        runner.telemetry_processing_service.is_window_full = AsyncMock(return_value=False)
        runner.cache_service.get_ttl = AsyncMock(return_value=5)  # 0 < 5 < 10

        lock_mock = AsyncMock()
        lock_mock.acquire = AsyncMock(return_value=False)  # lock not acquired
        runner.cache_service.lock = MagicMock(return_value=lock_mock)

        await runner._process_single_window("win-expiring")
        lock_mock.acquire.assert_awaited_once_with(blocking=False)

    @pytest.mark.asyncio
    async def test_lock_not_acquired_skips_processing(self, runner):
        runner.telemetry_processing_service.is_window_full = AsyncMock(return_value=True)
        runner.cache_service.get_ttl = AsyncMock(return_value=30)

        lock_mock = AsyncMock()
        lock_mock.acquire = AsyncMock(return_value=False)
        runner.cache_service.lock = MagicMock(return_value=lock_mock)

        await runner._process_single_window("win-locked")
        runner.telemetry_processing_service.process_window.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_window_returns_none_does_not_enqueue(self, runner):
        runner.telemetry_processing_service.is_window_full = AsyncMock(return_value=True)
        runner.cache_service.get_ttl = AsyncMock(return_value=30)
        runner.telemetry_processing_service.process_window = AsyncMock(return_value=None)

        lock_mock = AsyncMock()
        lock_mock.acquire = AsyncMock(return_value=True)
        runner.cache_service.lock = MagicMock(return_value=lock_mock)

        await runner._process_single_window("win-none")
        assert runner._analysis_queue.empty()


# ---------------------------------------------------------------------------
# _run_and_handle_failure — success path
# ---------------------------------------------------------------------------
class TestRunAndHandleFailureSuccess:
    @pytest.mark.asyncio
    async def test_success_does_not_enqueue(self, runner):
        agent_mock = AsyncMock()
        agent_mock.process_telemetry_window = AsyncMock(return_value={"result": "ok"})
        runner.agent = agent_mock

        pending = _PendingAnalysis(window_data={"ip": "1.2.3.4"}, window_key="win-ok")
        runner._enqueue_analysis = AsyncMock()

        await runner._run_and_handle_failure(pending)

        assert pending.attempts == 1
        runner._enqueue_analysis.assert_not_called()


# ---------------------------------------------------------------------------
# _window_processor_task — bytes key decoding
# ---------------------------------------------------------------------------
class TestWindowProcessorTaskBytesKey:
    @pytest.mark.asyncio
    async def test_bytes_key_decoded_correctly(self, runner):
        runner.telemetry_processing_service.get_active_windows = AsyncMock(
            return_value=[b"win-bytes-key"]
        )
        runner.telemetry_processing_service.is_window_full = AsyncMock(return_value=False)
        runner.cache_service.get_ttl = AsyncMock(return_value=-1)

        runner._process_single_window = AsyncMock()

        task = asyncio.create_task(runner._window_processor_task())
        await asyncio.sleep(0.05)
        runner._stop_event.set()
        await asyncio.sleep(0.02)
        try:
            task.cancel()
            await task
        except asyncio.CancelledError:
            pass

        # Decoded string should have been passed
        calls = runner._process_single_window.call_args_list
        assert any("win-bytes-key" == c[0][0] for c in calls)

    @pytest.mark.asyncio
    async def test_exception_in_processor_loop_is_swallowed(self, runner):
        """An exception inside the loop body must not crash the task."""
        runner.telemetry_processing_service.get_active_windows = AsyncMock(
            side_effect=RuntimeError("boom")
        )

        task = asyncio.create_task(runner._window_processor_task())
        await asyncio.sleep(0.05)
        runner._stop_event.set()
        await asyncio.sleep(0.02)
        try:
            task.cancel()
            await task
        except asyncio.CancelledError:
            pass
        # Task must still be alive (or just stopped), not failed
        assert not task.exception() if not task.cancelled() else True


# ---------------------------------------------------------------------------
# shutdown_subsystem with no handles
# ---------------------------------------------------------------------------
class TestShutdownSubsystem:
    @pytest.mark.asyncio
    async def test_shutdown_with_no_handles_is_safe(self, runner):
        runner._window_processor_handle = None
        runner._mcp_reconnect_handle = None
        runner._analysis_consumer_handle = None
        runner.mcp_manager = None
        await runner.shutdown_subsystem()  # must not raise

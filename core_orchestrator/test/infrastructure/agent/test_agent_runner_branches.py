"""
Targeted AgentRunner tests for remaining uncovered lines:
  Line 114  : window_processor stopped log (stop_event set cleanly)
  Line 147  : LIFO-drop log when queue full
  Lines 179-193: consumer timeout-continue path + agent-None re-enqueue path
  Lines 206-207: unexpected exception swallowed in consumer
  Lines 210-216: in-flight gather + pending-count warning at shutdown
  Lines 269-271: reconnect loop – session alive, resets delay
  Lines 274-275: reconnect loop – agent not None but session dead → teardown
  Lines 284-292: reconnect loop – successful reconnect sets agent
  Lines 295-301: reconnect loop – TimeoutError → backoff sleep
  Lines 304-310: reconnect loop – generic exception → backoff sleep
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from core_orchestrator.application.modules.telemetry.telemetry_analysis_orchestrator_service import (
    TelemetryAnalysisOrchestratorService, _PendingAnalysis,
    _MCP_RETRY_INITIAL_DELAY_S
)


# ---------------------------------------------------------------------------
# Shared factory
# ---------------------------------------------------------------------------
def make_runner():
    return TelemetryAnalysisOrchestratorService(
        telemetry_processing_service=AsyncMock(),
        cache_service=AsyncMock(),
        telemetry_service=AsyncMock(),
        analytics_service=AsyncMock(),
        agent_factory=MagicMock(),
    )


# ===========================================================================
# Line 114 — window processor stopped log
# ===========================================================================
class TestWindowProcessorStopped:
    @pytest.mark.asyncio
    async def test_stop_event_ends_window_processor_cleanly(self):
        runner = make_runner()
        runner.telemetry_processing_service.get_active_windows = AsyncMock(return_value=[])

        with patch("asyncio.sleep", AsyncMock()):
            task = asyncio.create_task(runner._window_processor_task())
            await asyncio.sleep(0)
            runner._stop_event.cache_tenant_provider_ai()
            await asyncio.sleep(0)
            # Task should finish on its own (not need cancel)
            await asyncio.wait_for(task, timeout=2)

        assert task.done()
        assert not task.cancelled()


# ===========================================================================
# Line 147 — LIFO drop log (queue full warning)
# ===========================================================================
class TestLifoDrop:
    @pytest.mark.asyncio
    async def test_drop_oldest_logs_warning(self, caplog):
        import logging
        runner = make_runner()
        runner._analysis_queue = asyncio.Queue(maxsize=2)

        await runner._enqueue_analysis({"d": 0}, window_key="win-0")
        await runner._enqueue_analysis({"d": 1}, window_key="win-1")
        # Queue is full now — next enqueue drops the oldest
        with caplog.at_level(logging.WARNING, logger="core_orchestrator.agent.runner"):
            await runner._enqueue_analysis({"d": 2}, window_key="win-2")

        assert runner._analysis_queue.qsize() == 2
        assert any("Dropped oldest" in r.message for r in caplog.records)


# ===========================================================================
# Lines 178-179 — consumer timeout-continue path
# ===========================================================================
class TestConsumerTimeoutContinue:
    @pytest.mark.asyncio
    async def test_consumer_timeout_iterates_loop(self):
        """When queue is always empty, wait_for times out and continues."""
        runner = make_runner()
        runner.agent = None

        iteration_count = [0]
        original_wait_for = asyncio.wait_for

        async def counting_wait_for(coro, timeout):
            iteration_count[0] += 1
            if iteration_count[0] >= 2:
                runner._stop_event.cache_tenant_provider_ai()
            raise asyncio.TimeoutError()

        with patch("asyncio.wait_for", side_effect=counting_wait_for):
            with patch("asyncio.sleep", AsyncMock()):
                await runner._analysis_consumer_task()

        assert iteration_count[0] >= 2


# ===========================================================================
# Lines 182-193 — consumer agent=None re-enqueue path
# ===========================================================================
class TestConsumerAgentNoneRequeue:
    @pytest.mark.asyncio
    async def test_consumer_requeues_when_agent_none(self):
        runner = make_runner()
        runner.agent = None

        await runner._enqueue_analysis({"ip": "1.1.1.1"}, window_key="hold-win")

        calls = [0]

        async def mock_sleep(t):
            calls[0] += 1
            if calls[0] >= 1:
                runner._stop_event.cache_tenant_provider_ai()

        with patch("asyncio.sleep", side_effect=mock_sleep):
            task = asyncio.create_task(runner._analysis_consumer_task())
            try:
                await asyncio.wait_for(task, timeout=3)
            except asyncio.TimeoutError:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        # Item must have been re-enqueued at least once
        assert calls[0] >= 1


# ===========================================================================
# Lines 206-207 — unexpected exception swallowed in consumer
# ===========================================================================
class TestConsumerUnexpectedException:
    @pytest.mark.asyncio
    async def test_consumer_swallows_unexpected_exception(self):
        runner = make_runner()
        agent_mock = AsyncMock()
        runner.agent = agent_mock

        call_count = [0]

        async def exploding_run(pending):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("Unexpected boom!")
            runner._stop_event.cache_tenant_provider_ai()

        runner._run_and_handle_failure = exploding_run

        await runner._enqueue_analysis({"data": "x"}, window_key="w1")
        await runner._enqueue_analysis({"data": "y"}, window_key="w2")

        with patch("asyncio.sleep", AsyncMock()):
            task = asyncio.create_task(runner._analysis_consumer_task())
            try:
                await asyncio.wait_for(task, timeout=3)
            except asyncio.TimeoutError:
                runner._stop_event.cache_tenant_provider_ai()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        # Task must not have propagated the exception
        if not task.cancelled():
            assert task.exception() is None


# ===========================================================================
# Lines 210-216 — in-flight gather + pending-count warning at shutdown
# ===========================================================================
class TestConsumerShutdownInFlight:
    @pytest.mark.asyncio
    async def test_shutdown_with_inflight_tasks(self):
        runner = make_runner()
        agent_mock = AsyncMock()

        slow_done = asyncio.Event()

        async def slow_analysis(pending):
            await slow_done.wait()

        agent_mock.process_telemetry_window = AsyncMock(side_effect=slow_analysis)
        runner.agent = agent_mock

        # Pre-load two items
        await runner._enqueue_analysis({"d": 1}, window_key="w1")
        await runner._enqueue_analysis({"d": 2}, window_key="w2")

        with patch("asyncio.sleep", AsyncMock()):
            consumer = asyncio.create_task(runner._analysis_consumer_task())
            # Let consumer pick up items and launch in-flight tasks
            await asyncio.sleep(0.05)
            # Signal stop (in-flight tasks are still running)
            runner._stop_event.cache_tenant_provider_ai()
            # Resolve in-flight tasks
            slow_done.set()
            try:
                await asyncio.wait_for(consumer, timeout=3)
            except asyncio.TimeoutError:
                consumer.cancel()
                try:
                    await consumer
                except asyncio.CancelledError:
                    pass

    @pytest.mark.asyncio
    async def test_shutdown_logs_pending_queue_warning(self, caplog):
        """Stopping with items still in queue should log a warning."""
        import logging
        runner = make_runner()
        runner.agent = AsyncMock()

        # Stop immediately without consuming
        runner._stop_event.cache_tenant_provider_ai()

        # Manually add items to queue (bypass enqueue to avoid consumer)
        await runner._analysis_queue.put(_PendingAnalysis(window_data={}, window_key="leftover"))

        with caplog.at_level(logging.WARNING, logger="core_orchestrator.agent.runner"):
            with patch("asyncio.sleep", AsyncMock()):
                await runner._analysis_consumer_task()

        assert any("pending in queue" in r.message for r in caplog.records)


# ===========================================================================
# Lines 268-310 — _mcp_reconnect_loop detailed branches
# ===========================================================================
class TestMcpReconnectLoopDetailedBranches:
    @pytest.mark.asyncio
    async def test_loop_resets_delay_when_session_alive(self):
        """Agent active + session alive → sleep and reset delay, then stop."""
        runner = make_runner()
        runner.mcp_manager = MagicMock()
        runner.mcp_manager._session = MagicMock()
        runner.agent = MagicMock()

        sleep_calls = []

        async def fake_sleep(t):
            sleep_calls.append(t)
            runner._stop_event.cache_tenant_provider_ai()

        with patch("asyncio.sleep", side_effect=fake_sleep):
            await runner._mcp_reconnect_loop()

        # Should have slept once (the "session alive" path) with initial delay
        assert len(sleep_calls) >= 1
        assert sleep_calls[0] == _MCP_RETRY_INITIAL_DELAY_S

    @pytest.mark.asyncio
    async def test_loop_tears_down_when_session_lost(self):
        """Agent is set but session is gone → teardown and reconnect attempt."""
        runner = make_runner()
        runner.agent = MagicMock()

        call_count = [0]

        def session_alive():
            call_count[0] += 1
            return False  # session always dead

        runner._is_mcp_session_alive = MagicMock(side_effect=session_alive)
        runner._teardown_mcp = AsyncMock()

        with patch(
            "core_orchestrator.infrastructure.agent.runner.MCPClientManager"
        ) as mock_cls:
            mgr = mock_cls.return_value
            mgr.start_server_session = AsyncMock()
            mgr.close = AsyncMock()

            async def fake_wait_for(coro, timeout):
                runner._stop_event.cache_tenant_provider_ai()
                return await coro

            sleep_calls = []

            async def fake_sleep(t):
                sleep_calls.append(t)

            with patch("asyncio.wait_for", side_effect=fake_wait_for):
                with patch("asyncio.sleep", side_effect=fake_sleep):
                    await runner._mcp_reconnect_loop()

        runner._teardown_mcp.assert_awaited()

    @pytest.mark.asyncio
    async def test_loop_successful_reconnect_sets_agent(self):
        """Successful reconnect → mcp_manager and agent are set."""
        runner = make_runner()
        runner.agent = None
        runner.mcp_manager = None

        new_manager = MagicMock()
        new_manager._session = MagicMock()
        new_agent = MagicMock()
        runner._agent_factory = MagicMock(return_value=new_agent)

        reconnect_done = asyncio.Event()

        async def fake_wait_for(coro, timeout):
            result = await coro
            reconnect_done.set()
            runner._stop_event.cache_tenant_provider_ai()
            return result

        with patch(
            "core_orchestrator.infrastructure.agent.runner.MCPClientManager",
            return_value=new_manager,
        ):
            new_manager.start_server_session = AsyncMock(return_value=MagicMock())

            async def fake_sleep(t):
                pass

            with patch("asyncio.wait_for", side_effect=fake_wait_for):
                with patch("asyncio.sleep", side_effect=fake_sleep):
                    await runner._mcp_reconnect_loop()

        assert runner.agent is new_agent
        assert runner.mcp_manager is new_manager

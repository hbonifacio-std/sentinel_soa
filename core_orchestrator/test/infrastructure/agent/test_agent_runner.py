import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
from core_orchestrator.infrastructure.adapters.workers.telemetry_processing_worker import TelemetryProcessingWorker, _PendingAnalysis

@pytest.fixture
def mock_telemetry_processing_service():
    return AsyncMock()

@pytest.fixture
def mock_cache_service():
    return AsyncMock()

@pytest.fixture
def mock_telemetry_service():
    return AsyncMock()

@pytest.fixture
def mock_analytics_service():
    return AsyncMock()

@pytest.fixture
def mock_agent_factory():
    return MagicMock()

@pytest.mark.asyncio
async def test_pending_analysis():
    pending = _PendingAnalysis(window_data={"key": "val"})
    assert pending.attempts == 0
    pending.increment()
    assert pending.attempts == 1

@pytest.mark.asyncio
async def test_agent_runner_lifecycle(
    mock_telemetry_processing_service,
    mock_cache_service,
    mock_telemetry_service,
    mock_analytics_service,
    mock_agent_factory
):
    runner = TelemetryProcessingWorker(
        telemetry_processing_service=mock_telemetry_processing_service,
        cache_service=mock_cache_service,
        telemetry_service=mock_telemetry_service,
        analytics_service=mock_analytics_service,
        agent_factory=mock_agent_factory
    )
    
    assert runner.is_mcp_connected is False
    
    # Initialize
    with patch("core_orchestrator.infrastructure.agent.runner.MCPClientManager") as mock_mcp_mgr_cls:
        mock_mcp_mgr = mock_mcp_mgr_cls.return_value
        mock_mcp_mgr.start_server_session = AsyncMock()
        mock_mcp_mgr.close = AsyncMock()
        
        # Call initialize in a patch to avoid long reconnect loop wait times
        with patch("asyncio.sleep", AsyncMock()):
            runner.initialize_subsystem()
            
            # Allow background tasks to run briefly
            await asyncio.sleep(0.05)
            
            # Shutdown
            await runner.shutdown_subsystem()
            
    assert runner.mcp_manager is None
    assert runner.agent is None

@pytest.mark.asyncio
async def test_agent_runner_task_callbacks(
    mock_telemetry_processing_service,
    mock_cache_service,
    mock_telemetry_service,
    mock_analytics_service,
    mock_agent_factory
):
    runner = TelemetryProcessingWorker(
        telemetry_processing_service=mock_telemetry_processing_service,
        cache_service=mock_cache_service,
        telemetry_service=mock_telemetry_service,
        analytics_service=mock_analytics_service,
        agent_factory=mock_agent_factory
    )
    
    # Test done callback when cancelled
    task = MagicMock()
    task.cancelled.return_value = True
    runner._on_background_task_done(task) # Should return directly
    
    # Test done callback with exception
    task.cancelled.return_value = False
    task.exception.return_value = Exception("error")
    runner._on_background_task_done(task) # Should log


@pytest.mark.asyncio
async def test_run_analysis_executes_immediately_when_agent_is_ready(
    mock_telemetry_processing_service,
    mock_cache_service,
    mock_telemetry_service,
    mock_analytics_service,
    mock_agent_factory
):
    runner = TelemetryProcessingWorker(
        telemetry_processing_service=mock_telemetry_processing_service,
        cache_service=mock_cache_service,
        telemetry_service=mock_telemetry_service,
        analytics_service=mock_analytics_service,
        agent_factory=mock_agent_factory
    )

    agent_mock = AsyncMock()
    agent_mock.process_telemetry_window.return_value = '{"status":"ok"}'
    runner.agent = agent_mock

    result = await runner.run_analysis({"window_id": "win-1"})

    assert result == '{"status":"ok"}'
    agent_mock.process_telemetry_window.assert_awaited_once_with({"window_id": "win-1"})


@pytest.mark.asyncio
async def test_agent_runner_enqueue_lifo_drop(
    mock_telemetry_processing_service,
    mock_cache_service,
    mock_telemetry_service,
    mock_analytics_service,
    mock_agent_factory
):
    runner = TelemetryProcessingWorker(
        telemetry_processing_service=mock_telemetry_processing_service,
        cache_service=mock_cache_service,
        telemetry_service=mock_telemetry_service,
        analytics_service=mock_analytics_service,
        agent_factory=mock_agent_factory
    )
    
    # Redefine queue to size 5 to test LIFO dropping easily
    runner._analysis_queue = asyncio.Queue(maxsize=5)
    
    # Fill queue to max size (5)
    for i in range(5):
        await runner._enqueue_analysis({"data": i}, window_key=f"win-{i}")
        
    assert runner._analysis_queue.full() is True
    
    # Enqueue 6th item. Should drop the oldest (win-0)
    await runner._enqueue_analysis({"data": 5}, window_key="win-5")
    assert runner._analysis_queue.full() is True
    
    items = []
    while not runner._analysis_queue.empty():
        items.append(runner._analysis_queue.get_nowait())
        
    # The first item popped should be win-1, win-0 should have been dropped
    assert items[0].window_key == "win-1"
    assert items[-1].window_key == "win-5"


@pytest.mark.asyncio
async def test_process_single_window_not_full_no_ttl(
    mock_telemetry_processing_service,
    mock_cache_service,
    mock_telemetry_service,
    mock_analytics_service,
    mock_agent_factory
):
    runner = TelemetryProcessingWorker(
        telemetry_processing_service=mock_telemetry_processing_service,
        cache_service=mock_cache_service,
        telemetry_service=mock_telemetry_service,
        analytics_service=mock_analytics_service,
        agent_factory=mock_agent_factory
    )
    mock_telemetry_processing_service.is_window_full.return_value = False
    mock_cache_service.get_ttl.return_value = -1  # no TTL

    await runner._process_single_window("win-key")
    mock_cache_service.lock.assert_not_called()


@pytest.mark.asyncio
async def test_process_single_window_full_acquires_lock(
    mock_telemetry_processing_service,
    mock_cache_service,
    mock_telemetry_service,
    mock_analytics_service,
    mock_agent_factory
):
    runner = TelemetryProcessingWorker(
        telemetry_processing_service=mock_telemetry_processing_service,
        cache_service=mock_cache_service,
        telemetry_service=mock_telemetry_service,
        analytics_service=mock_analytics_service,
        agent_factory=mock_agent_factory
    )
    mock_telemetry_processing_service.is_window_full.return_value = True
    mock_cache_service.get_ttl.return_value = 30
    
    lock_mock = AsyncMock()
    lock_mock.acquire.return_value = True
    mock_cache_service.lock = MagicMock(return_value=lock_mock)
    
    mock_telemetry_processing_service.process_window.return_value = MagicMock(
        model_dump=lambda: {"window": "data"}
    )
    
    await runner._process_single_window("win-key")
    
    lock_mock.acquire.assert_called_once_with(blocking=False)
    mock_telemetry_processing_service.process_window.assert_called_once_with("win-key")
    lock_mock.release.assert_called_once()
    assert runner._analysis_queue.qsize() == 1


@pytest.mark.asyncio
async def test_window_processor_task_loop(
    mock_telemetry_processing_service,
    mock_cache_service,
    mock_telemetry_service,
    mock_analytics_service,
    mock_agent_factory
):
    runner = TelemetryProcessingWorker(
        telemetry_processing_service=mock_telemetry_processing_service,
        cache_service=mock_cache_service,
        telemetry_service=mock_telemetry_service,
        analytics_service=mock_analytics_service,
        agent_factory=mock_agent_factory
    )
    mock_telemetry_processing_service.get_active_windows.return_value = [b"win-bytes", "win-str"]
    mock_telemetry_processing_service.is_window_full.return_value = False
    mock_cache_service.get_ttl.return_value = -1

    # Run loop briefly and cancel
    task = asyncio.create_task(runner._window_processor_task())
    await asyncio.sleep(0.01)
    runner._stop_event.set()
    await asyncio.sleep(0.01)
    try:
        task.cancel()
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_run_and_handle_failure_retries_and_discards(
    mock_telemetry_processing_service,
    mock_cache_service,
    mock_telemetry_service,
    mock_analytics_service,
    mock_agent_factory
):
    runner = TelemetryProcessingWorker(
        telemetry_processing_service=mock_telemetry_processing_service,
        cache_service=mock_cache_service,
        telemetry_service=mock_telemetry_service,
        analytics_service=mock_analytics_service,
        agent_factory=mock_agent_factory
    )
    
    agent_mock = AsyncMock()
    agent_mock.process_telemetry_window.side_effect = Exception("MCP down")
    runner.agent = agent_mock
    
    from core_orchestrator.infrastructure.adapters.workers.telemetry_processing_worker import _PendingAnalysis
    pending = _PendingAnalysis(window_data={"data": "test"}, window_key="win-fail")
    
    # We patch asyncio.sleep to run quickly
    with patch("asyncio.sleep", AsyncMock()) as mock_sleep:
        # We also mock _enqueue_analysis to track calls
        runner._enqueue_analysis = AsyncMock()
        
        # Run process multiple times to simulate retry attempts
        # Attempt 1
        await runner._run_and_handle_failure(pending)
        assert pending.attempts == 1
        runner._enqueue_analysis.assert_called_once_with({"data": "test"}, window_key="win-fail")
        
        # Attempt 2
        pending.attempts = 2
        await runner._run_and_handle_failure(pending)
        assert pending.attempts == 3
        
        # Attempt 5 (reaches max retries = 5)
        runner._enqueue_analysis.reset_mock()
        pending.attempts = 5
        await runner._run_and_handle_failure(pending)
        # Should discard, not enqueue again
        runner._enqueue_analysis.assert_not_called()


@pytest.mark.asyncio
async def test_analysis_consumer_task_waits_for_agent(
    mock_telemetry_processing_service,
    mock_cache_service,
    mock_telemetry_service,
    mock_analytics_service,
    mock_agent_factory
):
    runner = TelemetryProcessingWorker(
        telemetry_processing_service=mock_telemetry_processing_service,
        cache_service=mock_cache_service,
        telemetry_service=mock_telemetry_service,
        analytics_service=mock_analytics_service,
        agent_factory=mock_agent_factory
    )
    
    # Agent is None (MCP disconnected)
    runner.agent = None
    
    await runner._enqueue_analysis({"data": "hold"}, window_key="win-hold")
    
    # Start consumer, it should sleep/wait because agent is None
    with patch("asyncio.sleep", AsyncMock()) as mock_sleep:
        consumer_task = asyncio.create_task(runner._analysis_consumer_task())
        await asyncio.sleep(0.01)
        runner._stop_event.set()
        await asyncio.sleep(0.01)
        try:
            consumer_task.cancel()
            await consumer_task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_mcp_reconnect_loop_success_and_failure(
    mock_telemetry_processing_service,
    mock_cache_service,
    mock_telemetry_service,
    mock_analytics_service,
    mock_agent_factory
):
    runner = TelemetryProcessingWorker(
        telemetry_processing_service=mock_telemetry_processing_service,
        cache_service=mock_cache_service,
        telemetry_service=mock_telemetry_service,
        analytics_service=mock_analytics_service,
        agent_factory=mock_agent_factory
    )
    
    # Case 1: Session is alive, do nothing
    runner.agent = MagicMock()
    runner.mcp_manager = MagicMock()
    runner._is_mcp_session_alive = MagicMock(return_value=True)
    
    with patch("asyncio.sleep", AsyncMock()):
        reconnect_task = asyncio.create_task(runner._mcp_reconnect_loop())
        await asyncio.sleep(0.01)
        runner._stop_event.set()
        try:
            reconnect_task.cancel()
            await reconnect_task
        except asyncio.CancelledError:
            pass

    # Case 2: MCP disconnected, triggers reconnect loop success
    runner = TelemetryProcessingWorker(
        telemetry_processing_service=mock_telemetry_processing_service,
        cache_service=mock_cache_service,
        telemetry_service=mock_telemetry_service,
        analytics_service=mock_analytics_service,
        agent_factory=mock_agent_factory
    )
    runner._is_mcp_session_alive = MagicMock(return_value=False)
    
    with patch("core_orchestrator.infrastructure.agent.runner.MCPClientManager") as mock_mcp_mgr_cls:
        mock_mcp_mgr = mock_mcp_mgr_cls.return_value
        mock_mcp_mgr.start_server_session = AsyncMock()
        mock_mcp_mgr.close = AsyncMock()
        
        with patch("asyncio.sleep", AsyncMock()):
            reconnect_task = asyncio.create_task(runner._mcp_reconnect_loop())
            await asyncio.sleep(0.01)
            runner._stop_event.set()
            try:
                reconnect_task.cancel()
                await reconnect_task
            except asyncio.CancelledError:
                pass

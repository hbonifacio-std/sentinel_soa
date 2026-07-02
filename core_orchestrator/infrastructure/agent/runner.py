"""
AI Agent Orchestration Runner Module.

Serves as the unified entry point for the REST API to send telemetry payloads
to the agent's cognitive engine and its MCP tools.

Resilience model:
- MCP server is OPTIONAL at startup. A reconnect loop retries indefinitely.
- All analyses are enqueued; NONE are discarded when MCP is unavailable.
- The analysis consumer drains the queue as soon as MCP is back online.
- In-flight analyses that fail due to MCP disconnection are re-enqueued.
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import Callable, Dict, Any, Optional

from core_orchestrator.application.modules.analysis_reports.services.analytics_service import ReportTelemetryService
from core_orchestrator.infrastructure.agent.mcp_client import MCPClientManager
from core_orchestrator.infrastructure.agent.orchestrator import OrchestratorAgent
from core_orchestrator.application.modules.telemetry.services.telemetry_processing_service import TelemetryProcessingService
from core_orchestrator.application.modules.telemetry.services.telemetry_service import TelemetryService
from core_orchestrator.infrastructure.cache.cache_service import CacheService

logger = logging.getLogger("core_orchestrator.agent.runner")

# ── MCP Reconnect tunables ─────────────────────────────────────────────────
_MCP_RETRY_INITIAL_DELAY_S = 5
_MCP_RETRY_MAX_DELAY_S = 60
_MCP_RETRY_BACKOFF_FACTOR = 2
_MCP_CONNECT_TIMEOUT_S = 15

# ── Analysis queue tunables ────────────────────────────────────────────────
_ANALYSIS_QUEUE_MAXSIZE = 1000   # Máximo de ventanas pendientes en cola
_ANALYSIS_RETRY_DELAY_S = 3      # Espera entre reintentos si MCP no está listo
_ANALYSIS_MAX_RETRIES = 5        # Reintentos máximos por ventana antes de descartar


@dataclass
class _PendingAnalysis:
    """Envelope que viaja por la cola de análisis."""
    window_data: Dict[str, Any]
    attempts: int = 0
    window_key: str = ""         # Identificador para logs

    def increment(self) -> "_PendingAnalysis":
        self.attempts += 1
        return self


class AgentRunner:
    def __init__(
        self,
        telemetry_processing_service: TelemetryProcessingService,
        cache_service: CacheService,
        telemetry_service: TelemetryService,
        analytics_service: ReportTelemetryService,
        agent_factory: Callable[[MCPClientManager], OrchestratorAgent],
    ):
        self.telemetry_processing_service = telemetry_processing_service
        self.cache_service = cache_service
        self.telemetry_service = telemetry_service
        self.analytics_service = analytics_service
        self._agent_factory = agent_factory
        self.mcp_manager: Optional[MCPClientManager] = None
        self.agent: Optional[OrchestratorAgent] = None

        # Cola de análisis pendientes — NUNCA descartamos una ventana por falta de MCP
        self._analysis_queue: asyncio.Queue[_PendingAnalysis] = asyncio.Queue(
            maxsize=_ANALYSIS_QUEUE_MAXSIZE
        )

        # Handles de tasks de fondo
        self._window_processor_handle: Optional[asyncio.Task] = None
        self._analysis_consumer_handle: Optional[asyncio.Task] = None
        self._mcp_reconnect_handle: Optional[asyncio.Task] = None

        # Set de tasks de análisis activos (in-flight)
        self._inflight_tasks: set = set()

        # Señal de parada para el shutdown limpio
        self._stop_event = asyncio.Event()

    @property
    def is_mcp_connected(self) -> bool:
        """Public property to check if the MCP session is active."""
        return self._is_mcp_session_alive()

    # ──────────────────────────────────────────────────────────────────────
    # 1. PRODUCER: Window Processor  →  Analysis Queue
    # ──────────────────────────────────────────────────────────────────────

    async def _window_processor_task(self) -> None:
        """
        Detecta ventanas de telemetría listas para analizar y las mete a la cola.
        NO llama al agente directamente: desacopla producción de consumo.
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
        """Evalúa y encola una ventana individual si está lista."""
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
        Encola una ventana para análisis. Si la cola está llena, descarta la
        más antigua (política LIFO-drop para evitar análisis obsoletos).
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

    # ──────────────────────────────────────────────────────────────────────
    # 2. CONSUMER: Analysis Queue  →  Agent
    # ──────────────────────────────────────────────────────────────────────

    async def _analysis_consumer_task(self) -> None:
        """
        Consume la cola de análisis y envía cada ventana al agente IA.

        Garantías:
        - Si MCP no está listo, ESPERA en lugar de descartar.
        - Si el análisis falla por desconexión, REENCOLA.
        - Aplica backoff exponencial en reintentos.
        - Descarta solo tras _ANALYSIS_MAX_RETRIES intentos fallidos.
        """
        logger.info("Analysis consumer started.")
        while not self._stop_event.is_set():
            try:
                # Espera un ítem de la cola (timeout para chequear stop_event)
                try:
                    pending = await asyncio.wait_for(
                        self._analysis_queue.get(),
                        timeout=2.0
                    )
                except asyncio.TimeoutError:
                    continue  # Re-evalúa stop_event

                # Si el agente no está disponible, esperamos SIN descartar el ítem
                if self.agent is None:
                    wait_time = _ANALYSIS_RETRY_DELAY_S
                    logger.info(
                        f"MCP not ready. Holding window '{pending.window_key}' "
                        f"(attempt {pending.attempts + 1}). "
                        f"Re-checking in {wait_time}s..."
                    )
                    await asyncio.sleep(wait_time)
                    # Reencola al frente (re-put para priorizar)
                    await self._analysis_queue.put(pending)
                    self._analysis_queue.task_done()
                    continue

                # Lanzamos el análisis como task para no bloquear el consumer
                task = asyncio.create_task( # Corrected from asyncio..create_task
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

        # Shutdown: esperamos que terminen los análisis en curso
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
        Ejecuta un análisis. Si falla (p.ej. MCP caído), reencola para reintento.
        """
        pending.increment()
        window_key = pending.window_key or "unknown"
        try:
            result = await self.agent.process_telemetry_window(pending.window_data)
            del result
            logger.info(f"Analysis completed for window '{window_key}' ...")
        except Exception as e:
            # El agente falló — posiblemente MCP se cayó mid-flight
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

    # ──────────────────────────────────────────────────────────────────────
    # 3. MCP RECONNECT LOOP
    # ──────────────────────────────────────────────────────────────────────

    async def _mcp_reconnect_loop(self) -> None:
        """
        🔄 Loop de reconexión resiliente para el servidor MCP.

        - API arranca sin MCP → reintenta con backoff exponencial.
        - MCP sube después del startup → conecta y activa el agente.
        - MCP cae en producción → detecta y reconecta.
        """
        delay = _MCP_RETRY_INITIAL_DELAY_S

        while not self._stop_event.is_set():
            # Si ya tenemos agente activo, verificamos que la sesión siga viva
            if self.agent is not None and self._is_mcp_session_alive():
                await asyncio.sleep(delay)
                delay = _MCP_RETRY_INITIAL_DELAY_S  # reset backoff
                continue

            if self.agent is not None:
                logger.warning("MCP session lost. Tearing down and reconnecting...")
                await self._teardown_mcp()

            logger.info("MCP Reconnect Loop: attempting connection...")
            try:
                new_manager = MCPClientManager()
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
            except Exception:
                pass
        self.mcp_manager = None
        self.agent = None

    # ──────────────────────────────────────────────────────────────────────
    # 4. CICLO DE VIDA
    # ──────────────────────────────────────────────────────────────────────

    def initialize_subsystem(self) -> None:
        """
        Arranca todos los workers en background.
        NO bloquea el startup del servidor REST.
        """
        logger.info("Initializing Agent subsystem...")
        self._stop_event.clear()

        self._mcp_reconnect_handle = asyncio.create_task(
            self._mcp_reconnect_loop(), name="mcp-reconnect"
        )
        self._mcp_reconnect_handle.add_done_callback(self._on_background_task_done)

        self._analysis_consumer_handle = asyncio.create_task( # Corrected from asyncio..create_task
            self._analysis_consumer_task(), name="analysis-consumer"
        )
        self._analysis_consumer_handle.add_done_callback(self._on_background_task_done)

        self._window_processor_handle = asyncio.create_task(
            self._window_processor_task(), name="window-processor"
        )
        self._window_processor_handle.add_done_callback(self._on_background_task_done)

        logger.info(
            "Agent subsystem started: "
            "[window-processor] → [analysis-queue] → [analysis-consumer] → [mcp-agent]"
        )

    async def shutdown_subsystem(self) -> None:
        """Detiene todos los workers limpiamente, esperando in-flight analyses."""
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

    def _on_background_task_done(self, task: asyncio.Task) -> None:
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


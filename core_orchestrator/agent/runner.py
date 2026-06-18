"""
Módulo Runner de Orquestación del Agente de IA.

Sirve como el punto de entrada unificado para que la API REST envíe payloads
de telemetría hacia el motor cognitivo del agente y sus herramientas MCP.
"""

import asyncio
import logging
from typing import Dict, Any, Optional

from core_orchestrator.config import orchestrator_settings as settings
from core_orchestrator.agent.mcp_client import MCPClientManager
from core_orchestrator.agent.orchestrator import GeminiOrchestratorAgent
from core_orchestrator.services.database import db
from core_orchestrator.services.window_manager import window_manager

logger = logging.getLogger("core_orchestrator.agent.runner")


class AgentRunner:
    """
    Fachada responsable de gestionar la persistencia en memoria del cliente MCP
    y coordinar las llamadas concurrentes hacia el agente orquestador.
    """

    def __init__(self):
        self.mcp_manager: Optional[MCPClientManager] = None
        self.agent: Optional[GeminiOrchestratorAgent] = None
        self._initialization_task: Optional[asyncio.Task] = None
        self._window_processor_handle: Optional[asyncio.Task] = None
        self._initialized: bool = False

    async def _init_mcp_background(self) -> None:
        """
        Inicializa MCP en background sin bloquear FastAPI.
        """
        try:
            logger.info("Inicializando subsistema MCP en background...")
            if not self.mcp_manager:
                self.mcp_manager = MCPClientManager(
                    server_script_path=settings.mcp_log_analysis_server_cmd)

            await self.mcp_manager.start_server_session(timeout=60.0)
            self.agent = GeminiOrchestratorAgent(mcp_manager=self.mcp_manager)
            self._initialized = True
            logger.info(
                "Subsistema del Agente y Servidores MCP desplegado con éxito.")
        except Exception as exc:
            logger.error(
                f"Error al inicializar MCP en background: {str(exc)}", exc_info=True)
            self._initialized = False

    async def _window_processor_task(self):
        """
        Tarea en segundo plano que procesa las ventanas de telemetría de Redis.
        NOTA: Este es un enfoque simple. Para un sistema de producción, se podría
        mejorar usando notificaciones de espacio de claves de Redis para procesar
        las ventanas tan pronto como expiren, en lugar de sondear.
        """
        while True:
            try:
                keys = await window_manager.get_active_windows()
                for key in keys:
                    # Intentamos obtener un bloqueo para esta clave para evitar procesamiento duplicado
                    lock = await agent_runner.agent.get_redis_lock(f"lock:{key.decode('utf-8')}")
                    if await lock.acquire(blocking=False):
                        try:
                            ttl = await db.redis_client.ttl(key)
                            # Si la clave está a punto de expirar, la procesamos
                            if ttl < 10:  # Umbral de 10 segundos
                                telemetry_window = await window_manager.process_window(key.decode("utf-8"))
                                if telemetry_window:
                                    asyncio.create_task(self.run_analysis(
                                        telemetry_window.model_dump()))
                        finally:
                            await lock.release()
            except Exception as e:
                logger.error(
                    f"Error en el procesador de ventanas: {e}", exc_info=True)
            # Esperar 5 segundos antes de la siguiente iteración
            await asyncio.sleep(5)

    async def initialize_subsytem(self) -> None:
        """
        Inicia la inicialización de MCP y el procesador de ventanas como tareas de fondo.
        """
        logger.info(
            "Iniciando subsistema del Agente y Canales MCP (background)...")
        self._initialization_task = asyncio.create_task(
            self._init_mcp_background())
        self._window_processor_handle = asyncio.create_task(
            self._window_processor_task())
        await asyncio.sleep(0.5)
        logger.info(
            "FastAPI iniciando mientras los subsistemas se configuran en background...")

    async def wait_for_mcp_ready(self, timeout: float = 30.0) -> bool:
        """
        Espera a que MCP esté listo. Útil para las primeras solicitudes.
        """
        if self._initialized:
            return True

        if self._initialization_task is None:
            logger.error("No hay tarea de inicialización activa")
            return False

        try:
            await asyncio.wait_for(self._initialization_task, timeout=timeout)
            return self._initialized
        except asyncio.TimeoutError:
            logger.error(
                f"Timeout esperando a que MCP se inicialice (>{timeout}s)")
            return False

    async def run_analysis(self, telemetry_window: Dict[str, Any]) -> str:
        """
        Envía una ventana temporal preprocesada de eventos HTTP al agente para su evaluación.
        """
        if self._initialization_task and not self._initialization_task.done():
            await self._initialization_task

        if not self.agent:
            raise RuntimeError(
                "El subsistema del agente no ha sido inicializado.")

        return await self.agent.process_telemetry_window(telemetry_window)

    async def shutdown_subsytem(self) -> None:
        """
        Libera de forma controlada los recursos y subprocesos abiertos.
        """
        if self._window_processor_handle:
            self._window_processor_handle.cancel()
        if self.mcp_manager:
            logger.info("Apagando canales de comunicación MCP...")
            await self.mcp_manager.close()
            logger.info("Subsistema MCP apagado correctamente.")


# Instancia única global (Singleton) para ser compartida a lo largo de la aplicación FastAPI
agent_runner = AgentRunner()

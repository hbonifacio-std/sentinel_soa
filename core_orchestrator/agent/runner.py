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
        self._initialized: bool = False

    async def _init_mcp_background(self) -> None:
        """
        Inicializa MCP en background sin bloquear FastAPI.
        """
        try:
            logger.info("Inicializando subsistema MCP en background...")
            # La instancia del manager debe ser creada y asignada a self ANTES de usarla
            # para asegurar que su ciclo de vida persista junto con el AgentRunner.
            if not self.mcp_manager:
                self.mcp_manager = MCPClientManager(server_script_path=settings.mcp_log_analysis_server_cmd)
            
            await self.mcp_manager.start_server_session(timeout=60.0) # Ahora se llama sobre la instancia persistente
            self.agent = GeminiOrchestratorAgent(mcp_manager=self.mcp_manager)
            self._initialized = True
            logger.info("Subsistema del Agente y Servidores MCP desplegado con éxito.")
        except Exception as exc:
            logger.error(f"Error al inicializar MCP en background: {str(exc)}", exc_info=True)
            self._initialized = False

    async def initialize_subsytem(self) -> None:
        """
        Inicia la inicialización de MCP como una tarea background sin bloquear FastAPI.
        Este método es invocado típicamente en el evento de arranque (lifespan) de FastAPI.
        """
        logger.info("Iniciando subsistema del Agente y Canales MCP (background)...")
        # Crear una tarea asincrónica que se ejecute en background
        self._initialization_task = asyncio.create_task(self._init_mcp_background())
        # Esperar un poco para permitir que FastAPI comience
        await asyncio.sleep(0.5)
        logger.info("FastAPI iniciando mientras MCP se configura en background...")

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
            logger.error(f"Timeout esperando a que MCP se inicialice (>{timeout}s)")
            return False

    async def run_analysis(self, telemetry_window: Dict[str, Any]) -> str:
        """
        Envía una ventana temporal preprocesada de eventos HTTP al agente para su evaluación.

        Args:
            telemetry_window (Dict[str, Any]): Datos estructurados agregados por IP.

        Returns:
            str: Reporte analítico final emitido por la IA.
        """
        if self._initialization_task and not self._initialization_task.done():
            await self._initialization_task

        if not self.agent:
            raise RuntimeError("El subsistema del agente no ha sido inicializado mediante 'initialize_subsytem'.")
        
        return await self.agent.process_telemetry_window(telemetry_window)

    async def shutdown_subsytem(self) -> None:
        """
        Libera de forma controlada los recursos y subprocesos abiertos del canal MCP.
        """
        if self.mcp_manager:
            logger.info("Apagando canales de comunicación MCP...")
            await self.mcp_manager.close()
            logger.info("Subsistema MCP apagado correctamente.")


# Instancia única global (Singleton) para ser compartida a lo largo de la aplicación FastAPI
agent_runner = AgentRunner()
"""
Módulo del Cliente MCP para el Core Orchestrator usando FastMCP.

Gestiona la inicialización de la conexión con el servidor MCP, soportando
transportes HTTP (para producción/Docker) y stdio (para depuración local).
"""

import asyncio
import logging
import os
import sys
from typing import Dict, Any, Optional

from fastmcp.client import Client

logger = logging.getLogger("core_orchestrator.mcp_client")


class MCPClientManager:
    """
    Administrador de Conexión del Cliente MCP.
    Se encarga de inicializar la conexión con el servidor y mantener la sesión activa.
    """

    def __init__(self, server_script_path: Optional[str] = None):
        """
        Inicializa el mánager.

        Args:
            server_script_path (str, optional): Ruta al script del servidor, requerido para el modo stdio.
        """
        self.server_script_path = server_script_path
        self._client: Optional[Client] = None

    async def start_server_session(self, timeout: float = 60.0) -> Client:
        """
        Establece la sesión de comunicación con el servidor MCP, usando HTTP o stdio.

        Args:
            timeout: Tiempo máximo en segundos para la inicialización (default 60s)

        Returns:
            Client: Cliente inicializado y listo para usarse.
        """
        transport_mode = os.getenv('MCP_TRANSPORT', 'http').lower()
        logger.info(
            f"Iniciando sesión FastMCP en modo de transporte: {transport_mode}")

        client: Client

        try:
            async def _create_client():
                if transport_mode == 'http':
                    host = os.getenv('MCP_SERVER_HOST', 'localhost')
                    port = int(os.getenv('MCP_SERVER_PORT', '8080'))
                    # FastMCP HTTP transport exposes its endpoint under /mcp
                    url = f"http://{host}:{port}/mcp"
                    logger.info(
                        f"Configurando cliente FastMCP para conectar a {url}")
                    return Client(url)

                elif transport_mode == 'stdio':
                    if not self.server_script_path:
                        raise ValueError(
                            "El 'server_script_path' es requerido para el modo stdio.")

                    logger.info(
                        f"Levantando servidor FastMCP desde: {self.server_script_path}")
                    python_executable = sys.executable
                    command = [
                        python_executable,
                        "-u",  # Forza stdout/stderr sin buffer
                        "-m", self.server_script_path
                    ] if not self.server_script_path.endswith(".py") else [
                        python_executable,
                        "-u",  # Forza stdout/stderr sin buffer
                        self.server_script_path
                    ]
                    return Client(command)

                else:
                    raise ValueError(
                        f"Modo de transporte no válido: '{transport_mode}'. Usar 'http' o 'stdio'.")

            self._client = await asyncio.wait_for(_create_client(), timeout=timeout)
            # Inicializar la sesión
            # Enter client context to establish the background session and perform
            # the MCP initialization handshake. Use the public initialize() API.
            async with self._client:
                await self._client.initialize()
            logger.info("Cliente FastMCP conectado y listo.")
            return self._client

        except asyncio.TimeoutError:
            logger.critical(
                f"Timeout durante inicialización FastMCP (>{timeout}s) - el servidor no responde o está bloqueado.")
            raise RuntimeError(
                f"Timeout al inicializar FastMCP después de {timeout}s")
        except Exception as exc:
            logger.critical(
                f"Error fatal al conectar con el servidor FastMCP: {str(exc)}", exc_info=True)
            raise RuntimeError(
                f"No se pudo inicializar la sesión FastMCP: {str(exc)}") from exc

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Envía una solicitud de ejecución de método al servidor remoto.

        Args:
            tool_name (str): Nombre del método a ejecutar (ej: 'analyze_web_activity').
            arguments (Dict[str, Any]): Argumentos estructurados requeridos por el método.

        Returns:
            Dict[str, Any]: Respuesta deserializada del servidor.
        """
        if not self._client:
            raise RuntimeError("El cliente FastMCP no se encuentra activo.")

        logger.info(f"Invocando herramienta MCP remota: {tool_name}")
        try:
            async with self._client:
                result = await self._client.call_tool(tool_name, arguments)
            return result
        except Exception as exc:
            logger.error(
                f"Falla al ejecutar call para '{tool_name}': {str(exc)}", exc_info=True)
            return {"error": f"Excepción en la ejecución de la herramienta remota: {str(exc)}"}

    async def close(self):
        """
        Cierra de forma ordenada la conexión con el servidor.
        """
        if self._client:
            logger.info("Cerrando conexión del cliente FastMCP...")
            await self._client.close()
            self._client = None
            logger.info("Conexión FastMCP finalizada correctamente.")

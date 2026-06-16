# mcp_servers/log_analysis_server/server.py

import os
import sys
import logging
import asyncio
from typing import Dict, Any, List

from fastmcp.server import FastMCP

# Importar las funciones reales de análisis con heurísticas
from mcp_servers.log_analysis_server.tools.analyze_activity import execute_analyze_web_activity
from mcp_servers.log_analysis_server.tools.threat_context import execute_get_threat_context

# --- Configuración de Logging de Grado de Producción ---
if logging.root.handlers:
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format=log_format,
    force=True
)
logger = logging.getLogger(__name__)

# --- Inicializar servidor ---
server = FastMCP("log-analysis-server")

# --- Registrar herramientas reales con heurísticas ---
@server.tool()
async def analyze_web_activity(
        window_id: str,
        source_ip: str,
        window_start_utc: str,
        window_end_utc: str,
        total_requests: int,
        unique_uris_requested: List[str],
        http_methods_distribution: Dict[str, int],
        response_codes_distribution: Dict[str, int],
        user_agents_observed: List[str],
        requests_per_second_avg: float
) -> Dict[str, Any]:
    """
    Analiza la telemetría web para detectar amenazas usando heurísticas + LLM.

    Args:
        window_id: Identificador de la ventana.
        source_ip: IP de origen bajo análisis.
        window_start_utc: Timestamp de inicio.
        window_end_utc: Timestamp de fin.
        total_requests: Total de peticiones.
        unique_uris_requested: Lista de URIs consultadas.
        http_methods_distribution: Distribución de métodos HTTP.
        response_codes_distribution: Distribución de códigos de respuesta.
        user_agents_observed: Lista de User-Agents vistos.
        requests_per_second_avg: Promedio de peticiones por segundo.
    """
    # Reconstruimos el diccionario 'arguments' que espera tu execute_analyze_web_activity
    payload = {
        "window_id": window_id,
        "source_ip": source_ip,
        "window_start_utc": window_start_utc,
        "window_end_utc": window_end_utc,
        "total_requests": total_requests,
        "unique_uris_requested": unique_uris_requested,
        "http_methods_distribution": http_methods_distribution,
        "response_codes_distribution": response_codes_distribution,
        "user_agents_observed": user_agents_observed,
        "requests_per_second_avg": requests_per_second_avg
    }

    logger.info(f"Herramienta MCP 'analyze_web_activity' invocada exitosamente para IP: {source_ip}")

    try:
        # Se lo enviamos limpio a tu función interna sin tocar nada de tu core
        return await execute_analyze_web_activity(payload)
    except Exception as e:
        logger.error(f"Error en la ejecución de la herramienta: {str(e)}", exc_info=True)
        return {
            "window_id": window_id,
            "threat_detected": False,
            "error": str(e)
        }
@server.tool()
async def get_threat_context(source_ip: str = "N/A", limit: int = 5) -> Dict[str, Any]:
    """
    Obtiene el historial de amenazas para una IP específica.
    """
    logger.info(f"Herramienta MCP 'get_threat_context' invocada para IP: {source_ip}")
    try:
        # Construir argumentos en el formato esperado
        arguments = {"source_ip": source_ip, "limit": limit}
        return await execute_get_threat_context(arguments)
    except Exception as e:
        logger.error(f"Error en get_threat_context: {str(e)}", exc_info=True)
        return {
            "source_ip": source_ip,
            "history": [],
            "record_count": 0,
            "error": str(e)
        }

# --- Lógica de Arranque del Servidor ---
async def main():
    """
    Inicializa y corre el servidor MCP, seleccionando el transporte
    basado en la variable de entorno MCP_TRANSPORT.
    """
    transport_mode = os.getenv('MCP_TRANSPORT', 'http').lower()
    
    logger.info("Tools 'analyze_web_activity' and 'get_threat_context' registered.")

    if transport_mode == 'stdio':
        logger.info("Starting FastMCP Log Analysis Server over stdio channel...")
        await server.run_async(transport='stdio')

    elif transport_mode == 'http':
        host = os.getenv('MCP_SERVER_HOST', '0.0.0.0')
        port = int(os.getenv('MCP_SERVER_PORT', '8080'))
        logger.info(f"Starting FastMCP Log Analysis Server on HTTP at {host}:{port}...")
        await server.run_async(transport='http', host=host, port=port)
        
    else:
        logger.error(f"Invalid MCP_TRANSPORT: '{transport_mode}'. Use 'stdio' or 'http'.")
        sys.exit(1)

if __name__ == "__main__":
    try:
        # Este log inicial es seguro porque la configuración de logging ya está forzada a stderr.
        logger.info("MCP Server process starting.")
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("MCP Server shutting down.")
    except Exception as e:
        logger.error(f"MCP Server failed to start: {e}", exc_info=True)

"""
Módulo de la herramienta MCP para la recuperación de contexto de amenazas históricas.

Este archivo contiene la implementación de la herramienta 'get_threat_context',
la cual expone al agente LLM el historial de alertas previas asociadas a una IP
para identificar reincidencia y patrones de ataque persistentes.
"""

import logging
from typing import Dict, Any, List

from mcp_servers.log_analysis_server.store.alert_store import alert_store

# Configuración del logger local
logger = logging.getLogger(__name__)


async def execute_get_threat_context(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recupera las alertas previas de una IP de origen específica desde el almacén en memoria.

    Args:
        arguments (Dict[str, Any]): Argumentos de la herramienta provistos por el LLM.
            Se espera un diccionario con la clave obligatoria 'source_ip' y opcional 'limit'.

    Returns:
        Dict[str, Any]: Un contenedor con la lista de alertas previas formateadas
            como diccionarios estructurados, listo para el ciclo tool_result del agente.

    Raises:
        ValueError: Si los parámetros requeridos no están presentes o son inválidos.
    """
    try:
        # 1. Validación manual expedita de parámetros requeridos (contrato MCP)
        if "source_ip" not in arguments:
            raise ValueError("El parámetro requerido 'source_ip' no fue suministrado.")
        
        source_ip: str = str(arguments["source_ip"])
        limit: int = int(arguments.get("limit", 10))

        logger.info(f"Ejecutando 'get_threat_context' para IP: {source_ip} (Límite: {limit})")

        # 2. Consulta al almacén thread-safe en memoria
        historical_alerts = alert_store.get_history_by_ip(source_ip, limit=limit)
        
        # 3. Formateo y serialización limpia de los objetos estructurados a tipos nativos
        formatted_alerts: List[Dict[str, Any]] = [
            alert.model_dump() for alert in historical_alerts
        ]

        logger.debug(f"Retornando {len(formatted_alerts)} alertas históricas encontradas para {source_ip}.")

        # Envolvemos el resultado en un payload JSON nativo dictaminado por MCP
        return {
            "source_ip": source_ip,
            "alerts_found": len(formatted_alerts),
            "history": formatted_alerts
        }

    except ValueError as val_err:
        logger.error(f"Error de parámetros en 'get_threat_context': {str(val_err)}")
        raise ValueError(f"Argumentos inválidos para la herramienta: {str(val_err)}") from val_err
        
    except Exception as exc:
        logger.critical(f"Falla inesperada al recuperar contexto de amenazas: {str(exc)}")
        raise Exception(f"Error interno en la ejecución de la herramienta de contexto: {str(exc)}") from exc
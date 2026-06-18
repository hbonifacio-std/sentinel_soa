"""
Módulo del Administrador de Ventanas de Tiempo Agregadas.

Agrupa eventos individuales de telemetría HTTP por ventanas de tiempo
atendiendo a la IP de origen, consolidando las métricas de distribución de tráfico.
"""

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any
import json

from core_orchestrator.models.log_event import LogEvent as LogLine
from core_orchestrator.models.telemetry_window import TelemetryWindow
from core_orchestrator.services.database import db

logger = logging.getLogger("core_orchestrator.services.window_manager")


class WindowManager:
    """
    Gestor de agregación temporal de telemetría HTTP en Redis.
    """

    def __init__(self, window_duration_seconds: int = 120):
        self.window_duration = window_duration_seconds

    async def add_log_event(self, log_line: LogLine) -> None:
        """
        Inserta un evento de log procesado dentro de la lista de Redis correspondiente a su IP.
        """
        key = f"window:{log_line.source_ip}"
        # Si la lista no existe, Redis la crea automáticamente con RPUSH
        # y el comando EXPIRE la marcará para su eliminación si no hay actividad
        await db.redis_client.rpush(key, log_line.model_dump_json())
        await db.redis_client.expire(key, self.window_duration)

    def get_window_key(self, log_line: LogLine) -> str:
        """
        Genera la clave de Redis para la ventana de un evento de log.
        """
        return f"window:{log_line.source_ip}"

    async def get_window_size(self, key: str) -> int:
        """
        Obtiene el número de eventos en una ventana (el tamaño de la lista de Redis).
        """
        if not key:
            return 0
        return await db.redis_client.llen(key)

    async def get_active_windows(self) -> List[str]:
        """
        Obtiene todas las claves de ventanas activas.
        """
        return await db.redis_client.keys("window:*")

    async def process_window(self, key: str) -> TelemetryWindow:
        """
        Procesa una ventana de telemetría a partir de una clave de Redis.
        """
        source_ip = key.split(":")[1]
        events_json = await db.redis_client.lrange(key, 0, -1)
        await db.redis_client.delete(key)  # Limpiamos la ventana de Redis

        events = [LogLine.model_validate_json(e) for e in events_json]

        if not events:
            return None

        total_requests = len(events)

        methods_dist: Dict[str, int] = defaultdict(int)
        codes_dist: Dict[str, int] = defaultdict(int)
        unique_uris = set()
        unique_agents = set()
        source_ids = set()

        for ev in events:
            methods_dist[ev.http_method] += 1
            codes_dist[str(ev.response_code)] += 1
            unique_uris.add(ev.request_uri)
            unique_agents.add(ev.user_agent)

            if ev.source_id:
                source_ids.add(ev.source_id)
        # La duración es aproximada, ya que no guardamos el timestamp de inicio exacto en Redis.
        # Podríamos mejorarlo guardando un timestamp de inicio con cada ventana.
        duration_sec = self.window_duration
        rps_avg = round(total_requests / duration_sec,
                        2) if duration_sec > 0 else 0.0

        window_model = TelemetryWindow(
            window_id=uuid.uuid4(),
            source_ip=source_ip,
            window_start_utc=datetime.now(
                timezone.utc) - timedelta(seconds=self.window_duration),
            window_end_utc=datetime.now(timezone.utc),
            total_requests=total_requests,
            source_id=list(source_ids)[0] if source_ids else "unknown",
            unique_uris_requested=list(unique_uris),
            http_methods_distribution=dict(methods_dist),
            response_codes_distribution=dict(codes_dist),
            user_agents_observed=list(unique_agents),
            requests_per_second_avg=rps_avg
        )
        return window_model


# Creamos una instancia global para ser usada en la aplicación
window_manager = WindowManager()

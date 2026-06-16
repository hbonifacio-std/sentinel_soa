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

from core_orchestrator.models.log_event import LogEvent as LogLine
from core_orchestrator.models.telemetry_window import TelemetryWindow

logger = logging.getLogger("core_orchestrator.services.window_manager")


class WindowManager:
    """
    Gestor de agregación temporal de telemetría HTTP en memoria.
    """

    # 💡 CONSEJO PARA TU TESIS: Aumentar window_duration_seconds a 120 o 300 
    # reduce drásticamente el número de llamadas a Gemini, agrupando más actividad por IP.
    def __init__(self, window_duration_seconds: int = 120):
        self.window_duration = timedelta(seconds=window_duration_seconds)
        # Almacenamiento indexado por IP: contiene la lista de LogLines activos en la ventana corriente
        self._active_buffers: Dict[str, List[LogLine]] = defaultdict(list)
        # Registra el momento de inicio del ciclo de la ventana actual
        self._current_window_start = datetime.now(timezone.utc)

    def add_log_event(self, log_line: LogLine) -> None:
        """
        Inserta un evento de log procesado dentro del buffer correspondiente de su IP.
        """
        self._active_buffers[log_line.source_ip].append(log_line)

    def should_flush(self) -> bool:
        """
        Determina si el ciclo de tiempo de la ventana actual ha expirado y se debe realizar el corte.
        """
        return (datetime.now(timezone.utc) - self._current_window_start) >= self.window_duration

    def flush_and_aggregate(self) -> List[TelemetryWindow]:
        """
        Realiza el corte analítico de la ventana temporal actual. 
        Calcula distribuciones estadísticas por cada IP y vacía los buffers para el siguiente ciclo.

        Returns:
            List[TelemetryWindow]: Lista de ventanas agregadas y listas para su envío al Agente.
        """
        aggregated_windows: List[TelemetryWindow] = []
        end_time = datetime.now(timezone.utc)
        
        logger.info(f"Ejecutando flush de ventana temporal. IPs activas a procesar: {len(self._active_buffers)}")

        for source_ip, events in self._active_buffers.items():
            if not events:
                continue

            total_requests = len(events)
            
            # Cálculo de distribuciones mediante diccionarios primitivos de conteo
            methods_dist: Dict[str, int] = defaultdict(int)
            codes_dist: Dict[str, int] = defaultdict(int)
            unique_uris = set()
            unique_agents = set()

            for ev in events:
                methods_dist[ev.http_method] += 1
                codes_dist[str(ev.response_code)] += 1
                unique_uris.add(ev.request_uri)
                unique_agents.add(ev.user_agent)

            # Cálculo aproximado de peticiones por segundo dentro de esta ventana
            duration_sec = (end_time - self._current_window_start).total_seconds()
            rps_avg = round(total_requests / duration_sec, 2) if duration_sec > 0 else 0.0

            # Construcción del modelo estricto de TelemetryWindow
            window_model = TelemetryWindow(
                window_id=uuid.uuid4(),
                source_ip=source_ip,
                window_start_utc=self._current_window_start,
                window_end_utc=end_time,
                total_requests=total_requests,
                unique_uris_requested=list(unique_uris),
                http_methods_distribution=dict(methods_dist),
                response_codes_distribution=dict(codes_dist),
                user_agents_observed=list(unique_agents),
                requests_per_second_avg=rps_avg
            )
            aggregated_windows.append(window_model)

        # Reseteo absoluto del estado de los buffers de memoria
        self._active_buffers.clear()
        self._current_window_start = datetime.now(timezone.utc)
        
        return aggregated_windows
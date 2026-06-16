"""Módulo de almacenamiento en memoria para el Servidor MCP.

Provee un almacén thread-safe (seguro para hilos) basado en colecciones indexadas
para retener las alertas tempranas procesadas y permitir la consulta rápida de historial.
"""

import threading
from collections import defaultdict
from typing import Dict, List, Optional
from uuid import UUID

from mcp_servers.log_analysis_server.models.analysis_output import ThreatAssessment


class InMemoryAlertStore:
    """Gestiona de forma segura el almacenamiento en RAM de las alertas generadas.
    
    Implementa bloqueos de exclusión mutua (Mutex) para evitar condiciones de carrera
    cuando el host realiza consultas asíncronas concurrentes sobre herramientas MCP.
    """

    def __init__(self, max_history_per_ip: int = 50) -> None:
        """Inicializa los diccionarios internos y los mecanismos de bloqueo.
        
        Args:
            max_history_per_ip (int): Número máximo de veredictos que retendremos por IP.
        """
        self._max_history: int = max_history_per_ip
        # Diccionario indexado por IP: [ThreatAssessment, ThreatAssessment, ...]
        self._store: Dict[str, List[ThreatAssessment]] = defaultdict(list)
        # Lock primitivo para garantizar consistencia en lectura/escritura concurrente
        self._lock: threading.Lock = threading.Lock()

    def add_assessment(self, ip: str, assessment: ThreatAssessment) -> None:
        """Registra un nuevo veredicto analítico en el historial de una IP.
        
        Si el historial de la IP excede el límite máximo configurado, se remueve 
        el registro más antiguo (comportamiento similar a una cola FIFO).

        Args:
            ip (str): Dirección IP de origen evaluada.
            assessment (ThreatAssessment): Objeto con los datos del veredicto del LLM.
        """
        with self._lock:
            # Insertar el veredicto más reciente al inicio de la lista
            self._store[ip].insert(0, assessment)
            
            # Recorte preventivo para evitar fugas de memoria por almacenamiento infinito
            if len(self._store[ip]) > self._max_history:
                self._store[ip] = self._store[ip][:self._max_history]

    def get_history_by_ip(self, ip: str, limit: int = 10) -> List[ThreatAssessment]:
        """Recupera el listado cronológico de veredictos históricos para una IP específica.

        Args:
            ip (str): Dirección IP de consulta.
            limit (int): Cantidad máxima de registros históricos a retornar.

        Returns:
            List[ThreatAssessment]: Lista de objetos de evaluación de amenazas.
        """
        with self._lock:
            if ip not in self._store:
                return []
            # Retorna una copia de la lista rebanada para evitar mutaciones externas corruptas
            return list(self._store[ip][:limit])

    def clear_all(self) -> None:
        """Purga por completo todos los registros de la memoria del almacén."""
        with self._lock:
            self._store.clear()


# Instancia compartida única (Singleton) a nivel de servidor MCP para conservar consistencia de estado
alert_store = InMemoryAlertStore()
"""
Módulo del Modelo de Telemetría Agregada (TelemetryWindow).

Define el esquema de datos que consolida las métricas de comportamiento
de una dirección IP durante un intervalo temporal específico.
"""

from datetime import datetime
from uuid import UUID
from typing import List, Dict
from pydantic import BaseModel, Field


class TelemetryWindow(BaseModel):
    """
    Contrato de agregación perimetral enviado formalmente al Agente Orquestador.
    """
    window_id: UUID = Field(...,
                            description="Identificador único universal del bloque analítico.")
    source_ip: str = Field(..., description="IP bajo auditoría heurística.")
    window_start_utc: datetime = Field(...,
                                       description="Timestamp de inicio de la ventana.")
    window_end_utc: datetime = Field(...,
                                     description="Timestamp de cierre de la ventana.")
    total_requests: int = Field(...,
                                description="Volumen absoluto de peticiones en el bloque.")
    unique_uris_requested: List[str] = Field(
        ..., description="Lista de rutas únicas consultadas.")
    http_methods_distribution: Dict[str, int] = Field(
        ..., description="Distribución de métodos (GET, POST).")
    response_codes_distribution: Dict[str, int] = Field(
        ..., description="Distribución de estados (200, 404, 500).")
    user_agents_observed: List[str] = Field(
        ..., description="Colección de firmas de navegadores/scanners vistos.")
    requests_per_second_avg: float = Field(
        ..., description="Frecuencia promedio de solicitudes por segundo.")

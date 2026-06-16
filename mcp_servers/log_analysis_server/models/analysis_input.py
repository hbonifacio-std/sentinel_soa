"""Módulo de definición del modelo de entrada para la herramienta de análisis MCP.

Este módulo define los esquemas de validación de datos que el servidor MCP requiere
para procesar ventanas temporales de actividad HTTP sospechosa.
"""

from datetime import datetime
from typing import Dict, List
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class WebActivityWindowInput(BaseModel):
    """Modelo Pydantic que representa los datos de telemetría agrupados para su análisis.
    
    Define formalmente los campos requeridos por la herramienta MCP `analyze_web_activity`,
    asegurando que el LLM reciba un payload estructurado con tipos estáticos garantizados.
    """

    window_id: UUID = Field(
        ...,
        description="Identificador único universal (UUID v4) de la ventana de análisis."
    )
    source_ip: str = Field(
        ...,
        description="Dirección IP de origen (IPv4 o IPv6) bajo análisis."
    )
    window_start_utc: datetime = Field(
        ...,
        description="Timestamp de inicio de la ventana temporal en formato ISO 8601 UTC."
    )
    window_end_utc: datetime = Field(
        ...,
        description="Timestamp de finalización de la ventana temporal en formato ISO 8601 UTC."
    )
    total_requests: int = Field(
        ...,
        gt=0,
        description="Número total de peticiones registradas dentro de la ventana."
    )
    unique_uris_requested: List[str] = Field(
        ...,
        description="Listado consolidado de rutas de recursos (URIs) únicas solicitadas."
    )
    http_methods_distribution: Dict[str, int] = Field(
        default_factory=dict,
        description="Distribución de frecuencias por método HTTP (e.g., {'GET': 15, 'POST': 5})."
    )
    response_codes_distribution: Dict[str, int] = Field(
        default_factory=dict,
        description="Distribución de frecuencias de códigos de respuesta HTTP (e.g., {'200': 10, '404': 10})."
    )
    user_agents_observed: List[str] = Field(
        default_factory=list,
        description="Lista de cadenas User-Agent únicas identificadas en la ventana."
    )
    requests_per_second_avg: float = Field(
        ...,
        ge=0.0,
        description="Promedio de peticiones por segundo procesadas dentro del bloque temporal."
    )

    @field_validator("window_end_utc")
    @classmethod
    def validate_chronology(cls, v: datetime, info) -> datetime:
        """Valida que la ventana temporal sea cronológicamente coherente.
        
        Args:
            v (datetime): Valor del campo window_end_utc.
            info: Objeto de contexto de validación de Pydantic.
            
        Returns:
            datetime: El timestamp de fin validado.
            
        Raises:
            ValueError: Si la fecha de fin es anterior o igual a la fecha de inicio.
        """
        start_date = info.data.get("window_start_utc")
        if start_date and v <= start_date:
            raise ValueError("window_end_utc debe ser estrictamente posterior a window_start_utc")
        return v

    model_config = {
        "json_schema_extra": {
            "example": {
                "window_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
                "source_ip": "192.168.1.50",
                "window_start_utc": "2026-06-07T16:00:00Z",
                "window_end_utc": "2026-06-07T16:01:00Z",
                "total_requests": 25,
                "unique_uris_requested": ["/admin", "/wp-login.php", "/.env"],
                "http_methods_distribution": {"GET": 20, "POST": 5},
                "response_codes_distribution": {"404": 22, "200": 3},
                "user_agents_observed": ["Mozilla/5.0", "sqlmap/1.8.2"],
                "requests_per_second_avg": 0.41
            }
        }
    }
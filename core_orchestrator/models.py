"""Módulo que define los modelos de datos Pydantic para el Core Orchestrator."""

from pydantic import BaseModel, Field
from typing import Any, Dict


class TelemetryLog(BaseModel):
    """
    Define la estructura esperada para un log de telemetría individual.

    Este modelo es utilizado por el endpoint de ingesta para validar los datos
    recibidos de fuentes externas.
    """
    source_id: str = Field(
        ...,
        description="Identificador único del servidor o aplicación que origina el log. Ej: 'web-server-prod-01'.",
        examples=["web-server-prod-01", "api-gateway-staging"]
    )
    log_data: Dict[str, Any] = Field(
        ...,
        description="El contenido del log en formato de diccionario JSON."
    )
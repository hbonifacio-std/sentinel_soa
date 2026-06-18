"""Módulo de datos perimetrales para la ingesta de telemetría.

Define el esquema estructurado de validación Pydantic para cada línea parseada 
del servidor web transmitida mediante HTTP/REST hacia el orquestador core.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator, IPvAnyAddress


class LogEvent(BaseModel):
    """Modelo Pydantic que mapea una entrada de log web sanitizada.

    Asegura tipos estáticos rígidos para la ingestión rápida en la API REST
    proveniente del daemon de recolección local.
    """
    source_id: Optional[str] = Field(
        default=None,
        description="Identificador único del servidor o aplicación que origina el log. Ej: 'web-server-prod-01'.",
        examples=["web-server-prod-01", "api-gateway-staging"]
    )

    source_ip: str = Field(
        ...,
        description="Dirección IPv4 o IPv6 de origen extraída de la telemetría."
    )
    timestamp_utc: datetime = Field(
        ...,
        description="Fecha y hora del evento normalizada en formato ISO 8601 UTC."
    )
    http_method: str = Field(
        ...,
        description="Método estándar de la petición (e.g., GET, POST, HEAD)."
    )
    request_uri: str = Field(
        ...,
        description="Ruta de acceso absoluta del recurso, incluyendo query strings."
    )
    response_code: int = Field(
        ...,
        ge=100,
        le=599,
        description="Código de estado de la respuesta HTTP devuelto por el servidor."
    )
    response_size_bytes: Optional[int] = Field(
        default=None,
        ge=0,
        description="Tamaño de la carga de respuesta en bytes. Nulo si no está disponible."
    )
    referrer: Optional[str] = Field(
        default=None,
        description="Cabecera HTTP Referer de procedencia de la consulta."
    )
    user_agent: Optional[str] = Field(
        default=None,
        description="Identificador de la aplicación cliente (User-Agent)."
    )

    @field_validator("source_ip")
    @classmethod
    def validate_ip_format(cls, v: str) -> str:
        """Valida rigurosamente que el string recibido corresponda a una IP válida.

        Usa internamente la lógica de tipado IP nativa de Pydantic para evitar 
        inyecciones o valores de red corruptos en la llave de agrupación.
        """
        try:
            # Forzamos la validación usando el tipo especializado de Pydantic
            IPvAnyAddress(v)
            return v
        except Exception as e:
            raise ValueError(
                f"La dirección IP proporcionada '{v}' no tiene un formato válido.") from e

    @field_validator("http_method")
    @classmethod
    def normalize_method(cls, v: str) -> str:
        """Normaliza los métodos HTTP a mayúsculas para evitar colisiones de distribución."""
        return v.strip().upper()

    model_config = {
        "populate_by_name": True,
        "json_schema_extra": {
            "example": {
                "source_ip": "192.168.1.105",
                "timestamp_utc": "2026-06-07T21:45:10Z",
                "http_method": "GET",
                "request_uri": "/api/v1/users?id=1",
                "response_code": 200,
                "response_size_bytes": 1024,
                "referrer": "https://google.com",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            }
        }
    }

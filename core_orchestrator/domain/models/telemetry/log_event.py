"""Perimeter data module for telemetry ingestion.

Defines the structured Pydantic validation schema for each parsed web server
log line transmitted via HTTP/REST to the core orchestrator.
"""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, field_validator, TypeAdapter
from pydantic.networks import IPvAnyAddress


class NetworkContext(BaseModel):
    """Network-layer metadata including transport parameters."""
    client_ip: str = Field(..., description="Definitive resolved client IP.")
    client_port: Optional[int] = Field(default=None, ge=0, le=65535, description="Source port of the attacker/client.")
    server_port: Optional[int] = Field(default=None, ge=0, le=65535, description="Destination port of the service.")
    proxy_forwarded_for: Optional[str] = Field(default=None)
    proxy_real_ip: Optional[str] = Field(default=None)


class HttpContext(BaseModel):
    """Granular HTTP metrics."""
    method: str
    path: str
    query: Optional[str] = Field(default=None)
    status_code: int = Field(..., ge=100, le=599)
    processing_time_ms: Optional[float] = Field(default=None, ge=0)
    content_type: Optional[str] = Field(default=None)
    user_agent: Optional[str] = Field(default=None)
    referrer: Optional[str] = Field(default=None, description="Referrer string (compat)")
    response_size_bytes: Optional[int] = Field(default=None, description="Response size in bytes (compat)")
    payload: Optional[Optional[Any]] = Field(default=None, description="Raw request/response bodies.")


class SecurityContext(BaseModel):
    """Identity tracking context."""
    authenticated_user: Optional[str] = Field(default=None)
    attempted_login_user: Optional[str] = Field(default=None)
    auth_mechanism: Optional[str] = Field(default=None)


class HostContext(BaseModel):
    """Operating System and Process level execution data."""
    pid: Optional[int] = Field(default=None, description="Process ID that handled the request.")
    process_name: Optional[str] = Field(default=None,
                                        description="Name of the runtime process (e.g., uvicorn, python).")

    process_time_ms: Optional[float] = Field(default=None, ge=0)
    environment: Optional[str] = Field(default=None, description="Deployment stage (dev, simulation, prod).")


class InfrastructureContext(BaseModel):
    """Compact infrastructure summary derived from network and host metadata."""
    environment: Optional[str] = Field(default=None, description="Deployment stage (dev, simulation, prod).")
    process_name: Optional[str] = Field(default=None, description="Runtime process name (e.g., uvicorn/gunicorn).")
    server_port: Optional[int] = Field(default=None, ge=0, le=65535, description="Service port that received the request.")
    proxy_real_ip: Optional[str] = Field(default=None, description="Real client IP reported by the reverse proxy.")
    proxy_forwarded_for: Optional[str] = Field(default=None, description="Forwarded-for chain reported by the reverse proxy.")


class LogEvent(BaseModel):
    """Comprehensive Multi-Layer Telemetry Model for AI Security Analysis."""

    # Base Core Fields
    source_id: str = Field(..., description="Unique ID of the app instance.")
    tenant_id: Optional[str] = Field(default=None, description="Tenant identifier (set server-side; client values are ignored).")
    source_ip: str = Field(..., description="Resolved IP address used for indexing.")
    timestamp_utc: datetime = Field(..., description="Normalized ISO 8601 UTC timestamp.")

    # Layered Structs
    network: Optional[NetworkContext] = Field(default=None)
    http: Optional[HttpContext] = Field(default=None)
    host: Optional[HostContext] = Field(default=None)
    infra_context: Optional[InfrastructureContext] = Field(default=None)

    # Compatibility Fields for flat log format
    extra_fields: Optional[Dict[str, Any]] = Field(default_factory=dict,
                                                   description="Catch-all dictionary for non-HTTP logs (SSH, Syslog, DB).")

    @field_validator("source_ip")  # Puedes validar ambos si quieres
    @classmethod
    def validate_ip_format(cls, v: str) -> str:
        try:
            TypeAdapter(IPvAnyAddress).validate_python(v)
            return v
        except Exception as e:
            raise ValueError(f"Invalid IP format: {v}") from e



    model_config = {
        "populate_by_name": True,
        "extra": "allow"  # Permite recibir campos extra en la raíz sin romper el parseo
    }
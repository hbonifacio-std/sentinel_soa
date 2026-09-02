"""
This module provides a structured telemetry model for AI security analysis. It
includes hierarchical data models to represent network, HTTP, security,
process, and infrastructure contexts, as well as log event aggregation.

The classes defined in this module are tailored for generating, storing, and
processing telemetry data with a strong focus on extensibility and validation.
"""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, field_validator, TypeAdapter
from pydantic.networks import IPvAnyAddress


class NetworkContextDTO(BaseModel):
    """
    Represents the network context for a connection.

    This class encapsulates information about the network context, including the
    client's IP address and ports associated with the client and server. It is
    designed to provide details about the connection's attributes, such as the
    attacker's source port or the service destination port where applicable.

    Attributes:
        client_ip: Definitive resolved client IP.
        client_port: Source port of the client/attacker. Optionally, it must be between 0 and 65,535 if provided.
        server_port: Destination port of the server/service. Optionally, it must be between 0 and 65,535 if provided.
    """
    client_ip: str = Field(..., description="Definitive resolved client IP.")
    client_port: Optional[int] = Field(default=None, ge=0, le=65535, description="Source port of the attacker/client.")
    server_port: Optional[int] = Field(default=None, ge=0, le=65535, description="Destination port of the service.")
    proxy_forwarded_for: Optional[str] = Field(default=None)
    proxy_real_ip: Optional[str] = Field(default=None)


class HttpContextDTO(BaseModel):
    """
    Represents the context of an HTTP request and response.

    This class is used to encapsulate the details of an HTTP request and its associated response.
    It includes information about the HTTP method, URL path, query parameters, status code, and
    other metadata related to the request and response lifecycle. The class is particularly useful
    for tracking, logging, and analyzing HTTP interactions.

    Attributes:
        method: HTTP method as a string (e.g., "GET", "POST").
        path: The URL path of the request.
        query: Optional query string of the URL.
        status_code: HTTP status code for the response, constrained to the range 100-599.
        processing_time_ms: Optional processing time for the request, measured in milliseconds.
        content_type: Optional content type of the response.
        user_agent: Optional user agent string of the client making the request.
        referrer: Optional referrer string, compatible with legacy referrer reporting.
        response_size_bytes: Optional size of the response in bytes.
        payload: Optional raw content of the request/response body.
    """
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


class SecurityContextDTO(BaseModel):
    """
    Represents the security context for an authentication system.

    This class is used to store and manage security-related information
    such as the currently authenticated user, the user attempting to log in,
    and the authentication mechanism being used. It acts as a container for
    these details during authentication processes and can be used to pass
    security-related context throughout the application.
    """
    authenticated_user: Optional[str] = Field(default=None)
    attempted_login_user: Optional[str] = Field(default=None)
    auth_mechanism: Optional[str] = Field(default=None)


class HostContextDTO(BaseModel):
    """
    Represents the context of the host environment for a specific request.

    This class defines attributes that capture details about the runtime
    environment and process metadata. It is typically used to provide
    contextual information about the host environment, such as the process
    ID, process name, execution time, and deployment environment.

    Attributes:
        pid: Optional[int]
            Process ID that handled the request.
        process_name: Optional[str]
            Name of the runtime process (e.g., uvicorn, python).
        process_time_ms: Optional[float]
            Time taken by the process to handle the request, in milliseconds.
            Must be greater than or equal to 0.
        environment: Optional[str]
            Deployment stage of the host environment, such as "dev",
            "simulation", or "prod".
    """
    pid: Optional[int] = Field(default=None, description="Process ID that handled the request.")
    process_name: Optional[str] = Field(default=None,
                                        description="Name of the runtime process (e.g., uvicorn, python).")

    process_time_ms: Optional[float] = Field(default=None, ge=0)
    environment: Optional[str] = Field(default=None, description="Deployment stage (dev, simulation, prod).")


class LogEventDTO(BaseModel):
    """Represents a log event with contextual and optional metadata attributes.

    This class is designed to encapsulate the details of a log event, providing
    both required and optional fields to represent various aspects of the event.
    It supports attributes for source identification, network context, HTTP context,
    host context, infrastructure context, and additional custom fields. The primary
    purpose is to standardize log data processing, handling, and indexing.

    Attributes:
        source_id (Optional[str]): Unique ID of the app instance
        client_id (Optional[str]): Tenant identifier. Ignored on the client side,
                                    set server-side
        source_ip (str): Resolved IP address used for indexing
        timestamp_utc (datetime): Normalized ISO 8601 UTC timestamp
        network (Optional[NetworkContextDTO]): Captures network-specific contextual
                                            information
        http (Optional[HttpContextDTO]): Provides HTTP-related contextual details
        host (Optional[HostContextDTO]): Describes the host-related contextual
                                      information
        extra_fields (Optional[Dict[str, Any]]): A catch-all dictionary for logs
                                                 outside HTTP (e.g., SSH, Syslog,
                                                 database logs)

    Raises:
        ValueError: If the provided value for `source_ip` is not in a valid IP
                    address format.
    """

    source_id: Optional[str] = Field(default=None, description="Unique ID of the app instance.")
    client_id: Optional[str] = Field(default=None, description="Tenant identifier (set server-side; client values are ignored).")
    source_ip: str = Field(..., description="Resolved IP address used for indexing.")
    timestamp_utc: datetime = Field(..., description="Normalized ISO 8601 UTC timestamp.")


    network: Optional[NetworkContextDTO] = Field(default=None)
    http: Optional[HttpContextDTO] = Field(default=None)
    host: Optional[HostContextDTO] = Field(default=None)

    extra_fields: Optional[Dict[str, Any]] = Field(default_factory=dict,
                                                   description="Catch-all dictionary for non-HTTP logs (SSH, Syslog, DB).")

    @field_validator("source_ip")
    @classmethod
    def validate_ip_format(cls, v: str) -> str:
        try:
            TypeAdapter(IPvAnyAddress).validate_python(v)
            return v
        except Exception as e:
            raise ValueError(f"Invalid IP format: {v}") from e



    model_config = {
        "populate_by_name": True,
        "extra": "allow"
    }
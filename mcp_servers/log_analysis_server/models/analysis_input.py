"""Input model definition module for the MCP analysis tool.

This module defines the data validation schemas that the MCP server requires
to process time windows of suspicious HTTP activity.
"""
from datetime import datetime
from typing import Dict, List, Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class SuspiciousPayloadSample(BaseModel):
    """Representa una muestra de tráfico sospechoso detectado por el backend."""
    uri: str = Field(..., description="The URI path where the suspicious payload was sent.")
    method: str = Field(..., description="HTTP Method used (POST, GET, etc.).")
    payload_preview: str = Field(..., description="Sanitized preview of the payload, query parameters, or body.")
    reason: str = Field(...,
                        description="Heuristic reason why this sample was included (e.g., 'SQLi syntax', 'Sensitive file extension').")
    status_code: str = Field("", description="HTTP status code returned for this specific sample.")
    response_size_bytes: int = Field(0, ge=0, description="Response size for this specific sample.")
    log_id: str = Field("", description="The database OID (_id) of the original raw log for drill-down purposes.")


class SecurityStateFeatures(BaseModel):
    """State features extracted from authentication/session behavior in the window."""
    compromised_accounts: List[str] = Field(
        default_factory=list,
        description="User accounts targeted with concurrent successful codes (200)."
    )
    successful_logins_count: int = Field(
        default=0,
        ge=0,
        description="Count of status code 200 on authentication checkpoints."
    )
    post_auth_internal_requests: int = Field(
        default=0,
        ge=0,
        description="Volume of internal API requests observed after valid auth signatures."
    )


class WebActivityWindowInput(BaseModel):
    """Pydantic model representing grouped telemetry data for analysis.

    Formally defines the fields required by the MCP tool `analyze_web_activity`,
    ensuring the LLM receives a structured payload with guaranteed static types.
    """

    window_id: Optional[UUID] = Field(
        default=None,
        description="Universal unique identifier (UUID v4) of the analysis window. Used for report tracking, not sent to LLM analysis."
    )
    source_id: Optional[str] = Field(
        default=None,
        description="Unique identifier of the server or application that originates the log. Used for report tracking, not sent to LLM analysis."
    )
    source_ip: str = Field(
        ...,
        description="Source IP address (IPv4 or IPv6) under analysis."
    )
    window_start_utc: datetime = Field(
        ...,
        description="Time window start timestamp in ISO 8601 UTC format."
    )
    window_end_utc: datetime = Field(
        ...,
        description="Time window end timestamp in ISO 8601 UTC format."
    )
    total_requests: int = Field(
        ...,
        gt=0,
        description="Total number of requests recorded within the window."
    )
    unique_uris_requested: List[str] = Field(
        ...,
        description="Consolidated list of unique resource paths (URIs) requested."
    )
    http_methods_distribution: Dict[str, int] = Field(
        default_factory=dict,
        description="Frequency distribution by HTTP method (e.g., {'GET': 15, 'POST': 5})."
    )
    response_codes_distribution: Dict[str, int] = Field(
        default_factory=dict,
        description="Frequency distribution of HTTP response codes (e.g., {'200': 10, '404': 10})."
    )
    user_agents_observed: List[str] = Field(
        default_factory=list,
        description="List of unique User-Agent strings identified in the window."
    )
    requests_per_second_avg: float = Field(
        ...,
        ge=0.0,
        description="Average requests per second processed within the time block."
    )

    attempted_usernames: List[str] = Field(
        default_factory=list,
        description="Distinct usernames targeted during authentication attempts in this window."
    )

    invalid_token_requests_count: int = Field(
        default=0,
        ge=0,
        description="Number of requests made to protected endpoints where authentication failed or token was invalid."
    )

    max_response_size_bytes: int = Field(
        default=0,
        ge=0,
        description="The maximum response size observed. Helps detect anomalous data exfiltration."
    )

    suspicious_samples: List[SuspiciousPayloadSample] = Field(
        default_factory=list,
        description="A list of up to 3-5 structural log samples containing suspicious characters, payloads, or target files."
    )
    critical_payload_features: List[str] = Field(
        default_factory=list,
        description="Sanitized high-signal payload fragments extracted by the backend to enrich the AI threat assessment."
    )
    infra_context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Compact infrastructure summary derived from network and host telemetry (environment, process, ports, proxy headers)."
    )
    security_state_features: SecurityStateFeatures = Field(
        default_factory=SecurityStateFeatures,
        description="State machine features detecting session compromise or multi-stage behavior."
    )

    @field_validator("window_end_utc")
    @classmethod
    def validate_chronology(cls, v: datetime, info) -> datetime:
        start_date = info.data.get("window_start_utc")
        if start_date and v <= start_date:
            raise ValueError("window_end_utc must be strictly later than window_start_utc")
        return v

    model_config = {
        "json_schema_extra": {
            "example": {
                "window_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
                "source_id": "victim-app-01",
                "source_ip": "172.18.0.3",
                "window_start_utc": "2026-06-22T20:41:34Z",
                "window_end_utc": "2026-06-22T20:45:00Z",
                "total_requests": 50,
                "unique_uris_requested": ["/auth/login", "/api/products", "/backup.zip"],
                "http_methods_distribution": {"GET": 35, "POST": 15},
                "response_codes_distribution": {"401": 12, "200": 35, "404": 3},
                "user_agents_observed": ["Mozilla/5.0", "sqlmap/1.8"],
                "requests_per_second_avg": 0.24,
                # Demostración de los nuevos campos:
                "attempted_usernames": ["alice", "admin", "' OR 'a'='a"],
                "invalid_token_requests_count": 8,
                "max_response_size_bytes": 165,
                "suspicious_samples": [
                    {
                        "uri": "/auth/login",
                        "method": "POST",
                        "payload_preview": "username=' OR 'a'='a&password=[REDACTED]",
                        "reason": "SQL Injection pattern detected in authentication payload.",
                        "status_code": "200",
                        "response_size_bytes": 165,
                        "log_id": "665fa12b3e4a1c0012abcd01"
                    },
                    {
                        "uri": "/backup.zip",
                        "method": "GET",
                        "payload_preview": "",
                        "reason": "Targeting high-risk archive/backup file extensions.",
                        "status_code": "404",
                        "response_size_bytes": 0,
                        "log_id": "665fa12b3e4a1c0012abcd02"
                    }
                ],
                "critical_payload_features": [
                    "' OR 'a'='a",
                    "UNION SELECT username,password FROM users"
                ],
                "infra_context": {
                    "environment": "simulation",
                    "process_name": "uvicorn/gunicorn",
                    "server_port": 8080,
                    "proxy_real_ip": "172.18.0.3",
                    "proxy_forwarded_for": "172.18.0.3"
                },
                "security_state_features": {
                    "compromised_accounts": ["alice"],
                    "successful_logins_count": 1,
                    "post_auth_internal_requests": 6
                }
            }
        }
    }

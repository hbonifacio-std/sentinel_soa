"""Module that defines the Pydantic data models for the Core Orchestrator."""

from pydantic import BaseModel, Field
from typing import Any, Dict


class TelemetryLog(BaseModel):
    """
    Defines the expected structure for an individual telemetry log.

    This model is used by the ingestion endpoint to validate data
    received from external sources.
    """
    source_id: str = Field(
        ...,
        description="Unique identifier of the server or application that originates the log. E.g.: 'web-server-prod-01'.",
        examples=["web-server-prod-01", "api-gateway-staging"]
    )
    log_data: Dict[str, Any] = Field(
        ...,
        description="Log content in JSON dictionary format."
    )
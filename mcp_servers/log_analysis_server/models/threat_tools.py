"""Validated contracts for Mongo-backed MCP threat intelligence tools."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class BaseWindowedQuery(BaseModel):
    """Common optional filters for telemetry/report searches."""

    source_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    source_ip: Optional[str] = Field(default=None, min_length=1, max_length=64)
    window_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    client_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    from_utc: Optional[datetime] = Field(default=None)
    to_utc: Optional[datetime] = Field(default=None)
    query_text: Optional[str] = Field(default=None, min_length=1, max_length=256)

    @field_validator("source_id", "source_ip", "window_id", "client_id", "query_text", mode="before")
    @classmethod
    def normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        return normalized

    @model_validator(mode="after")
    def validate_range(self) -> "BaseWindowedQuery":
        if self.from_utc and self.to_utc and self.from_utc > self.to_utc:
            raise ValueError("'from_utc' must be less than or equal to 'to_utc'.")
        return self


class RawTelemetryQueryInput(BaseWindowedQuery):
    """Input for retrieving raw telemetry events."""

    limit: int = Field(default=100, ge=1, le=5000)
    status_code: Optional[int] = Field(default=None, ge=100, le=599)
    http_method: Optional[str] = Field(default=None, min_length=1, max_length=16)
    path_contains: Optional[str] = Field(default=None, min_length=1, max_length=256)
    only_suspicious: bool = Field(default=False)

    @field_validator("http_method", mode="before")
    @classmethod
    def normalize_http_method(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().upper()
        if not normalized:
            return None
        return normalized


class ThreatReportQueryInput(BaseWindowedQuery):
    """Input for retrieving threat reports from reports collection."""

    limit: int = Field(default=100, ge=1, le=5000)
    threat_level: Optional[str] = Field(default=None, max_length=32)
    reviewed: Optional[bool] = Field(default=None)
    resolved: Optional[bool] = Field(default=None)
    threat_detected: Optional[bool] = Field(default=None)
    min_threat_score: Optional[int] = Field(default=None, ge=0, le=100)
    max_threat_score: Optional[int] = Field(default=None, ge=0, le=100)

    @field_validator("threat_level", mode="before")
    @classmethod
    def normalize_threat_level(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().upper()
        if not normalized:
            return None
        return normalized

    @model_validator(mode="after")
    def validate_score_range(self) -> "ThreatReportQueryInput":
        if (
            self.min_threat_score is not None
            and self.max_threat_score is not None
            and self.min_threat_score > self.max_threat_score
        ):
            raise ValueError("'min_threat_score' must be less than or equal to 'max_threat_score'.")
        return self


class SourceTimelineInput(BaseModel):
    """Input for assembling a source-specific timeline from both collections."""

    source_ip: str = Field(min_length=1, max_length=64)
    source_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    window_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    client_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    query_text: Optional[str] = Field(default=None, min_length=1, max_length=256)
    limit_raw_events: int = Field(default=120, ge=1, le=5000)
    limit_reports: int = Field(default=60, ge=1, le=2000)
    from_utc: Optional[datetime] = Field(default=None)
    to_utc: Optional[datetime] = Field(default=None)

    @field_validator("source_ip", "source_id", "window_id", "client_id", "query_text", mode="before")
    @classmethod
    def normalize_required_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        return normalized

    @model_validator(mode="after")
    def validate_range(self) -> "SourceTimelineInput":
        if self.from_utc and self.to_utc and self.from_utc > self.to_utc:
            raise ValueError("'from_utc' must be less than or equal to 'to_utc'.")
        return self


class PotentialThreatAnalysisInput(SourceTimelineInput):
    """Input for deep deterministic threat analysis based on Mongo evidence."""

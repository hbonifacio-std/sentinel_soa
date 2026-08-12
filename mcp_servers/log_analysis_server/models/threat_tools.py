"""Validated contracts for forensic MCP threat tools."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, field_validator


class ThreatDashboardSummaryInput(BaseModel):
    """Input for threat dashboard summary (macro/triage view)."""

    client_id: str = Field(min_length=1, max_length=128, description="Tenant unique ID (REQUIRED)")
    time_window_hours: int = Field(default=24, ge=1, le=720, description="Lookback period in hours")
    min_threat_level: str = Field(
        default="LOW",
        pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$",
        description="Minimum threat level filter",
    )


class WindowTelemetrySummaryInput(BaseModel):
    """Input for window telemetry statistical summary."""

    client_id: str = Field(min_length=1, max_length=128, description="Tenant unique ID (REQUIRED)")
    window_id: str = Field(min_length=1, max_length=128, description="UUID of telemetry window to summarize")


class AttackerChronologicalTimelineInput(BaseModel):
    """Input for attacker chronological timeline reconstruction."""

    client_id: str = Field(min_length=1, max_length=128, description="Tenant unique ID (REQUIRED)")
    source_ip: Optional[str] = Field(default=None, min_length=1, max_length=64, description="Attacker IP address")
    window_id: Optional[str] = Field(default=None, min_length=1, max_length=128, description="Window ID constraint")
    only_suspicious: bool = Field(
        default=True,
        description="If True, filters only flagged suspicious events",
    )
    limit: int = Field(default=30, ge=1, le=50, description="Event return cap (max 50)")

    @field_validator("source_ip", "window_id", mode="before")
    @classmethod
    def normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        return normalized


class DataExfiltrationEvidenceInput(BaseModel):
    """Input for data exfiltration evidence check."""

    client_id: str = Field(min_length=1, max_length=128, description="Tenant unique ID (REQUIRED)")
    source_ip: str = Field(min_length=1, max_length=64, description="Suspect attacker IP (REQUIRED)")
    window_id: Optional[str] = Field(default=None, min_length=1, max_length=128, description="Specific window constraint")

    @field_validator("source_ip", "window_id", mode="before")
    @classmethod
    def normalize_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        return normalized


class PivotBlastRadiusInput(BaseModel):
    """Input for pivot blast radius discovery."""

    client_id: str = Field(min_length=1, max_length=128, description="Tenant unique ID (REQUIRED)")
    source_ip: str = Field(min_length=1, max_length=64, description="IP to investigate (REQUIRED)")

    @field_validator("source_ip", mode="before")
    @classmethod
    def normalize_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        return normalized


class TimelineEvent(BaseModel):
    """Single event in attacker timeline."""

    timestamp_utc: str = Field(description="Event timestamp in UTC")
    method: Optional[str] = Field(default=None, description="HTTP method (GET, POST, etc)")
    path: Optional[str] = Field(default=None, description="HTTP path/endpoint accessed")
    status_code: Optional[int] = Field(default=None, description="HTTP response status code")
    response_size_bytes: Optional[int] = Field(default=None, description="Response size in bytes")
    user_agent: Optional[str] = Field(default=None, description="HTTP User-Agent header")


class AttackerChronologicalTimelineOutput(BaseModel):
    """Output for attacker chronological timeline."""

    timeline_events: list[TimelineEvent] = Field(description="Chronologically ordered attack events")

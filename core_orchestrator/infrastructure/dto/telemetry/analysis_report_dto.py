import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

class ReportActionRequestDTO(BaseModel):
    """
    Represents a request to perform a report action.

    This class is used to structure the information required for submitting a
    report action request. It ensures that the provided data adheres to specific
    validation rules, such as the length of the comment, and trims excess
    whitespace from string inputs.
    """

    model_config = ConfigDict(str_strip_whitespace=True)
    comment: str = Field(min_length=1, max_length=2000)

class AnalysisActionEntryDTO(BaseModel):
    comment: str
    created_at_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        alias="created_at_utc"
    )

class AnalysisReportResponseDTO(BaseModel):
    """Schema for analytics report rows shown in Alert Center."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True, from_attributes=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    threat_detected: bool = False
    source_id: str | None = None
    window_id: str | None = None
    client_id: str | None = None
    source_ip: str | None = None
    targeted_asset: str | None = None

    threat_level: str | None = None
    threat_score: float | int | None = None
    kill_chain_phase: str | None = None

    mitre_tactic: str | None = None
    mitre_tactic_id: str | None = None
    mitre_technique: str | None = None
    mitre_technique_id: str | None = None
    mitre_sub_technique: str | None = None
    mitre_sub_technique_id: str | None = None

    reasoning_summary: str | None = None
    recommendation: str | None = None
    indicators_found: list[str] = Field(default_factory=list)
    suggested_mitigations: list[dict[str, Any]] = Field(default_factory=list)

    reviewed: bool = False
    resolved: bool = False
    actions: list[AnalysisActionEntryDTO] | list[dict[str, Any]] = Field(
        default_factory=list
    )

    created_at_utc: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    resolved_at_utc: Optional[datetime] = None


class AnalysisReportsPageInfoDTO(BaseModel):
    total_records: int
    page: int
    limit: int
    next_page: str | None = None
    prev_page: str | None = None


class AnalysisReportsPageResponseDTO(BaseModel):
    info: AnalysisReportsPageInfoDTO
    results: list[AnalysisReportResponseDTO]

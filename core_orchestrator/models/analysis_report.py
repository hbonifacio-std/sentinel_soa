from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AnalysisActionEntry(BaseModel):
    comment: str
    created_at_utc: str


class AnalysisReportResponse(BaseModel):
    """Schema for analytics report rows shown in Alert Center."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: str = Field(alias="_id")
    source_id: str | None = None
    source_ip: str | None = None
    threat_level: str | None = None
    threat_score: float | int | None = None
    kill_chain_phase: str | None = None
    created_at_utc: str
    reviewed: bool = False
    resolved: bool = False
    actions: list[AnalysisActionEntry] | list[dict[str, Any]] = Field(default_factory=list)


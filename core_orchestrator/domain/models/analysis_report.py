from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class AnalysisActionEntry(BaseModel):
    comment: str
    created_at_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        alias="timestamp"
    )

class AnalysisReportResponse(BaseModel):
    """Schema for analytics report rows shown in Alert Center."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: Optional[str] = Field(default=None, alias="_id")
    source_id: str | None = None
    source_ip: str | None = None
    threat_level: str | None = None
    threat_score: float | int | None = None
    kill_chain_phase: str | None = None
    reviewed: bool = False
    resolved: bool = False
    actions: list[AnalysisActionEntry] | list[dict[str, Any]] = Field(default_factory=list)
    created_at_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    )
    resolved_at_utc: Optional[str]=None



class AnalysisReportsPageInfo(BaseModel):
    total_records: int
    page: int
    limit: int
    next_page: str | None = None
    prev_page: str | None = None


class AnalysisReportsPageResponse(BaseModel):
    info: AnalysisReportsPageInfo
    results: list[AnalysisReportResponse]

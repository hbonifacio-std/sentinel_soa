from typing import Any, Optional

from pydantic import BaseModel, Field


class ForensicQueryPlannerInput(BaseModel):
    """Validated payload for NLQ-to-Mongo forensic planning."""

    query: str = Field(..., min_length=3, max_length=400)
    source_id: str = Field(default=None, min_length=1, max_length=100)


class ForensicReportInput(BaseModel):
    """Validated payload for forensic markdown report generation."""

    query: str = Field(..., min_length=3, max_length=400)
    source_id: str = Field(default=None, min_length=1, max_length=100)
    total_matches: int = Field(default=0, ge=0)
    model_id: Optional[str] = Field(default=None, min_length=3, max_length=100)
    rows: list[dict[str, Any]] = Field(default_factory=list)
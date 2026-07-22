"""Domain models for forensic search and report generation."""

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class ForensicAnalyzeRequest(BaseModel):
    """Input payload used to run a forensic analysis query."""

    query: str = Field(..., min_length=3, max_length=1000)
    source_id: Optional[str] = Field(default=None, min_length=1, max_length=100)
    client_id: Optional[str] = Field(default=None, min_length=1, max_length=100)
    page: int = Field(default=1, ge=1)
    limit: int = Field(default=25, ge=1, le=100)
    model_id: Optional[str] = Field(
        default=None,
        description="ID del modelo a usar (de los modelos habilitados para el tenant)"
    )


class ForensicHistoryQuery(BaseModel):
    """Pagination/filter contract for forensic history listing."""

    source_id: Optional[str] = Field(default=None, min_length=1, max_length=100)
    client_id: Optional[str] = Field(default=None, min_length=1, max_length=100)
    page: int = Field(default=1, ge=1)
    limit: int = Field(default=10, ge=1, le=100)


class ForensicAnalysisRecord(BaseModel):
    """Persisted forensic report metadata and generated content."""

    analysis_id: str
    query: str
    source_id: Optional[str] = None
    client_id: Optional[str] = None
    created_at_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_matches: int = Field(default=0, ge=0)
    highlights: list[str] = Field(default_factory=list)
    markdown_report: str
    sample_results: list[dict[str, Any]] = Field(default_factory=list)
    llm_provider_used: Optional[str] = None
    llm_model_used: Optional[str] = None
    provider_source: Optional[str] = None


class ForensicHistoryResponse(BaseModel):
    """Paginated forensic analysis history response."""

    info: dict[str, Any]
    results: list[ForensicAnalysisRecord]

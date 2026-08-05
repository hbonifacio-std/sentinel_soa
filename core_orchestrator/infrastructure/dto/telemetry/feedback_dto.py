from datetime import datetime
from pydantic import BaseModel, Field


class ActionRequestDTO(BaseModel):
    comment: str = Field(..., min_length=1, max_length=2000)


class ActionEntryDTO(BaseModel):
    comment: str
    created_at_utc: datetime


class AlertWorkflowResponseDTO(BaseModel):
    report_id: str
    reviewed: bool
    resolved: bool
    actions: list[ActionEntryDTO]

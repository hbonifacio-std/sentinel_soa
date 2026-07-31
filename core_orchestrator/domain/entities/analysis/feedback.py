from datetime import datetime
from pydantic import BaseModel, Field


class ActionRequest(BaseModel):
    comment: str = Field(..., min_length=1, max_length=2000)


class ActionEntry(BaseModel):
    comment: str
    created_at_utc: datetime


class AlertWorkflowResponse(BaseModel):
    report_id: str
    reviewed: bool
    resolved: bool
    actions: list[ActionEntry]

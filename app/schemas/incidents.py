"""Validated request models for operational incident workflow."""

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.alerts import AlertStatus


class IncidentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Optional[AlertStatus] = None
    assignee_id: Optional[str] = Field(default=None, max_length=128)
    resolution_notes: Optional[str] = Field(default=None, max_length=4000)

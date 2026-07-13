"""
WarSOC Alert Management Schemas (Phase 2: Detection Engine)

Pydantic models for the interactive Alert Management System.
These enforce strict validation before any data touches MongoDB.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Union
from pydantic import BaseModel, Field
import uuid


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AlertResponse(BaseModel):
    """Read model: what the API returns to the frontend."""
    alert_id: str
    tenant_id: str
    event_id: Union[int, str]
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.NEW
    assignee_id: Optional[str] = None
    resolution_notes: Optional[str] = None
    mitre_tactic: Optional[str] = None
    summary: Optional[str] = None
    source_ip: Optional[str] = None
    user: Optional[str] = None
    message: Optional[str] = None
    timestamp: datetime


class AlertUpdate(BaseModel):
    """
    Write model: what the frontend sends to PATCH an alert.
    Only these three fields are mutable. Everything else is immutable
    forensic evidence and cannot be altered post-ingestion.
    """
    status: Optional[AlertStatus] = None
    assignee_id: Optional[str] = None
    resolution_notes: Optional[str] = None
    related_alert_ids: list[str] = Field(
        default_factory=list,
        max_length=500,
        description="Tenant-scoped members of an aggregated incident view",
    )

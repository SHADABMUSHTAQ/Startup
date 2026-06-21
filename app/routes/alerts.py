"""
WarSOC Alert Management Router (Phase 2: Detection Engine)

Endpoints for querying and managing security alerts.
All queries are strictly tenant-isolated via JWT context.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from app.database import get_db
from app.routes.auth import get_current_user
from app.schemas.alerts import AlertResponse, AlertUpdate, AlertSeverity, AlertStatus
from app.utils.limiter import limiter
from app.utils.rbac import RoleChecker
from bson import ObjectId
import json

router = APIRouter()


def _json_serializer(obj):
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def _serialize_alert(doc: dict) -> dict:
    """
    Transforms a raw MongoDB document into the shape the frontend expects.
    Handles both legacy alerts (from siem_worker) and new managed alerts.
    """
    # Normalize _id
    if "_id" in doc:
        doc["_id"] = str(doc["_id"])

    # Ensure alert_id exists (legacy alerts from siem_worker lack this field)
    if not doc.get("alert_id"):
        doc["alert_id"] = doc.get("_id") or uuid.uuid4().hex

    # Ensure status exists (legacy alerts are implicitly NEW)
    if not doc.get("status"):
        doc["status"] = AlertStatus.NEW.value

    # Normalize event_id to int (siem_worker stores as string sometimes)
    raw_eid = doc.get("event_id", 0)
    try:
        doc["event_id"] = int(raw_eid) if raw_eid else 0
    except (ValueError, TypeError):
        doc["event_id"] = 0

    # Normalize severity to uppercase enum value
    raw_sev = str(doc.get("severity", "MEDIUM")).upper()
    if raw_sev not in [s.value for s in AlertSeverity]:
        raw_sev = "MEDIUM"
    doc["severity"] = raw_sev

    # Normalize timestamp
    ts = doc.get("timestamp")
    if ts and isinstance(ts, str):
        try:
            doc["timestamp"] = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            doc["timestamp"] = datetime.now(timezone.utc)
    elif not ts:
        doc["timestamp"] = datetime.now(timezone.utc)

    # Strip internal MongoDB fields the frontend should never see
    doc.pop("_retention_ts", None)

    return doc


# ---------------------------------------------------------
# GET /alerts — Tenant-Isolated Alert Feed
# ---------------------------------------------------------
@router.get("")
@limiter.limit("30/minute")
async def get_alerts(
    request: Request,
    next_cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    event_uid: str | None = Query(None),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    status: Optional[str] = Query(None, description="Filter by status: NEW, ACKNOWLEDGED, CLOSED, FALSE_POSITIVE"),
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    role: str = Depends(RoleChecker(["Analyst", "Manager", "Admin"]))
):
    """
    Returns a paginated, tenant-isolated list of security alerts.
    The tenant_id is extracted from the authenticated user's JWT —
    it is NEVER accepted from the request body or query parameters.
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Critical: User lacks tenant assignment.")

    # Build strictly tenant-scoped query
    hot_window_start = datetime.now(timezone.utc) - timedelta(days=7)
    query = {
        "tenant_id": tenant_id,
        "$and": [
            {
                "$or": [
                    {"timestamp": {"$gte": hot_window_start}},
                    {"timestamp": {"$gte": hot_window_start.isoformat()}},
                    {"ingested_at": {"$gte": hot_window_start}},
                    {"ingested_at": {"$gte": hot_window_start.isoformat()}},
                ]
            }
        ],
    }

    if next_cursor:
        from bson import ObjectId
        from bson.errors import InvalidId
        try:
            query["_id"] = {"$lt": ObjectId(next_cursor)}
        except (InvalidId, TypeError):
            raise HTTPException(status_code=400, detail="Invalid cursor format")

    if event_uid:
        query["$and"].append({
            "$or": [
                {"event_uid": event_uid},
                {"raw_event_data.event_uid": event_uid},
                {"raw_data.event_uid": event_uid},
            ]
        })

    # Optional filters
    if severity:
        sev_upper = severity.upper()
        if sev_upper in [s.value for s in AlertSeverity]:
            query["severity"] = sev_upper

    if status:
        status_upper = status.upper()
        if status_upper in [s.value for s in AlertStatus]:
            query["status"] = status_upper

    # Count total for pagination metadata
    total = await db["security_alerts"].count_documents(query)

    # Fetch page
    cursor = db["security_alerts"].find(query).sort([("timestamp", -1), ("_id", -1)]).limit(limit)
    docs = await cursor.to_list(length=limit)

    # Serialize for frontend consumption
    alerts = [_serialize_alert(doc) for doc in docs]
    alerts = json.loads(json.dumps(alerts, default=_json_serializer))
    
    new_cursor = alerts[-1].get("_id") if alerts else None

    return {
        "data": alerts,
        "next_cursor": new_cursor,
        "limit": limit,
        "total": total,
    }


# ---------------------------------------------------------
# PATCH /alerts/{alert_id}/status — Update Alert Workflow
# ---------------------------------------------------------
@router.patch("/{alert_id}/status")
@limiter.limit("30/minute")
async def update_alert_status(
    alert_id: str,
    update: AlertUpdate,
    request: Request,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    role: str = Depends(RoleChecker(["Manager", "Admin"]))
):
    """
    Updates the workflow state of a specific alert.

    Business Rules:
    - CLOSED status requires non-empty resolution_notes (compliance mandate).
    - The update query includes tenant_id to prevent cross-tenant modification.
    - Only status, assignee_id, and resolution_notes are mutable.
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Critical: User lacks tenant assignment.")

    # BUSINESS RULE: Closing an alert demands documentation
    if update.status == AlertStatus.CLOSED:
        if not update.resolution_notes or not update.resolution_notes.strip():
            raise HTTPException(
                status_code=400,
                detail="Resolution notes are mandatory when closing an alert. "
                       "Provide a written justification for compliance records.",
            )

    # Build the $set payload from only the fields that were actually sent
    set_fields = {}
    if update.status is not None:
        set_fields["status"] = update.status.value
    if update.assignee_id is not None:
        set_fields["assignee_id"] = update.assignee_id
    if update.resolution_notes is not None:
        set_fields["resolution_notes"] = update.resolution_notes

    if not set_fields:
        raise HTTPException(status_code=400, detail="No fields provided for update.")

    # Timestamp the workflow change for audit trail
    set_fields["updated_at"] = datetime.now(timezone.utc).isoformat()
    set_fields["updated_by"] = current_user.get("username", "unknown")

    # TENANT-ISOLATED UPDATE: Both alert_id AND tenant_id must match.
    # This mathematically prevents Tenant A from modifying Tenant B's alerts.
    # We check both _id (ObjectId string) and alert_id (UUID string) for
    # backward compatibility with legacy alerts that lack alert_id.
    from bson import ObjectId

    id_filter = {"tenant_id": tenant_id}
    if ObjectId.is_valid(alert_id):
        id_filter["$or"] = [
            {"_id": ObjectId(alert_id)},
            {"alert_id": alert_id},
        ]
    else:
        id_filter["alert_id"] = alert_id

    result = await db["security_alerts"].update_one(
        id_filter,
        {"$set": set_fields},
    )

    if result.matched_count == 0:
        raise HTTPException(
            status_code=404,
            detail="Alert not found or access denied.",
        )

    return {
        "status": "success",
        "message": f"Alert {alert_id} updated successfully.",
        "updated_fields": list(set_fields.keys()),
    }

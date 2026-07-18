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
from app.utils.archive_reader import fetch_archived_documents
from app.utils.alert_incidents import aggregate_security_alerts
from app.utils.alert_context import operator_alert_document
from app.utils.security_incidents import (
    find_incident_ids_for_references,
    incident_reference_values,
)
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

    # Normalize event_id to int or preserve string (e.g. FBR-INV-DEL)
    raw_eid = doc.get("event_id", 0)
    try:
        doc["event_id"] = int(raw_eid) if raw_eid else 0
    except (ValueError, TypeError):
        doc["event_id"] = str(raw_eid) if raw_eid else 0

    # Normalize severity to uppercase enum value
    raw_sev = str(doc.get("severity", "MEDIUM")).upper()
    if raw_sev in ["INFO", "INFORMATIONAL"]:
        raw_sev = "LOW"
    elif raw_sev == "WARNING":
        raw_sev = "MEDIUM"
    elif raw_sev not in [s.value for s in AlertSeverity]:
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
    doc.pop("_expire_at", None)

    return operator_alert_document(doc)


# ---------------------------------------------------------
# GET /alerts — Tenant-Isolated Alert Feed
# ---------------------------------------------------------
@router.get("")
@limiter.limit("30/minute")
async def get_alerts(
    request: Request,
    next_cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    days: int = Query(7, ge=1, le=365),
    event_uid: str | None = Query(None),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    status: Optional[str] = Query(None, description="Filter by status: NEW, ACKNOWLEDGED, CLOSED, FALSE_POSITIVE"),
    aggregate: bool = Query(True, description="Group repeated alerts into operator incidents"),
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

    tenant = await db["tenants"].find_one({"tenant_id": tenant_id}, {"retention_days": 1})
    retention_days = int((tenant or {}).get("retention_days") or days)
    window_days = min(days, max(1, retention_days))

    # Build strictly tenant-scoped query
    hot_window_start = datetime.now(timezone.utc) - timedelta(days=window_days)
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
    raw_total = await db["security_alerts"].count_documents(query)
    total = raw_total

    # Fetch page
    cursor = db["security_alerts"].find(query).sort([("timestamp", -1), ("_id", -1)]).limit(limit)
    docs = await cursor.to_list(length=limit)
    hot_next_cursor = str(docs[-1].get("_id")) if docs else None
    archived_docs = []
    if not next_cursor:
        archived_docs, _ = await fetch_archived_documents(
            db,
            tenant_id=tenant_id,
            collections=["security_alerts"],
            start_dt=hot_window_start,
            end_dt=None,
            event_uid=event_uid,
            limit=limit,
        )
        if severity:
            archived_docs = [
                doc for doc in archived_docs
                if str(doc.get("severity", "")).upper() == severity.upper()
            ]
        if status:
            archived_docs = [
                doc for doc in archived_docs
                if str(doc.get("status", AlertStatus.NEW.value)).upper() == status.upper()
            ]
        raw_total += len(archived_docs)
        total = raw_total

    if archived_docs:
        deduped = {str(doc.get("_id")): doc for doc in [*docs, *archived_docs]}
        docs = sorted(
            deduped.values(),
            key=lambda doc: str(doc.get("timestamp") or doc.get("ingested_at") or ""),
            reverse=True,
        )[:limit]

    # Serialize for frontend consumption
    alerts = [_serialize_alert(doc) for doc in docs]
    alerts = json.loads(json.dumps(alerts, default=_json_serializer))
    if aggregate:
        alerts = aggregate_security_alerts(alerts)

    new_cursor = hot_next_cursor

    return {
        "data": alerts,
        "next_cursor": new_cursor,
        "limit": limit,
        "total": total,
        "incident_count": len(alerts),
        "raw_total": raw_total,
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

    requested_ids = [alert_id, *update.related_alert_ids]
    unique_ids = list(dict.fromkeys(value.strip() for value in requested_ids if value and value.strip()))
    id_terms = []
    for requested_id in unique_ids:
        if ObjectId.is_valid(requested_id):
            id_terms.append({"_id": ObjectId(requested_id)})
        id_terms.append({"alert_id": requested_id})

    id_filter = {"tenant_id": tenant_id, "$or": id_terms}
    matched_alerts = await db["security_alerts"].find(
        id_filter,
        {"_id": 1, "alert_id": 1, "alert_uid": 1, "event_uid": 1},
    ).to_list(length=500)
    result = await db["security_alerts"].update_many(
        id_filter,
        {"$set": set_fields},
    )

    references = incident_reference_values(matched_alerts, unique_ids)
    incident_ids = await find_incident_ids_for_references(db, tenant_id, references)
    incident_updates = dict(set_fields)
    incident_updates["updated_at"] = datetime.now(timezone.utc)
    if update.status == AlertStatus.CLOSED:
        incident_updates["closed_at"] = incident_updates["updated_at"]
    elif update.status is not None:
        incident_updates["closed_at"] = None

    incident_result = None
    if incident_ids:
        incident_result = await db.security_incidents.update_many(
            {"tenant_id": tenant_id, "incident_id": {"$in": incident_ids}},
            {"$set": incident_updates},
        )
        audit_rows = [
            {
                "tenant_id": tenant_id,
                "incident_id": incident_id,
                "action": "legacy_alert_workflow_sync",
                "changed_fields": list(incident_updates.keys()),
                "operator": set_fields["updated_by"],
                "timestamp": incident_updates["updated_at"],
            }
            for incident_id in incident_ids
        ]
        if audit_rows:
            await db.incident_audit_log.insert_many(audit_rows)

    if result.matched_count == 0 and not incident_ids:
        raise HTTPException(
            status_code=404,
            detail="Alert not found or access denied.",
        )

    return {
        "status": "success",
        "message": f"Alert {alert_id} updated successfully.",
        "updated_fields": list(set_fields.keys()),
        "updated_alerts": result.matched_count,
        "updated_incidents": incident_result.modified_count if incident_result else 0,
    }

"""Tenant-isolated operational incident APIs.

Incidents are mutable workflow records. Their referenced SIEM/FBR evidence
remains immutable and may move independently from MongoDB to Azure.
"""

from __future__ import annotations

import base64
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pymongo import ReturnDocument

from app.database import get_db
from app.routes.auth import get_current_user
from app.schemas.alerts import AlertStatus
from app.schemas.incidents import IncidentUpdate
from app.utils.alert_context import operator_alert_document
from app.utils.archive_reader import fetch_archived_documents
from app.utils.limiter import limiter
from app.utils.rbac import RoleChecker
from app.utils.security_incidents import (
    MAX_INCIDENT_EVIDENCE_REFS,
    MAX_INCIDENT_WORKFLOW_HISTORY,
    OPEN_INCIDENT_STATUSES,
    TERMINAL_INCIDENT_STATUSES,
    serialize_incident,
)


router = APIRouter()
logger = logging.getLogger(__name__)


def _json_default(value):
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _encode_cursor(document: dict) -> str:
    payload = {
        "last_seen": _json_default(document.get("last_seen")),
        "id": str(document.get("_id")),
    }
    return base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")


def _decode_cursor(value: str) -> tuple[datetime, ObjectId]:
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii")).decode("utf-8")
        payload = json.loads(raw)
        last_seen = datetime.fromisoformat(str(payload["last_seen"]).replace("Z", "+00:00"))
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        return last_seen.astimezone(timezone.utc), ObjectId(str(payload["id"]))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid incident cursor") from exc


def _without_superseded_generic(documents: list[dict]) -> list[dict]:
    specific_event_uids = {
        str(event_uid)
        for document in documents
        if document.get("interpretation_kind") != "generic"
        for event_uid in document.get("event_uids") or []
        if event_uid
    }
    return [
        document
        for document in documents
        if document.get("interpretation_kind") != "generic"
        or not specific_event_uids.intersection(
            str(event_uid) for event_uid in document.get("event_uids") or [] if event_uid
        )
    ]


def _serialize_workflow_entry(document: dict) -> dict:
    safe = {
        "audit_id": document.get("audit_id"),
        "action": document.get("action") or "workflow_update",
        "changed_fields": document.get("changed_fields") or [],
        "changes": document.get("changes") or {},
        "status": document.get("status"),
        "resolution_notes": document.get("resolution_notes"),
        "operator": document.get("operator"),
        "operator_id": document.get("operator_id"),
        "operator_role": document.get("operator_role"),
        "timestamp": document.get("timestamp"),
        "workflow_version": document.get("workflow_version"),
    }
    return json.loads(json.dumps(safe, default=_json_default))


def _workflow_action(status: AlertStatus | None, *, assignee_changed: bool) -> str:
    if status == AlertStatus.ACKNOWLEDGED:
        return "acknowledged"
    if status == AlertStatus.CLOSED:
        return "closed"
    if status == AlertStatus.FALSE_POSITIVE:
        return "marked_false_positive"
    if status == AlertStatus.NEW:
        return "reopened"
    if assignee_changed:
        return "assigned"
    return "workflow_updated"


@router.get("/summary")
@limiter.limit("60/minute")
async def get_incident_summary(
    request: Request,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "analyst"])),
):
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="User lacks tenant context")

    open_query = {
        "tenant_id": tenant_id,
        "status": {"$in": list(OPEN_INCIDENT_STATUSES)},
        "suppressed": {"$ne": True},
    }
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    open_total = await db.security_incidents.count_documents(open_query)
    critical_open = await db.security_incidents.count_documents({**open_query, "severity": "CRITICAL"})
    new_24h = await db.security_incidents.count_documents(
        {**open_query, "first_seen": {"$gte": since}}
    )
    correlation_open = await db.security_incidents.count_documents(
        {
            **open_query,
            "$or": [
                {"engine_source": {"$regex": "correlation|stateful", "$options": "i"}},
                {"rule_id": {"$regex": "correlation|spray|chain|sequence", "$options": "i"}},
            ],
        }
    )
    severity_rows = await db.security_incidents.aggregate(
        [
            {"$match": open_query},
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        ]
    ).to_list(length=10)
    severity = {str(row.get("_id") or "MEDIUM"): int(row.get("count") or 0) for row in severity_rows}
    return {
        "status": "success",
        "data": {
            "open_total": open_total,
            "critical_open": critical_open,
            "new_24h": new_24h,
            "correlation_open": correlation_open,
            "rule_match_open": max(0, open_total - correlation_open),
            "severity": severity,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
    }


@router.get("")
@limiter.limit("60/minute")
async def list_incidents(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    next_cursor: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    include_closed: bool = Query(False),
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "analyst"])),
):
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="User lacks tenant context")

    query: dict = {"tenant_id": tenant_id, "suppressed": {"$ne": True}}
    if status:
        normalized_status = status.strip().upper()
        if normalized_status not in {item.value for item in AlertStatus}:
            raise HTTPException(status_code=400, detail="Invalid incident status")
        query["status"] = normalized_status
    elif not include_closed:
        query["status"] = {"$in": list(OPEN_INCIDENT_STATUSES)}
    if severity:
        normalized_severity = severity.strip().upper()
        if normalized_severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise HTTPException(status_code=400, detail="Invalid incident severity")
        query["severity"] = normalized_severity
    if next_cursor:
        cursor_time, cursor_id = _decode_cursor(next_cursor)
        query["$or"] = [
            {"last_seen": {"$lt": cursor_time}},
            {"last_seen": cursor_time, "_id": {"$lt": cursor_id}},
        ]

    # Fetch a bounded surplus because generic interpretations may be removed
    # when a specific finding references the same immutable event UID.
    documents = await (
        db.security_incidents.find(query)
        .sort([("last_seen", -1), ("_id", -1)])
        .limit(min(1000, limit * 2 + 1))
        .to_list(length=min(1000, limit * 2 + 1))
    )
    visible = _without_superseded_generic(documents)
    has_more = len(visible) > limit
    visible = visible[:limit]
    return {
        "status": "success",
        "data": [serialize_incident(document) for document in visible],
        "next_cursor": _encode_cursor(visible[-1]) if has_more and visible else None,
        "returned": len(visible),
        "has_more": has_more,
    }


@router.get("/assignees")
@limiter.limit("30/minute")
async def list_incident_assignees(
    request: Request,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager"])),
):
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="User lacks tenant context")

    cursor = db.users.find(
        {
            "tenant_id": tenant_id,
            "status": {"$ne": "pending"},
            "role": {"$in": ["admin", "manager", "analyst"]},
        },
        {"_id": 1, "username": 1, "email": 1, "full_name": 1, "role": 1},
    ).sort([("role", 1), ("full_name", 1), ("username", 1)])
    assignees = []
    async for member in cursor:
        assignees.append(
            {
                "id": str(member["_id"]),
                "username": member.get("username"),
                "email": member.get("email"),
                "full_name": member.get("full_name"),
                "role": member.get("role"),
            }
        )
    return {"status": "success", "data": assignees}


@router.get("/{incident_id}")
@limiter.limit("60/minute")
async def get_incident_detail(
    incident_id: str,
    request: Request,
    evidence_limit: int = Query(50, ge=1, le=100),
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "analyst"])),
):
    tenant_id = current_user.get("tenant_id")
    incident = await db.security_incidents.find_one(
        {"tenant_id": tenant_id, "incident_id": incident_id}
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    evidence_refs = incident.get("evidence_refs") or []
    alert_uids = list(dict.fromkeys(incident.get("alert_uids") or []))[-evidence_limit:]
    event_uids = list(dict.fromkeys(incident.get("event_uids") or []))[-evidence_limit:]
    object_ids = []
    for reference in evidence_refs[-evidence_limit:]:
        document_id = str(reference.get("document_id") or "")
        if ObjectId.is_valid(document_id):
            object_ids.append(ObjectId(document_id))

    terms = []
    if alert_uids:
        terms.append({"alert_uid": {"$in": alert_uids}})
    if event_uids:
        terms.append({"event_uid": {"$in": event_uids}})
    if object_ids:
        terms.append({"_id": {"$in": object_ids}})
    hot_docs = []
    if terms:
        hot_docs = await db.security_alerts.find(
            {"tenant_id": tenant_id, "$or": terms}
        ).sort("timestamp", -1).limit(evidence_limit).to_list(length=evidence_limit)

    hot_event_uids = {str(document.get("event_uid")) for document in hot_docs if document.get("event_uid")}
    missing_event_uids = [value for value in event_uids if value not in hot_event_uids]
    archived_docs = []
    if missing_event_uids:
        archived_docs, _ = await fetch_archived_documents(
            db,
            tenant_id=tenant_id,
            collections=["security_alerts"],
            event_uids=missing_event_uids,
            limit=evidence_limit,
        )

    evidence = []
    seen = set()
    for document in [*hot_docs, *archived_docs]:
        identity = str(document.get("alert_uid") or document.get("event_uid") or document.get("_id"))
        if identity in seen:
            continue
        seen.add(identity)
        safe = operator_alert_document(document)
        safe["storage_tier"] = "cold_archive" if document.get("_archived") else "hot"
        safe.pop("_archive_blob_name", None)
        evidence.append(json.loads(json.dumps(safe, default=_json_default)))
        if len(evidence) >= evidence_limit:
            break

    embedded_history = incident.get("workflow_history") or []
    external_history = await (
        db.incident_audit_log.find(
            {"tenant_id": tenant_id, "incident_id": incident_id},
            {"_id": 0, "tenant_id": 0, "incident_id": 0},
        )
        .sort("timestamp", -1)
        .limit(MAX_INCIDENT_WORKFLOW_HISTORY)
        .to_list(length=MAX_INCIDENT_WORKFLOW_HISTORY)
    )
    history_by_key: dict[str, dict] = {}
    for entry in [*embedded_history, *external_history]:
        key = str(
            entry.get("audit_id")
            or f"{entry.get('timestamp')}:{entry.get('operator')}:{entry.get('action')}"
        )
        history_by_key[key] = entry
    workflow_history = sorted(
        (_serialize_workflow_entry(entry) for entry in history_by_key.values()),
        key=lambda entry: str(entry.get("timestamp") or ""),
    )[-MAX_INCIDENT_WORKFLOW_HISTORY:]

    assignee = None
    if incident.get("assignee_id") and ObjectId.is_valid(str(incident.get("assignee_id"))):
        assignee_doc = await db.users.find_one(
            {"tenant_id": tenant_id, "_id": ObjectId(str(incident["assignee_id"]))},
            {"_id": 1, "username": 1, "email": 1, "full_name": 1, "role": 1},
        )
        if assignee_doc:
            assignee = {
                "id": str(assignee_doc["_id"]),
                "username": assignee_doc.get("username"),
                "email": assignee_doc.get("email"),
                "full_name": assignee_doc.get("full_name"),
                "role": assignee_doc.get("role"),
            }

    visible_occurrences = incident.get("visible_occurrences")
    occurrence_total = int(
        visible_occurrences
        if visible_occurrences is not None
        else incident.get("occurrences") or 0
    )
    reference_total = len(evidence_refs)
    hot_count = sum(1 for row in evidence if row.get("storage_tier") == "hot")
    cold_count = sum(1 for row in evidence if row.get("storage_tier") == "cold_archive")

    return {
        "status": "success",
        "data": {
            "incident": serialize_incident(incident),
            "evidence": evidence,
            "evidence_returned": len(evidence),
            "evidence_total": occurrence_total,
            "evidence_truncated": occurrence_total > len(evidence),
            "evidence_coverage": {
                "occurrence_total": occurrence_total,
                "reference_total": reference_total,
                "returned": len(evidence),
                "hot": hot_count,
                "cold_archive": cold_count,
                "unresolved_references": max(0, reference_total - len(evidence)),
                "tracking_bounded": occurrence_total > reference_total,
                "tracking_limit": MAX_INCIDENT_EVIDENCE_REFS,
                "preview_limit": evidence_limit,
            },
            "assignee": assignee,
            "workflow_history": workflow_history,
            "workflow_history_truncated": len(history_by_key) > len(workflow_history),
        },
    }


@router.patch("/{incident_id}/status")
@limiter.limit("30/minute")
async def update_incident_status(
    incident_id: str,
    update: IncidentUpdate,
    request: Request,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager"])),
):
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="User lacks tenant context")
    if update.status in {AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE} and not (
        update.resolution_notes or ""
    ).strip():
        raise HTTPException(
            status_code=400,
            detail="Resolution notes are required when closing or marking an incident false positive",
        )

    previous = await db.security_incidents.find_one(
        {"tenant_id": tenant_id, "incident_id": incident_id}
    )
    if not previous:
        raise HTTPException(status_code=404, detail="Incident not found")

    set_fields = {}
    if update.status is not None:
        set_fields["status"] = update.status.value
    if update.resolution_notes is not None:
        set_fields["resolution_notes"] = update.resolution_notes.strip()
    if "assignee_id" in update.model_fields_set and update.assignee_id is None:
        set_fields["assignee_id"] = None
    elif update.assignee_id is not None:
        assignee_query = {
            "tenant_id": tenant_id,
            "status": {"$ne": "pending"},
            "role": {"$in": ["admin", "manager", "analyst"]},
        }
        if ObjectId.is_valid(update.assignee_id):
            assignee_query["_id"] = ObjectId(update.assignee_id)
        else:
            assignee_query["$or"] = [
                {"username": update.assignee_id},
                {"email": update.assignee_id},
            ]
        assignee = await db.users.find_one(assignee_query, {"_id": 1})
        if not assignee:
            raise HTTPException(status_code=400, detail="Assignee is not an active member of this tenant")
        set_fields["assignee_id"] = str(assignee["_id"])
    if not set_fields:
        raise HTTPException(status_code=400, detail="No incident fields provided")

    mutable_fields = {
        key: value
        for key, value in set_fields.items()
        if key in {"status", "resolution_notes", "assignee_id"}
    }
    changes = {
        key: {"from": previous.get(key), "to": value}
        for key, value in mutable_fields.items()
        if previous.get(key) != value
    }
    if not changes:
        return {"status": "success", "data": serialize_incident(previous)}

    now = datetime.now(timezone.utc)
    set_fields["updated_at"] = now
    set_fields["updated_by"] = current_user.get("username") or current_user.get("email") or "unknown"
    if update.status is not None and update.status.value in TERMINAL_INCIDENT_STATUSES:
        set_fields["closed_at"] = now
    elif update.status is not None:
        set_fields["closed_at"] = None

    previous_workflow_version = previous.get("workflow_version")
    next_workflow_version = int(previous_workflow_version or 0) + 1
    audit_entry = {
        "audit_id": f"AUD-{uuid.uuid4().hex.upper()}",
        "action": _workflow_action(
            update.status,
            assignee_changed="assignee_id" in changes,
        ),
        "changed_fields": list(changes.keys()),
        "changes": changes,
        "status": set_fields.get("status", previous.get("status")),
        "resolution_notes": set_fields.get("resolution_notes", previous.get("resolution_notes")),
        "operator": set_fields["updated_by"],
        "operator_id": str(current_user.get("_id") or current_user.get("id") or ""),
        "operator_role": current_user.get("role"),
        "timestamp": now,
        "workflow_version": next_workflow_version,
    }

    version_filter = (
        {"workflow_version": {"$exists": False}}
        if previous_workflow_version is None
        else {"workflow_version": previous_workflow_version}
    )
    incident = await db.security_incidents.find_one_and_update(
        {
            "tenant_id": tenant_id,
            "incident_id": incident_id,
            **version_filter,
        },
        {
            "$set": set_fields,
            "$inc": {"workflow_version": 1},
            "$push": {
                "workflow_history": {
                    "$each": [audit_entry],
                    "$slice": -MAX_INCIDENT_WORKFLOW_HISTORY,
                }
            },
        },
        return_document=ReturnDocument.AFTER,
    )
    if not incident:
        raise HTTPException(
            status_code=409,
            detail="Incident workflow changed; refresh and retry",
        )

    try:
        await db.incident_audit_log.insert_one(
            {
                **audit_entry,
                "tenant_id": tenant_id,
                "incident_id": incident_id,
            }
        )
    except Exception:
        # Workflow state and its bounded audit entry were committed atomically
        # on the incident. The separate audit collection is a query replica.
        logger.exception("Incident %s audit replica write failed", incident_id)

    alert_uids = list(dict.fromkeys(incident.get("alert_uids") or []))
    hot_set = {
        key: value
        for key, value in set_fields.items()
        if key in {"status", "resolution_notes", "assignee_id", "updated_at", "updated_by"}
    }
    if alert_uids and hot_set:
        try:
            await db.security_alerts.update_many(
                {"tenant_id": tenant_id, "alert_uid": {"$in": alert_uids}},
                {"$set": hot_set},
            )
        except Exception:
            # The incident is authoritative workflow state. Alert fields are a
            # temporary compatibility mirror while hot evidence remains in Mongo.
            logger.exception("Incident %s legacy alert mirror failed", incident_id)

    redis_client = getattr(request.app.state, "redis", None)
    if redis_client is not None:
        try:
            await redis_client.publish(
                "security_incidents",
                json.dumps(
                    {
                        "type": "incident.updated",
                        "tenant_id": tenant_id,
                        "incident": serialize_incident(incident),
                    },
                    default=str,
                ),
            )
        except Exception:
            logger.exception(
                "Incident %s was updated, but its live notification could not be published",
                incident_id,
            )
    return {"status": "success", "data": serialize_incident(incident)}

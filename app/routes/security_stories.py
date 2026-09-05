"""Tenant-scoped operator API for bounded WarSOC Security Story projections."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.config.config import get_settings
from app.database import get_db
from app.routes.auth import get_current_user
from app.schemas.security_stories import SecurityStoryUpdate
from app.utils.limiter import limiter
from app.utils.rbac import RoleChecker
from app.utils.security_stories import VISIBLE_STORY_STATUSES, serialize_security_story


router = APIRouter()


def _tenant_id(current_user: dict) -> str:
    tenant_id = str(current_user.get("tenant_id") or "").strip()
    if not tenant_id:
        raise HTTPException(status_code=403, detail="User lacks tenant context")
    return tenant_id


def _require_enabled() -> None:
    if not get_settings().security_stories_enabled:
        raise HTTPException(status_code=404, detail="Security Stories are not enabled")


def _encode_cursor(document: dict) -> str:
    value = {
        "last_seen": str(document.get("last_seen") or ""),
        "id": str(document.get("_id") or ""),
    }
    return base64.urlsafe_b64encode(json.dumps(value).encode("utf-8")).decode("ascii")


def _decode_cursor(value: str) -> tuple[datetime, ObjectId]:
    try:
        payload = json.loads(
            base64.urlsafe_b64decode(value.encode("ascii")).decode("utf-8")
        )
        seen_at = datetime.fromisoformat(str(payload["last_seen"]).replace("Z", "+00:00"))
        if seen_at.tzinfo is None:
            seen_at = seen_at.replace(tzinfo=timezone.utc)
        return seen_at.astimezone(timezone.utc), ObjectId(str(payload["id"]))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid Security Story cursor") from exc


@router.get("/status")
@limiter.limit("60/minute")
async def get_security_story_status(
    request: Request,
    current_user: dict = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "analyst"])),
):
    _tenant_id(current_user)
    settings = get_settings()
    return {
        "status": "success",
        "data": {
            "enabled": settings.security_stories_enabled,
            "detection_source": "WarSOC",
            "schema_version": "warsoc-security-story-v1",
            "medium_confidence_mode": "CANDIDATE",
            "wazuh_candidate_policy": "SHADOW_NOT_ACTIONABLE",
        },
    }


@router.get("/summary")
@limiter.limit("60/minute")
async def get_security_story_summary(
    request: Request,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "analyst"])),
):
    _require_enabled()
    tenant_id = _tenant_id(current_user)
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    rows = await db.security_stories.aggregate(
        [
            {"$match": {"tenant_id": tenant_id}},
            {
                "$facet": {
                    "open_total": [
                        {"$match": {"status": {"$in": ["OPEN", "ACKNOWLEDGED"]}}},
                        {"$count": "value"},
                    ],
                    "candidate_total": [
                        {"$match": {"status": "CANDIDATE"}},
                        {"$count": "value"},
                    ],
                    "urgent_open": [
                        {
                            "$match": {
                                "status": {"$in": ["OPEN", "ACKNOWLEDGED"]},
                                "attention_priority": "URGENT",
                            }
                        },
                        {"$count": "value"},
                    ],
                    "new_24h": [
                        {"$match": {"first_seen": {"$gte": since}}},
                        {"$count": "value"},
                    ],
                    "by_priority": [
                        {"$match": {"status": {"$in": ["OPEN", "ACKNOWLEDGED"]}}},
                        {"$group": {"_id": "$attention_priority", "count": {"$sum": 1}}},
                    ],
                    "by_type": [
                        {"$match": {"status": {"$in": ["OPEN", "ACKNOWLEDGED"]}}},
                        {"$group": {"_id": "$story_type", "count": {"$sum": 1}}},
                    ],
                }
            },
        ]
    ).to_list(length=1)
    facets = rows[0] if rows else {}

    def count(name: str) -> int:
        values = facets.get(name) or []
        return int(values[0].get("value") or 0) if values else 0

    return {
        "status": "success",
        "data": {
            "open_total": count("open_total"),
            "candidate_total": count("candidate_total"),
            "urgent_open": count("urgent_open"),
            "new_24h": count("new_24h"),
            "by_priority": {
                str(row.get("_id") or "UNKNOWN"): int(row.get("count") or 0)
                for row in facets.get("by_priority") or []
            },
            "by_type": {
                str(row.get("_id") or "UNKNOWN"): int(row.get("count") or 0)
                for row in facets.get("by_type") or []
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
    }


@router.get("")
@limiter.limit("60/minute")
async def list_security_stories(
    request: Request,
    limit: int = Query(100, ge=1, le=250),
    next_cursor: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    attention_priority: Optional[str] = Query(None),
    story_type: Optional[str] = Query(None, min_length=3, max_length=80),
    asset_id: Optional[str] = Query(None, min_length=3, max_length=128),
    include_candidates: bool = Query(False),
    include_closed: bool = Query(False),
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "analyst"])),
):
    _require_enabled()
    tenant_id = _tenant_id(current_user)
    query: dict = {"tenant_id": tenant_id}
    if status:
        normalized_status = status.strip().upper()
        if normalized_status not in VISIBLE_STORY_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid Security Story status")
        query["status"] = normalized_status
    else:
        visible = ["OPEN", "ACKNOWLEDGED"]
        if include_candidates:
            visible.insert(0, "CANDIDATE")
        if include_closed:
            visible.append("CLOSED")
        query["status"] = {"$in": visible}
    if attention_priority:
        priority = attention_priority.strip().upper()
        if priority not in {"LOW", "MEDIUM", "HIGH", "URGENT"}:
            raise HTTPException(status_code=400, detail="Invalid attention priority")
        query["attention_priority"] = priority
    if story_type:
        query["story_type"] = story_type.strip().upper()
    if asset_id:
        query["affected_asset_ids"] = asset_id.strip()
    if next_cursor:
        cursor_time, cursor_id = _decode_cursor(next_cursor)
        query["$or"] = [
            {"last_seen": {"$lt": cursor_time}},
            {"last_seen": cursor_time, "_id": {"$lt": cursor_id}},
        ]

    documents = await (
        db.security_stories.find(query)
        .sort([("last_seen", -1), ("_id", -1)])
        .limit(limit + 1)
        .to_list(length=limit + 1)
    )
    has_more = len(documents) > limit
    visible = documents[:limit]
    return {
        "status": "success",
        "data": [serialize_security_story(document) for document in visible],
        "next_cursor": _encode_cursor(visible[-1]) if has_more and visible else None,
        "returned": len(visible),
        "has_more": has_more,
    }


@router.get("/{story_id}")
@limiter.limit("60/minute")
async def get_security_story(
    story_id: str,
    request: Request,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "analyst"])),
):
    _require_enabled()
    tenant_id = _tenant_id(current_user)
    document = await db.security_stories.find_one(
        {"tenant_id": tenant_id, "story_id": story_id}
    )
    if not document:
        raise HTTPException(status_code=404, detail="Security Story was not found")
    return {"status": "success", "data": serialize_security_story(document, detail=True)}


@router.patch("/{story_id}/status")
@limiter.limit("30/minute")
async def update_security_story_status(
    story_id: str,
    body: SecurityStoryUpdate,
    request: Request,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager"])),
):
    _require_enabled()
    tenant_id = _tenant_id(current_user)
    current = await db.security_stories.find_one(
        {"tenant_id": tenant_id, "story_id": story_id}
    )
    if not current:
        raise HTTPException(status_code=404, detail="Security Story was not found")
    if int(current.get("version") or 1) != body.expected_version:
        raise HTTPException(status_code=409, detail="Security Story changed; refresh and retry")

    now = datetime.now(timezone.utc)
    operator = str(current_user.get("email") or current_user.get("username") or "operator")[:200]
    entry = {
        "audit_id": f"STORY-AUDIT-{uuid.uuid4().hex.upper()}",
        "action": body.status.lower(),
        "from_status": current.get("status"),
        "to_status": body.status,
        "notes": body.notes,
        "operator": operator,
        "operator_id": str(current_user.get("_id") or "") or None,
        "operator_role": str(current_user.get("role") or "").lower(),
        "timestamp": now,
        "version": body.expected_version + 1,
    }
    result = await db.security_stories.update_one(
        {
            "_id": current["_id"],
            "tenant_id": tenant_id,
            "version": body.expected_version,
        },
        {
            "$set": {
                "status": body.status,
                "updated_at": now,
                "updated_by": operator,
                "has_new_activity": False,
            },
            "$inc": {"version": 1},
            "$push": {"workflow_history": {"$each": [entry], "$slice": -50}},
        },
    )
    if result.modified_count != 1:
        raise HTTPException(status_code=409, detail="Security Story changed; refresh and retry")
    updated = await db.security_stories.find_one({"_id": current["_id"]})
    return {"status": "success", "data": serialize_security_story(updated, detail=True)}

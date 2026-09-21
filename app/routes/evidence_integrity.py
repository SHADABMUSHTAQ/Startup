from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.database import get_db
from app.routes.auth import get_current_user
from app.routes.evidence_cases import CASE_EVIDENCE_COLLECTIONS
from app.utils.compliance_chain import (
    CASE_EVIDENCE_DIGEST_VERSION,
    case_evidence_record_digest,
    evidence_record_digest,
    verify_ledger_sequence,
)
from app.utils.evidence_custody import verify_custody_chain
from app.utils.limiter import limiter
from app.utils.rbac import RoleChecker

router = APIRouter(
    tags=["compliance"],
)

logger = logging.getLogger(__name__)


@router.get("/verify/daily-ledger")
@limiter.limit("10/minute")
async def verify_daily_ledger(
    request: Request,
    start_date: str = Query(..., description="Start date (YYYY-MM-DD)"),
    end_date: str = Query(..., description="End date (YYYY-MM-DD)"),
    current_user: dict[str, Any] = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "auditor"])),
    db: Any = Depends(get_db),
):
    try:
        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD.")

    if (end_dt - start_dt).days > 366:
        raise HTTPException(status_code=400, detail="Date range must be <= 366 days.")
    if start_dt > end_dt:
        raise HTTPException(status_code=400, detail="start_date must be before end_date.")

    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Tenant ID not found in token.")

    cursor = db.daily_forensic_ledgers.find(
        {"tenant_id": tenant_id, "date": {"$gte": start_date, "$lte": end_date}}
    ).sort("date", 1)

    entries = await cursor.to_list(length=367)

    verify_result = verify_ledger_sequence(entries)
    if not entries:
        verify_result["status"] = "NO_LEDGER_ENTRIES"

    return {
        "date_range": {"start_date": start_date, "end_date": end_date},
        "verification_scope": "stored_daily_ledger_chain",
        "claim_boundary": (
            "Validates stored daily commitments and chain continuity. It does not "
            "rehash raw evidence that has already moved to the archive."
        ),
        "verification_result": verify_result,
    }


@router.get("/verify/case/{case_id}")
@limiter.limit("10/minute")
async def verify_case(
    request: Request,
    case_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "auditor"])),
    db: Any = Depends(get_db),
):
    if not re.match(r"^[A-Za-z0-9_.-]{3,100}$", case_id):
        raise HTTPException(status_code=400, detail="Invalid case_id format.")

    tenant_id = str(current_user.get("tenant_id") or "")
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Tenant ID not found in token.")

    case = await db.evidence_cases.find_one({"tenant_id": tenant_id, "case_id": case_id})
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    events_cursor = db.evidence_custody_events.find(
        {"tenant_id": tenant_id, "case_id": case_id, "state": "COMMITTED"}
    ).sort("sequence", 1)
    events = await events_cursor.to_list(10000)

    chain_result = verify_custody_chain(events)

    items_cursor = db.evidence_case_items.find(
        {"tenant_id": tenant_id, "case_id": case_id, "state": "COMMITTED"}
    ).sort("added_at", 1)
    committed_items = await items_cursor.to_list(5000)

    item_results = []
    overall_status = "VERIFIED"

    for item in committed_items:
        collection_name = item.get("collection")
        doc_id = item.get("document_id")
        event_uid = item.get("event_uid")

        if collection_name not in CASE_EVIDENCE_COLLECTIONS:
            overall_status = "INTEGRITY_VIOLATION"
            item_results.append({
                "case_item_id": str(item.get("case_item_id") or item.get("_id") or ""),
                "collection": collection_name,
                "hash_match": None,
                "status": "UNSUPPORTED_COLLECTION",
            })
            continue

        query: dict[str, Any] = {"tenant_id": tenant_id}
        if doc_id:
            try:
                query["_id"] = ObjectId(doc_id)
            except Exception:
                query["_id"] = doc_id
        elif event_uid:
            query["event_uid"] = event_uid
        else:
            overall_status = "INTEGRITY_VIOLATION"
            item_results.append({
                "case_item_id": str(item.get("case_item_id") or item.get("_id") or ""),
                "collection": collection_name,
                "hash_match": None,
                "status": "INVALID_REFERENCE",
            })
            continue

        doc = await db[str(collection_name)].find_one(query)

        status = "VERIFIED"
        hash_match: bool | None = False
        archive_reference = None
        if not doc:
            archive = None
            if event_uid:
                archive = await db.storage_archives.find_one(
                    {
                        "tenant_id": tenant_id,
                        "collection": collection_name,
                        "event_uids": event_uid,
                        "status": "archived",
                    },
                    {
                        "_id": 1,
                        "archive_key": 1,
                        "readback_verified": 1,
                        "physical_worm_verified": 1,
                    },
                )
            hash_match = None
            if archive:
                status = "ARCHIVED_LEDGER_PRESENT_NOT_REHASHED"
                archive_reference = {
                    "archive_id": str(archive.get("_id") or ""),
                    "archive_key": archive.get("archive_key"),
                    "readback_verified": bool(archive.get("readback_verified")),
                    "physical_worm_verified": bool(
                        archive.get("physical_worm_verified")
                    ),
                }
            else:
                status = "HOT_EVIDENCE_UNAVAILABLE"
            if overall_status == "VERIFIED":
                overall_status = "PARTIALLY_VERIFIED"
        else:
            if item.get("evidence_hash_version") == CASE_EVIDENCE_DIGEST_VERSION:
                computed_digest = case_evidence_record_digest(
                    str(collection_name), doc
                )
            else:
                computed_digest = evidence_record_digest(str(collection_name), doc)
            stored_hash = item.get("evidence_record_hash")

            if computed_digest == stored_hash:
                hash_match = True
            else:
                status = "HASH_MISMATCH"
                overall_status = "INTEGRITY_VIOLATION"

        item_results.append({
            "case_item_id": str(item.get("case_item_id") or item.get("_id") or ""),
            "collection": collection_name,
            "hash_match": hash_match,
            "status": status,
            "archive_reference": archive_reference,
        })

    if not chain_result.get("verified", False) or chain_result.get("head_hash") != case.get("custody_head_hash"):
        overall_status = "INTEGRITY_VIOLATION"

    return {
        "case_id": case_id,
        "verification_scope": "custody_chain_and_available_evidence",
        "claim_boundary": (
            "Hot evidence is rehashed. Archived evidence is reported from the archive "
            "ledger and requires an explicit restore for content re-verification."
        ),
        "custody_chain": chain_result,
        "evidence_items": item_results,
        "overall_status": overall_status,
    }


@router.get("/report/custody/{case_id}")
@limiter.limit("10/minute")
async def report_custody(
    request: Request,
    case_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "auditor"])),
    db: Any = Depends(get_db),
):
    if not re.match(r"^[A-Za-z0-9_.-]{3,100}$", case_id):
        raise HTTPException(status_code=400, detail="Invalid case_id format.")

    tenant_id = str(current_user.get("tenant_id") or "")
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Tenant ID not found in token.")

    case = await db.evidence_cases.find_one({"tenant_id": tenant_id, "case_id": case_id})
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    events_cursor = db.evidence_custody_events.find(
        {"tenant_id": tenant_id, "case_id": case_id, "state": "COMMITTED"}
    ).sort("sequence", 1)
    events = await events_cursor.to_list(10000)

    chain_verification = verify_custody_chain(events)

    return {
        "report_type": "WARSOC_CHAIN_OF_CUSTODY_SUPPORT",
        "report_version": "warsoc-custody-report-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id,
        "case_title": case.get("title", ""),
        "case_status": case.get("status", ""),
        "tenant_id": tenant_id,
        "custody_head_hash": case.get("custody_head_hash"),
        "claim_boundary": (
            "Technical custody and integrity support only. Legal admissibility depends "
            "on applicable law, collection procedure, and independent review."
        ),
        "total_events": len(events),
        "chain_verification": chain_verification,
        "timeline": [
            {
                "sequence": event.get("sequence"),
                "custody_event_id": event.get("custody_event_id"),
                "action": event.get("action"),
                "actor_email": event.get("actor_email", ""),
                "actor_role": event.get("actor_role", ""),
                "reason": event.get("reason", ""),
                "occurred_at": (
                    event["occurred_at"].isoformat()
                    if hasattr(event.get("occurred_at"), "isoformat")
                    else str(event.get("occurred_at", ""))
                ),
                "custody_hash": event.get("current_custody_hash", ""),
                "previous_hash": event.get("previous_custody_hash", ""),
                "metadata": event.get("metadata", {}),
            }
            for event in events
        ],
    }

"""Hash-linked evidence custody operations."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import date, datetime, timezone
from typing import Any

from pymongo import ReturnDocument


CUSTODY_CHAIN_VERSION = "warsoc-custody-sha256-v1"


def _mongo_utc_now() -> datetime:
    now = datetime.now(timezone.utc)
    return now.replace(microsecond=(now.microsecond // 1000) * 1000)


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        normalized = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return normalized.astimezone(timezone.utc).isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def custody_event_hash(event: dict) -> str:
    signable = {
        key: value
        for key, value in event.items()
        if key not in {"_id", "current_custody_hash", "state", "committed_at"}
    }
    return hashlib.sha256(canonical_bytes(signable)).hexdigest()


async def append_custody_event(
    db,
    *,
    tenant_id: str,
    case_id: str,
    action: str,
    actor: dict,
    reason: str,
    request_id: str,
    case_item_id: str | None = None,
    metadata: dict | None = None,
) -> dict:
    """Append one custody event using a recoverable compare-and-set transition."""

    for _ in range(5):
        case = await db.evidence_cases.find_one(
            {"tenant_id": tenant_id, "case_id": case_id},
            {
                "custody_sequence": 1,
                "custody_head_hash": 1,
                "custody_pending_event_id": 1,
            },
        )
        if not case:
            raise ValueError("Evidence case was not found")
        if case.get("custody_pending_event_id"):
            await recover_pending_custody_event(db, case)
            continue
        previous_sequence = int(case.get("custody_sequence") or 0)
        previous_hash = str(case.get("custody_head_hash") or "0" * 64)
        occurred_at = _mongo_utc_now()
        event = {
            "custody_event_id": f"CUSTODY-{uuid.uuid4().hex.upper()}",
            "chain_version": CUSTODY_CHAIN_VERSION,
            "tenant_id": tenant_id,
            "case_id": case_id,
            "case_item_id": case_item_id,
            "sequence": previous_sequence + 1,
            "action": action,
            "actor_user_id": str(actor.get("_id") or ""),
            "actor_email": str(actor.get("email") or actor.get("username") or ""),
            "actor_role": str(actor.get("role") or ""),
            "reason": reason,
            "request_id": request_id,
            "metadata": dict(metadata or {}),
            "occurred_at": occurred_at,
            "previous_custody_hash": previous_hash,
        }
        event["current_custody_hash"] = custody_event_hash(event)
        event["state"] = "PENDING"
        await db.evidence_custody_events.insert_one(event)

        updated = await db.evidence_cases.find_one_and_update(
            {
                "_id": case["_id"],
                "custody_sequence": previous_sequence,
                "custody_head_hash": previous_hash,
                "$or": [
                    {"custody_pending_event_id": {"$exists": False}},
                    {"custody_pending_event_id": None},
                ],
            },
            {
                "$set": {
                    "custody_sequence": event["sequence"],
                    "custody_head_hash": event["current_custody_hash"],
                    "custody_pending_event_id": event["custody_event_id"],
                    "updated_at": occurred_at,
                }
            },
            return_document=ReturnDocument.AFTER,
        )
        if updated:
            await db.evidence_custody_events.update_one(
                {"custody_event_id": event["custody_event_id"], "state": "PENDING"},
                {"$set": {"state": "COMMITTED", "committed_at": datetime.now(timezone.utc)}},
            )
            await db.evidence_cases.update_one(
                {
                    "_id": case["_id"],
                    "custody_pending_event_id": event["custody_event_id"],
                },
                {"$unset": {"custody_pending_event_id": ""}},
            )
            event["state"] = "COMMITTED"
            return event

        await db.evidence_custody_events.update_one(
            {"custody_event_id": event["custody_event_id"], "state": "PENDING"},
            {"$set": {"state": "ABORTED", "aborted_at": datetime.now(timezone.utc)}},
        )
    raise RuntimeError("Evidence custody chain is busy; retry the operation")


async def recover_pending_custody_event(db, case: dict) -> dict:
    """Finish a custody append whose case-head CAS already succeeded."""

    pending_id = str(case.get("custody_pending_event_id") or "")
    if not pending_id:
        return case
    event = await db.evidence_custody_events.find_one(
        {
            "tenant_id": case.get("tenant_id"),
            "case_id": case.get("case_id"),
            "custody_event_id": pending_id,
        }
    )
    valid = bool(
        event
        and event.get("state") in {"PENDING", "COMMITTED"}
        and int(event.get("sequence") or 0) == int(case.get("custody_sequence") or 0)
        and str(event.get("current_custody_hash") or "")
        == str(case.get("custody_head_hash") or "")
        and str(event.get("current_custody_hash") or "") == custody_event_hash(event)
    )
    if not valid:
        raise RuntimeError("Evidence custody recovery requires operator review")
    if event.get("state") == "PENDING":
        await db.evidence_custody_events.update_one(
            {"custody_event_id": pending_id, "state": "PENDING"},
            {"$set": {"state": "COMMITTED", "committed_at": _mongo_utc_now()}},
        )
    await db.evidence_cases.update_one(
        {"_id": case["_id"], "custody_pending_event_id": pending_id},
        {"$unset": {"custody_pending_event_id": ""}},
    )
    recovered = await db.evidence_cases.find_one({"_id": case["_id"]})
    return recovered or case


def verify_custody_chain(events: list[dict]) -> dict:
    ordered = sorted(events, key=lambda item: int(item.get("sequence") or 0))
    previous_hash = "0" * 64
    invalid_event_ids = []
    for expected_sequence, event in enumerate(ordered, start=1):
        valid = (
            event.get("state") == "COMMITTED"
            and event.get("chain_version") == CUSTODY_CHAIN_VERSION
            and int(event.get("sequence") or 0) == expected_sequence
            and str(event.get("previous_custody_hash") or "") == previous_hash
            and str(event.get("current_custody_hash") or "") == custody_event_hash(event)
        )
        if not valid:
            invalid_event_ids.append(str(event.get("custody_event_id") or "unknown"))
        previous_hash = str(event.get("current_custody_hash") or "")
    return {
        "status": "VERIFIED" if ordered and not invalid_event_ids else "UNVERIFIED",
        "verified": bool(ordered) and not invalid_event_ids,
        "event_count": len(ordered),
        "head_hash": previous_hash if ordered else None,
        "invalid_event_ids": invalid_event_ids,
    }

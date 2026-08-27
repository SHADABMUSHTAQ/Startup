"""Mongo-backed retention fences for hold and archive state transitions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError


async def acquire_retention_fence(
    db,
    tenant_id: str,
    owner: str,
    *,
    lease_seconds: int = 30,
) -> bool:
    now = datetime.now(timezone.utc)
    lock_id = f"tenant-retention:{tenant_id}"
    try:
        record = await db.evidence_retention_fences.find_one_and_update(
            {
                "lock_id": lock_id,
                "$or": [
                    {"expires_at": {"$lte": now}},
                    {"owner": owner},
                ],
            },
            {
                "$set": {
                    "tenant_id": tenant_id,
                    "owner": owner,
                    "acquired_at": now,
                    "expires_at": now + timedelta(seconds=max(5, lease_seconds)),
                },
                "$setOnInsert": {"lock_id": lock_id, "created_at": now},
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
    except DuplicateKeyError:
        return False
    return bool(record and record.get("owner") == owner)


async def release_retention_fence(db, tenant_id: str, owner: str) -> None:
    await db.evidence_retention_fences.delete_one(
        {"lock_id": f"tenant-retention:{tenant_id}", "owner": owner}
    )

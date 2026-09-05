"""Fail-closed reconciliation of WarSOC legal holds with Azure archive blobs."""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from datetime import datetime, timedelta, timezone

from azure.storage.blob.aio import BlobServiceClient
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

from app.utils.archive_legal_holds import (
    archive_blob_client,
    protect_archive_for_hold,
    release_managed_blob_legal_hold,
)
from app.utils.evidence_holds import archive_query_for_hold
from app.utils.evidence_locks import acquire_retention_fence, release_retention_fence


load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("evidence_hold_worker")

ACTIVE_STATES = {"ACTIVE", "PENDING_RELEASE"}
BATCH_SIZE = 50


async def _apply_hold(db, blob_service, hold: dict) -> None:
    query = archive_query_for_hold(hold)
    cursor_id = hold.get("archive_scan_after_id")
    if cursor_id:
        query["_id"] = {"$gt": cursor_id}
    archives = await db.storage_archives.find(query).sort("_id", 1).limit(BATCH_SIZE).to_list(BATCH_SIZE)
    for archive in archives:
        await protect_archive_for_hold(db, blob_service, hold, archive)
    now = datetime.now(timezone.utc)
    if len(archives) == BATCH_SIZE:
        await db.legal_holds.update_one(
            {"_id": hold["_id"], "status": "ACTIVE"},
            {
                "$set": {
                    "archive_protection_status": "PENDING",
                    "archive_scan_after_id": archives[-1]["_id"],
                    "archive_protection_checked_at": now,
                    "updated_at": now,
                },
                "$unset": {"archive_protection_error": "", "archive_retry_at": ""},
            },
        )
        return
    await db.legal_holds.update_one(
        {"_id": hold["_id"], "status": "ACTIVE"},
        {
            "$set": {
                "archive_protection_status": "PROTECTED",
                "archive_protection_checked_at": now,
                "updated_at": now,
            },
            "$unset": {
                "archive_scan_after_id": "",
                "archive_protection_error": "",
                "archive_retry_at": "",
            },
        },
    )


async def _other_active_hold_exists(
    db,
    tenant_id: str,
    archive: dict,
    current_hold_id: str,
) -> bool:
    collection = str(archive.get("collection") or "")
    event_uids = [str(value) for value in archive.get("event_uids") or [] if value]
    scope_queries: list[dict] = [
        {"scope_type": "TENANT"},
        {"scope_type": "COLLECTION", "collection": collection},
    ]
    if event_uids:
        scope_queries.append(
            {
                "scope_type": "EVENT",
                "collection": collection,
                "event_uid": {"$in": event_uids},
            }
        )
    return bool(
        await db.legal_holds.find_one(
            {
                "tenant_id": tenant_id,
                "hold_id": {"$ne": current_hold_id},
                "status": {"$in": list(ACTIVE_STATES)},
                "$or": scope_queries,
            },
            {"_id": 1},
        )
    )


async def _release_binding(db, blob_service, hold: dict, binding: dict) -> None:
    archive_key = str(binding["archive_key"])
    hold_id = str(hold["hold_id"])
    archive = await db.storage_archives.find_one(
        {"tenant_id": hold["tenant_id"], "archive_key": archive_key},
        {"collection": 1, "event_uids": 1},
    )
    if not archive:
        raise RuntimeError("Archive ledger is missing for a legal-hold binding")
    preserve_for_other_hold = await _other_active_hold_exists(
        db,
        str(hold["tenant_id"]),
        archive,
        hold_id,
    )
    if not preserve_for_other_hold:
        container = blob_service.get_container_client(str(binding["container_name"]))
        await release_managed_blob_legal_hold(
            archive_blob_client(container, str(binding["blob_name"]), binding.get("blob_version_id")),
            preexisting=bool(binding.get("json_hold_preexisting")),
        )
        await release_managed_blob_legal_hold(
            archive_blob_client(
                container,
                str(binding["hash_blob_name"]),
                binding.get("hash_blob_version_id"),
            ),
            preexisting=bool(binding.get("hash_hold_preexisting")),
        )
    now = datetime.now(timezone.utc)
    await db.evidence_archive_hold_bindings.update_one(
        {"_id": binding["_id"], "status": {"$ne": "RELEASED"}},
        {
            "$set": {
                "status": "RELEASED",
                "released_at": now,
                "preserved_for_other_hold": preserve_for_other_hold,
                "updated_at": now,
            }
        },
    )
    await db.storage_archives.update_one(
        {"tenant_id": hold["tenant_id"], "archive_key": archive_key},
        {"$pull": {"active_hold_ids": hold_id}, "$set": {"legal_hold_reconciled_at": now}},
    )


async def _commit_release_audit(db, hold: dict) -> None:
    now = datetime.now(timezone.utc)
    operation_id = str(hold["release_operation_id"])
    audit_result = await db.evidence_hold_audit.update_one(
        {"operation_id": operation_id},
        {"$set": {"status": "COMMITTED", "updated_at": now}},
    )
    if audit_result.matched_count != 1:
        raise RuntimeError("Evidence hold release audit operation is missing")
    result = await db.legal_holds.update_one(
        {
            "_id": hold["_id"],
            "status": "PENDING_RELEASE",
            "release_operation_id": operation_id,
        },
        {
            "$set": {
                "status": "RELEASED",
                "archive_protection_status": "RELEASED",
                "released_at": now,
                "updated_at": now,
            },
            "$unset": {"archive_protection_error": "", "archive_retry_at": ""},
        },
    )
    if result.modified_count != 1:
        raise RuntimeError("Evidence hold changed during release finalization")


async def _release_hold(db, blob_service, hold: dict) -> None:
    owner = f"hold-worker:{socket.gethostname()}:{hold['hold_id']}"
    tenant_id = str(hold["tenant_id"])
    if not await acquire_retention_fence(db, tenant_id, owner):
        return
    try:
        if not hold.get("release_archive_scan_complete"):
            query = archive_query_for_hold(hold)
            cursor_id = hold.get("release_archive_scan_after_id")
            if cursor_id:
                query["_id"] = {"$gt": cursor_id}
            archives = await db.storage_archives.find(query).sort("_id", 1).limit(BATCH_SIZE).to_list(BATCH_SIZE)
            for archive in archives:
                await protect_archive_for_hold(db, blob_service, hold, archive)
            now = datetime.now(timezone.utc)
            if len(archives) == BATCH_SIZE:
                await db.legal_holds.update_one(
                    {"_id": hold["_id"], "status": "PENDING_RELEASE"},
                    {
                        "$set": {
                            "release_archive_scan_after_id": archives[-1]["_id"],
                            "updated_at": now,
                        }
                    },
                )
                return
            await db.legal_holds.update_one(
                {"_id": hold["_id"], "status": "PENDING_RELEASE"},
                {
                    "$set": {"release_archive_scan_complete": True, "updated_at": now},
                    "$unset": {"release_archive_scan_after_id": ""},
                },
            )
            hold["release_archive_scan_complete"] = True
        bindings = await db.evidence_archive_hold_bindings.find(
            {
                "tenant_id": tenant_id,
                "hold_id": hold["hold_id"],
                "status": {"$ne": "RELEASED"},
            }
        ).sort("_id", 1).limit(BATCH_SIZE).to_list(BATCH_SIZE)
        for binding in bindings:
            if binding.get("status") != "PROTECTED":
                archive = await db.storage_archives.find_one(
                    {"tenant_id": tenant_id, "archive_key": binding["archive_key"]}
                )
                if not archive:
                    raise RuntimeError("Archive ledger is missing for a legal-hold binding")
                await protect_archive_for_hold(db, blob_service, hold, archive)
                binding = await db.evidence_archive_hold_bindings.find_one({"_id": binding["_id"]})
            await _release_binding(db, blob_service, hold, binding)
        remaining = await db.evidence_archive_hold_bindings.find_one(
            {"tenant_id": tenant_id, "hold_id": hold["hold_id"], "status": {"$ne": "RELEASED"}},
            {"_id": 1},
        )
        if not remaining:
            await _commit_release_audit(db, hold)
    finally:
        await release_retention_fence(db, tenant_id, owner)


async def _mark_failure(db, hold: dict, exc: Exception) -> None:
    now = datetime.now(timezone.utc)
    await db.legal_holds.update_one(
        {"_id": hold["_id"], "status": {"$in": list(ACTIVE_STATES)}},
        {
            "$set": {
                "archive_protection_status": "FAILED",
                "archive_protection_error": type(exc).__name__,
                "archive_retry_at": now + timedelta(minutes=5),
                "updated_at": now,
            },
            "$inc": {"archive_protection_attempts": 1},
        },
    )


async def reconcile_once(db, blob_service) -> bool:
    now = datetime.now(timezone.utc)
    hold = await db.legal_holds.find_one(
        {
            "status": "PENDING_RELEASE",
            "$or": [{"archive_retry_at": {"$exists": False}}, {"archive_retry_at": {"$lte": now}}],
        },
        sort=[("release_requested_at", 1)],
    )
    if not hold:
        hold = await db.legal_holds.find_one(
            {
                "status": "ACTIVE",
                "archive_protection_status": {"$in": ["PENDING", "FAILED"]},
                "$or": [
                    {"archive_retry_at": {"$exists": False}},
                    {"archive_retry_at": {"$lte": now}},
                ],
            },
            sort=[("created_at", 1)],
        )
    if not hold:
        return False
    try:
        if hold["status"] == "PENDING_RELEASE":
            await _release_hold(db, blob_service, hold)
        else:
            await _apply_hold(db, blob_service, hold)
    except Exception as exc:
        logger.exception("Evidence hold reconciliation failed for %s", hold.get("hold_id"))
        await _mark_failure(db, hold, exc)
    return True


async def run_worker() -> None:
    connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING", "").strip()
    if not connection_string:
        raise RuntimeError("AZURE_STORAGE_CONNECTION_STRING is required")
    mongo = AsyncIOMotorClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
    db = mongo[os.getenv("MONGODB_DB_NAME", "warsoc_db")]
    blob_service = BlobServiceClient.from_connection_string(connection_string)
    logger.info("WarSOC evidence hold worker started")
    try:
        while True:
            worked = await reconcile_once(db, blob_service)
            await asyncio.sleep(1 if worked else 15)
    finally:
        await blob_service.close()
        mongo.close()


if __name__ == "__main__":
    asyncio.run(run_worker())

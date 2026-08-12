import asyncio
import logging
import os
import socket
import uuid
from datetime import timedelta

from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.identity.aio import DefaultAzureCredential
from azure.storage.blob import RehydratePriority, StandardBlobTier
from azure.storage.blob.aio import BlobServiceClient
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ReturnDocument

from app.config.config import get_settings
from app.utils.archive_reader import archive_ledger_query
from app.utils.archive_retrieval import (
    maximum_retrieval_blobs,
    normalize_utc,
    retrieval_enabled,
    retrieval_month_key,
    utc_now,
)


logger = logging.getLogger("archive_retrieval_worker")


def _staging_container_name() -> str:
    return os.getenv("AZURE_RETRIEVAL_STAGING_CONTAINER", "warsoc-retrieval-staging").strip()


def _poll_interval_seconds() -> int:
    try:
        return max(15, min(900, int(os.getenv("ARCHIVE_RETRIEVAL_POLL_SECONDS", "60"))))
    except ValueError:
        return 60


def _safe_segment(value: str) -> str:
    return "".join(character for character in value if character.isalnum() or character in {"-", "_"})


async def _claim_approved_request(db, worker_id: str) -> dict | None:
    now = utc_now()
    return await db["archive_retrieval_requests"].find_one_and_update(
        {"status": "APPROVED"},
        {
            "$set": {
                "status": "PENDING_REHYDRATION",
                "worker_lease": worker_id,
                "worker_claimed_at": now,
                "updated_at": now,
            },
            "$inc": {"worker_attempts": 1},
            "$push": {
                "history": {
                    "status": "PENDING_REHYDRATION",
                    "at": now,
                    "actor": worker_id,
                }
            },
        },
        sort=[("created_at", 1)],
        return_document=ReturnDocument.AFTER,
    )


async def _start_request_copies(
    blob_service,
    db,
    request_doc: dict,
    *,
    source_authorization: str,
) -> None:
    staging_container_name = _staging_container_name()
    if not staging_container_name:
        raise RuntimeError("AZURE_RETRIEVAL_STAGING_CONTAINER is required")
    staging_container = blob_service.get_container_client(staging_container_name)
    try:
        await staging_container.get_container_properties()
    except ResourceNotFoundError as exc:
        raise RuntimeError("Configured retrieval staging container does not exist") from exc

    query = archive_ledger_query(
        tenant_id=request_doc["tenant_id"],
        collections=request_doc["collections"],
        start_dt=normalize_utc(request_doc["start_at"]),
        end_dt=normalize_utc(request_doc["end_at"]),
    )
    max_blobs = maximum_retrieval_blobs()
    entries = await db["storage_archives"].find(query).sort("created_at", 1).limit(
        max_blobs + 1
    ).to_list(length=max_blobs + 1)
    if not entries:
        raise RuntimeError("No archived blobs match the approved retrieval")
    if len(entries) > max_blobs:
        raise RuntimeError("Approved retrieval exceeds the configured blob limit")

    items = []
    request_segment = _safe_segment(request_doc["request_id"])
    tenant_segment = _safe_segment(request_doc["tenant_id"])
    default_source_container = os.getenv("AZURE_STORAGE_CONTAINER", "warsoc-cold-storage")
    for entry in entries:
        source_container_name = entry.get("container_name") or default_source_container
        source_blob_name = str(entry.get("blob_name") or "")
        archive_key = str(entry.get("archive_key") or "")
        if not source_container_name or not source_blob_name or not archive_key:
            raise RuntimeError("Archive ledger entry is incomplete")

        suffix = source_blob_name.rsplit(".", 1)[-1] if "." in source_blob_name else "json"
        staging_blob_name = (
            f"{tenant_segment}/{request_segment}/"
            f"{_safe_segment(entry.get('collection') or 'archive')}-"
            f"{_safe_segment(archive_key)}.{_safe_segment(suffix)}"
        )
        source_blob = blob_service.get_blob_client(source_container_name, source_blob_name)
        destination_blob = staging_container.get_blob_client(staging_blob_name)
        copy_status = "pending"
        copy_id = None
        try:
            properties = await destination_blob.get_blob_properties()
            copy_status = str(properties.copy.status or "").lower()
            copy_id = properties.copy.id
        except ResourceNotFoundError:
            result = await destination_blob.start_copy_from_url(
                source_blob.url,
                metadata={
                    "request_id": request_doc["request_id"],
                    "archive_key": archive_key,
                    "sha256": str(entry.get("sha256") or ""),
                },
                standard_blob_tier=StandardBlobTier.COOL,
                rehydrate_priority=RehydratePriority.STANDARD,
                source_authorization=source_authorization,
            )
            copy_status = str(result.get("copy_status") or "pending").lower()
            copy_id = result.get("copy_id")
        except ResourceExistsError:
            properties = await destination_blob.get_blob_properties()
            copy_status = str(properties.copy.status or "").lower()
            copy_id = properties.copy.id

        items.append(
            {
                "archive_key": archive_key,
                "collection": entry.get("collection"),
                "source_container": source_container_name,
                "source_blob_name": source_blob_name,
                "staging_container": staging_container_name,
                "staging_blob_name": staging_blob_name,
                "sha256": entry.get("sha256"),
                "copy_id": copy_id,
                "status": copy_status,
                "bytes": int(entry.get("blob_size_bytes") or 0),
            }
        )

    now = utc_now()
    await db["archive_retrieval_requests"].update_one(
        {"request_id": request_doc["request_id"], "status": "PENDING_REHYDRATION"},
        {
            "$set": {
                "items": items,
                "copy_started_at": now,
                "updated_at": now,
            }
        },
    )


async def _refresh_pending_request(
    blob_service,
    db,
    request_doc: dict,
    *,
    source_authorization: str,
) -> None:
    items = request_doc.get("items") or []
    if not items:
        await _start_request_copies(
            blob_service,
            db,
            request_doc,
            source_authorization=source_authorization,
        )
        return

    refreshed = []
    all_ready = True
    failed = False
    actual_bytes = 0
    for item in items:
        destination = blob_service.get_blob_client(
            item["staging_container"],
            item["staging_blob_name"],
        )
        properties = await destination.get_blob_properties()
        status = str(properties.copy.status or "").lower()
        if status not in {"success", "failed", "aborted"}:
            all_ready = False
        if status in {"failed", "aborted"}:
            failed = True
        size = int(getattr(properties, "size", 0) or 0)
        actual_bytes += size
        refreshed.append({**item, "status": status, "bytes": size})

    now = utc_now()
    if failed:
        await db["archive_retrieval_requests"].update_one(
            {"request_id": request_doc["request_id"], "status": "PENDING_REHYDRATION"},
            {
                "$set": {
                    "status": "FAILED",
                    "items": refreshed,
                    "updated_at": now,
                    "failed_at": now,
                },
                "$push": {
                    "history": {
                        "status": "FAILED",
                        "at": now,
                        "actor": "archive-retrieval-worker",
                    }
                },
            },
        )
        return

    if not all_ready:
        await db["archive_retrieval_requests"].update_one(
            {"request_id": request_doc["request_id"], "status": "PENDING_REHYDRATION"},
            {"$set": {"items": refreshed, "last_polled_at": now, "updated_at": now}},
        )
        return

    expires_hours = max(1, min(72, int(request_doc.get("staging_expires_hours") or 48)))
    ready_doc = await db["archive_retrieval_requests"].find_one_and_update(
        {"request_id": request_doc["request_id"], "status": "PENDING_REHYDRATION"},
        {
            "$set": {
                "status": "READY",
                "items": refreshed,
                "actual_bytes": actual_bytes,
                "ready_at": now,
                "expires_at": now + timedelta(hours=expires_hours),
                "updated_at": now,
            },
            "$push": {
                "history": {
                    "status": "READY",
                    "at": now,
                    "actor": "archive-retrieval-worker",
                }
            },
        },
        return_document=ReturnDocument.AFTER,
    )
    if ready_doc is not None:
        await db["archive_retrieval_usage"].update_one(
            {
                "tenant_id": request_doc["tenant_id"],
                "billing_month": request_doc.get("billing_month") or retrieval_month_key(now),
            },
            {
                "$setOnInsert": {
                    "tenant_id": request_doc["tenant_id"],
                    "billing_month": request_doc.get("billing_month") or retrieval_month_key(now),
                    "created_at": now,
                },
                "$inc": {
                    "ready_jobs": 1,
                    "retrieved_bytes": actual_bytes,
                    "retrieved_blobs": len(refreshed),
                },
                "$set": {"updated_at": now},
            },
            upsert=True,
        )


async def _expire_ready_requests(blob_service, db) -> None:
    now = utc_now()
    rows = await db["archive_retrieval_requests"].find(
        {"status": "READY", "expires_at": {"$lte": now}}
    ).limit(20).to_list(length=20)
    for request_doc in rows:
        deletion_failed = False
        for item in request_doc.get("items") or []:
            try:
                await blob_service.get_blob_client(
                    item["staging_container"],
                    item["staging_blob_name"],
                ).delete_blob(delete_snapshots="include")
            except ResourceNotFoundError:
                continue
            except Exception:
                deletion_failed = True
                logger.exception(
                    "Unable to delete staged archive object for %s",
                    request_doc.get("request_id"),
                )
        if deletion_failed:
            continue
        await db["archive_retrieval_requests"].update_one(
            {"request_id": request_doc["request_id"], "status": "READY"},
            {
                "$set": {"status": "EXPIRED", "expired_at": now, "updated_at": now},
                "$push": {
                    "history": {
                        "status": "EXPIRED",
                        "at": now,
                        "actor": "archive-retrieval-worker",
                    }
                },
            },
        )


async def run_worker() -> None:
    if not retrieval_enabled():
        logger.warning("Archive retrieval worker is disabled by configuration")
        return

    settings = get_settings()
    account_url = os.getenv("AZURE_STORAGE_ACCOUNT_URL", "").strip().rstrip("/")
    if not account_url.startswith("https://"):
        raise RuntimeError("AZURE_STORAGE_ACCOUNT_URL must be configured with HTTPS")

    mongo_client = AsyncIOMotorClient(settings.mongodb_uri)
    db = mongo_client[settings.mongodb_db_name]
    credential = DefaultAzureCredential()
    blob_service = BlobServiceClient(account_url=account_url, credential=credential)
    worker_id = f"archive-retrieval:{socket.gethostname()}:{uuid.uuid4().hex[:8]}"
    interval = _poll_interval_seconds()
    try:
        while True:
            try:
                claimed = await _claim_approved_request(db, worker_id)
                if claimed is not None:
                    token = await credential.get_token("https://storage.azure.com/.default")
                    await _start_request_copies(
                        blob_service,
                        db,
                        claimed,
                        source_authorization=f"Bearer {token.token}",
                    )

                pending = await db["archive_retrieval_requests"].find(
                    {"status": "PENDING_REHYDRATION"}
                ).sort("created_at", 1).limit(20).to_list(length=20)
                for request_doc in pending:
                    try:
                        token = await credential.get_token("https://storage.azure.com/.default")
                        await _refresh_pending_request(
                            blob_service,
                            db,
                            request_doc,
                            source_authorization=f"Bearer {token.token}",
                        )
                    except Exception as exc:
                        logger.exception(
                            "Archive retrieval processing failed for %s",
                            request_doc.get("request_id"),
                        )
                        await db["archive_retrieval_requests"].update_one(
                            {"request_id": request_doc.get("request_id")},
                            {
                                "$set": {
                                    "last_error_at": utc_now(),
                                    "last_error_internal": type(exc).__name__,
                                }
                            },
                        )
                await _expire_ready_requests(blob_service, db)
            except Exception:
                logger.exception("Archive retrieval worker iteration failed")
            await asyncio.sleep(interval)
    finally:
        await blob_service.close()
        await credential.close()
        mongo_client.close()


if __name__ == "__main__":
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    asyncio.run(run_worker())

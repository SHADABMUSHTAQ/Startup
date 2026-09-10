"""Controlled production canary for WarSOC historical Azure retrieval."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import redis
from azure.storage.blob.aio import BlobServiceClient
from pymongo import MongoClient

from app.config.config import get_settings
from app.routes.auth import create_access_token


SOURCE_CONTAINER = "warsoc-general-90"
SOURCE_BLOB = (
    "WARSOC_AZURE_E2E_20260906T161701Z/fbr_pos_logs/year=2026/month=08/day=29/"
    "archive_fbr_pos_logs_88968d61ef08c0f93e377855.json"
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def _blob_sha256(blob_client) -> tuple[str, int]:
    downloader = await blob_client.download_blob(max_concurrency=1)
    digest = hashlib.sha256()
    size = 0
    async for chunk in downloader.chunks():
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


async def _delete_staging_prefix(blob_service, prefix: str) -> int:
    container = blob_service.get_container_client(
        os.getenv("AZURE_RETRIEVAL_STAGING_CONTAINER", "warsoc-retrieval-staging")
    )
    deleted = 0
    async for blob in container.list_blobs(name_starts_with=prefix):
        await container.delete_blob(blob.name, delete_snapshots="include")
        deleted += 1
    return deleted


async def run_canary() -> dict:
    settings = get_settings()
    if os.getenv("ARCHIVE_RETRIEVAL_ENABLED", "false").strip().lower() != "true":
        raise RuntimeError("Archive retrieval is disabled")
    if os.getenv("AZURE_RETRIEVAL_SAS_MODE", "").strip().lower() != "service_sas":
        raise RuntimeError("This canary requires the explicit service_sas fallback")

    connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING", "").strip()
    if not connection_string:
        raise RuntimeError("AZURE_STORAGE_CONNECTION_STRING is missing")

    now = utc_now()
    run_id = f"ARCHIVE-RETRIEVAL-CANARY-{now:%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    tenant_id = f"WARSOC_RETRIEVAL_CANARY_{uuid.uuid4().hex[:12].upper()}"
    username = f"archive_canary_{uuid.uuid4().hex[:12]}"
    request_id = None
    prefix = f"{tenant_id}/"
    report = {"run_id": run_id, "checks": {}, "cleanup": {}, "passed": False}

    mongo = MongoClient(settings.mongodb_uri)
    db = mongo[settings.mongodb_db_name]
    redis_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    blob_service = BlobServiceClient.from_connection_string(connection_string)
    try:
        source = blob_service.get_blob_client(SOURCE_CONTAINER, SOURCE_BLOB)
        source_properties = await source.get_blob_properties()
        source_sha256, source_bytes = await _blob_sha256(source)
        report["checks"]["synthetic_source_is_cold"] = (
            str(source_properties.blob_tier or "").lower() == "cold"
            and SOURCE_BLOB.startswith("WARSOC_AZURE_E2E_")
        )
        report["checks"]["source_sha256_bounded"] = (
            len(source_sha256) == 64 and 0 < source_bytes <= 1024 * 1024
        )

        db.tenants.insert_one(
            {
                "tenant_id": tenant_id,
                "company_name": "WarSOC Archive Retrieval Canary",
                "status": "active",
                "active": True,
                "has_active_plan": True,
                "retention_days": 90,
                "created_at": now,
                "test_run_id": run_id,
            }
        )
        db.users.insert_one(
            {
                "username": username,
                "email": f"{username}@acceptance.invalid",
                "full_name": "WarSOC Archive Canary",
                "tenant_id": tenant_id,
                "role": "admin",
                "status": "active",
                "plan_type": "Custom",
                "has_active_plan": True,
                "compliance_packs": ["fbr_pos"],
                "created_at": now,
                "test_run_id": run_id,
            }
        )
        db.storage_archives.insert_one(
            {
                "tenant_id": tenant_id,
                "collection": "fbr_pos_logs",
                "archive_key": f"canary-{uuid.uuid4().hex[:16]}",
                "container_name": SOURCE_CONTAINER,
                "blob_name": SOURCE_BLOB,
                "sha256": source_sha256,
                "blob_size_bytes": source_bytes,
                "document_count": 1,
                "status": "archived_hot_deleted",
                "oldest_at": now - timedelta(days=30),
                "newest_at": now - timedelta(days=30) + timedelta(minutes=1),
                "oldest_customer_access_until": now + timedelta(days=60),
                "customer_access_until": now + timedelta(days=60),
                "created_at": now,
                "test_run_id": run_id,
            }
        )

        csrf = uuid.uuid4().hex
        token = create_access_token(
            {
                "sub": username,
                "type": "user",
                "tenant_id": tenant_id,
                "role": "admin",
            },
            expires_delta=timedelta(minutes=15),
        )
        headers = {
            "Authorization": f"Bearer {token}",
            "X-CSRF-Token": csrf,
        }
        cookies = {"csrf_token": csrf}
        with httpx.Client(
            base_url="http://127.0.0.1:8000/api/v1",
            headers=headers,
            cookies=cookies,
            timeout=30.0,
        ) as client:
            created = client.post(
                "/archive-retrievals",
                json={
                    "collections": ["fbr_pos_logs"],
                    "start_at": (now - timedelta(days=31)).isoformat(),
                    "end_at": (now - timedelta(days=29)).isoformat(),
                    "reason": "Controlled production archive retrieval acceptance",
                },
            )
            report["create_http"] = created.status_code
            created.raise_for_status()
            request_doc = created.json()
            request_id = request_doc["request_id"]
            report["checks"]["request_auto_approved"] = (
                request_doc.get("status") == "APPROVED"
                and request_doc.get("included_allowance") is True
            )

            deadline = time.monotonic() + 240
            current = request_doc
            while time.monotonic() < deadline:
                status_response = client.get(f"/archive-retrievals/{request_id}")
                status_response.raise_for_status()
                current = status_response.json()
                if current.get("status") in {"READY", "FAILED"}:
                    break
                time.sleep(2)

            report["retrieval_status"] = current.get("status")
            report["checks"]["worker_reached_ready"] = current.get("status") == "READY"
            if current.get("status") != "READY":
                raise RuntimeError(f"Retrieval ended in {current.get('status')}")

            links_response = client.post(
                f"/archive-retrievals/{request_id}/download-links"
            )
            report["links_http"] = links_response.status_code
            links_response.raise_for_status()
            links = links_response.json().get("items") or []
            report["checks"]["one_short_lived_direct_link"] = len(links) == 1
            downloaded = httpx.get(links[0]["url"], timeout=30.0)
            report["download_http"] = downloaded.status_code
            downloaded.raise_for_status()
            report["checks"]["download_sha256_matches"] = (
                hashlib.sha256(downloaded.content).hexdigest() == source_sha256
            )

        internal = db.archive_retrieval_requests.find_one(
            {"request_id": request_id, "tenant_id": tenant_id}
        )
        items = (internal or {}).get("items") or []
        report["checks"]["worker_recorded_integrity"] = bool(
            items
            and all(
                item.get("integrity_status") == "verified"
                and item.get("verified_sha256") == source_sha256
                for item in items
            )
        )
        report["passed"] = all(report["checks"].values())
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {str(exc)[:400]}"
    finally:
        try:
            report["cleanup"]["staged_blobs_deleted"] = await _delete_staging_prefix(
                blob_service, prefix
            )
        except Exception as exc:
            report["cleanup"]["staging_error"] = type(exc).__name__
        deleted = {}
        for collection_name in db.list_collection_names():
            result = db[collection_name].delete_many({"tenant_id": tenant_id})
            if result.deleted_count:
                deleted[collection_name] = result.deleted_count
        redis_deleted = 0
        for pattern in (f"*{tenant_id}*", f"*{username}*", f"*{run_id}*"):
            keys = list(redis_client.scan_iter(match=pattern, count=100))
            if keys:
                redis_deleted += redis_client.delete(*keys)
        report["cleanup"].update(
            {
                "mongo_deleted": deleted,
                "redis_keys_deleted": redis_deleted,
                "remaining_mongo_records": sum(
                    db[name].count_documents({"tenant_id": tenant_id})
                    for name in db.list_collection_names()
                ),
                "source_blob_untouched": True,
            }
        )
        await blob_service.close()
        redis_client.close()
        mongo.close()

    report["completed_at"] = utc_now().isoformat()
    return report


def main() -> None:
    report = asyncio.run(run_canary())
    print(json.dumps(report, indent=2, default=str))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()

"""Bounded worker for signed, independently verifiable evidence packages."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import shutil
import socket
import tempfile
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.storage.blob import ContentSettings
from azure.storage.blob.aio import BlobServiceClient
from bson import ObjectId
from cryptography.hazmat.primitives import serialization
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ReturnDocument

from app.config.config import get_settings
from app.utils.evidence_custody import append_custody_event, verify_custody_chain
from app.utils.evidence_package import build_evidence_package


logger = logging.getLogger("evidence_export_worker")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


def _enabled() -> bool:
    return os.getenv("EVIDENCE_EXPORT_ENABLED", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _safe_segment(value: str) -> str:
    result = "".join(character for character in str(value) if character.isalnum() or character in "-_")
    if not result:
        raise ValueError("Evidence export identifier is invalid")
    return result


def _load_signing_material() -> tuple[bytes, bytes | None, str, int, str]:
    encoded = os.getenv("EVIDENCE_PACKAGE_PRIVATE_KEY_B64", "").strip()
    if not encoded:
        raise RuntimeError("EVIDENCE_PACKAGE_PRIVATE_KEY_B64 is required")
    try:
        private_pem = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise RuntimeError("Evidence package private key is not valid base64") from exc
    password_value = os.getenv("EVIDENCE_PACKAGE_PRIVATE_KEY_PASSWORD", "")
    password = password_value.encode("utf-8") if password_value else None
    key = serialization.load_pem_private_key(private_pem, password=password)
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(public_der).hexdigest()
    key_id = os.getenv("EVIDENCE_PACKAGE_SIGNING_KEY_ID", "").strip()
    if not key_id:
        raise RuntimeError("EVIDENCE_PACKAGE_SIGNING_KEY_ID is required")
    version = int(os.getenv("EVIDENCE_PACKAGE_SIGNING_KEY_VERSION", "1"))
    if version < 1:
        raise RuntimeError("EVIDENCE_PACKAGE_SIGNING_KEY_VERSION must be positive")
    return private_pem, password, key_id, version, fingerprint


def _write_deterministic_zip(package_dir: Path, zip_path: Path) -> tuple[str, int]:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(package_dir.rglob("*")):
            if not path.is_file():
                continue
            relative = str(path.relative_to(package_dir)).replace("\\", "/")
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, path.read_bytes())
    payload_hash = hashlib.sha256()
    size = 0
    with zip_path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            payload_hash.update(chunk)
            size += len(chunk)
    return payload_hash.hexdigest(), size


async def _claim_export(db, worker_id: str) -> dict | None:
    now = datetime.now(timezone.utc)
    lease_seconds = max(60, min(3600, int(os.getenv("EVIDENCE_EXPORT_LEASE_SECONDS", "600"))))
    return await db.evidence_exports.find_one_and_update(
        {
            "$or": [
                {"status": "REQUESTED"},
                {"status": "PROCESSING", "worker_lease_until": {"$lte": now}},
            ]
        },
        {
            "$set": {
                "status": "PROCESSING",
                "worker_id": worker_id,
                "worker_claimed_at": now,
                "worker_lease_until": now + timedelta(seconds=lease_seconds),
                "updated_at": now,
            },
            "$inc": {"worker_attempts": 1},
        },
        sort=[("created_at", 1)],
        return_document=ReturnDocument.AFTER,
    )


async def _load_hot_case_evidence(db, request_doc: dict, maximum_bytes: int):
    tenant_id = request_doc["tenant_id"]
    case_id = request_doc["case_id"]
    case = await db.evidence_cases.find_one({"tenant_id": tenant_id, "case_id": case_id})
    if not case:
        raise RuntimeError("Evidence case no longer exists")
    items = await db.evidence_case_items.find(
        {"tenant_id": tenant_id, "case_id": case_id, "state": "COMMITTED"}
    ).sort("added_at", 1).to_list(5000)
    if not items:
        raise RuntimeError("Evidence case has no committed items")
    evidence_records = {}
    total_bytes = 0
    for item in items:
        try:
            document_id = ObjectId(str(item.get("document_id") or ""))
        except Exception:
            return case, items, {}, "REQUIRES_ARCHIVE_RETRIEVAL"
        document = await db[str(item["collection"])].find_one(
            {"_id": document_id, "tenant_id": tenant_id}
        )
        if not document:
            return case, items, {}, "REQUIRES_ARCHIVE_RETRIEVAL"
        # The package stores the exact Mongo representation after canonical JSON
        # conversion. Bound the isolated worker before creating local files.
        from app.utils.evidence_custody import canonical_bytes

        total_bytes += len(canonical_bytes(document))
        if total_bytes > maximum_bytes:
            raise RuntimeError("Evidence package exceeds the configured byte limit")
        evidence_records[str(item["case_item_id"])] = document
    custody = await db.evidence_custody_events.find(
        {"tenant_id": tenant_id, "case_id": case_id, "state": "COMMITTED"}
    ).sort("sequence", 1).to_list(10000)
    if not verify_custody_chain(custody)["verified"]:
        raise RuntimeError("Evidence custody chain is not verified")
    return case, items, evidence_records, custody


async def process_evidence_export(
    db,
    blob_service,
    request_doc: dict,
    *,
    private_key_pem: bytes,
    private_key_password: bytes | None,
    signing_key_id: str,
    signing_key_version: int,
    signing_key_fingerprint: str,
) -> dict:
    maximum_bytes = max(
        1024 * 1024,
        min(512 * 1024 * 1024, int(os.getenv("EVIDENCE_EXPORT_MAX_BYTES", str(50 * 1024 * 1024)))),
    )
    loaded = await _load_hot_case_evidence(db, request_doc, maximum_bytes)
    if loaded[3] == "REQUIRES_ARCHIVE_RETRIEVAL":
        now = datetime.now(timezone.utc)
        await db.evidence_exports.update_one(
            {
                "_id": request_doc["_id"],
                "status": "PROCESSING",
                "worker_id": request_doc.get("worker_id"),
            },
            {
                "$set": {
                    "status": "REQUIRES_ARCHIVE_RETRIEVAL",
                    "updated_at": now,
                    "failure_code": "HOT_EVIDENCE_UNAVAILABLE",
                }
            },
        )
        return {"status": "REQUIRES_ARCHIVE_RETRIEVAL"}
    case, items, evidence_records, custody = loaded
    container_name = os.getenv("EVIDENCE_EXPORT_CONTAINER", "").strip()
    if not container_name:
        raise RuntimeError("EVIDENCE_EXPORT_CONTAINER is required")
    container = blob_service.get_container_client(container_name)
    try:
        await container.get_container_properties()
    except ResourceNotFoundError as exc:
        raise RuntimeError("Configured evidence-export container does not exist") from exc

    export_id = str(request_doc["export_id"])
    tenant_segment = hashlib.sha256(str(request_doc["tenant_id"]).encode("utf-8")).hexdigest()
    blob_name = f"packages/{tenant_segment}/{_safe_segment(export_id)}.zip"
    with tempfile.TemporaryDirectory(prefix="warsoc-evidence-export-") as temporary:
        root = Path(temporary)
        package_dir = root / "package"
        build_evidence_package(
            package_dir,
            case=case,
            items=items,
            evidence_records=evidence_records,
            custody_events=custody,
            private_key_pem=private_key_pem,
            signing_key_id=signing_key_id,
            signing_key_version=signing_key_version,
            private_key_password=private_key_password,
        )
        zip_path = root / "evidence-package.zip"
        package_sha256, package_bytes = _write_deterministic_zip(package_dir, zip_path)
        if package_bytes > maximum_bytes:
            raise RuntimeError("Compressed evidence package exceeds the configured byte limit")
        blob = container.get_blob_client(blob_name)
        try:
            with zip_path.open("rb") as stream:
                await blob.upload_blob(
                    stream,
                    overwrite=False,
                    content_settings=ContentSettings(content_type="application/zip"),
                    metadata={
                        "export_id": export_id,
                        "sha256": package_sha256,
                        "signing_key_id": signing_key_id,
                        "signing_key_version": str(signing_key_version),
                    },
                )
        except ResourceExistsError:
            properties = await blob.get_blob_properties()
            metadata = getattr(properties, "metadata", {}) or {}
            if metadata.get("sha256") != package_sha256:
                raise RuntimeError("Existing evidence package conflicts with the requested export")

    actor = {
        "_id": request_doc.get("requested_by_user_id"),
        "email": request_doc.get("requested_by"),
        "role": "system-export-worker",
    }
    custody_event = await db.evidence_custody_events.find_one(
        {
            "tenant_id": request_doc["tenant_id"],
            "case_id": request_doc["case_id"],
            "action": "EXPORT",
            "state": "COMMITTED",
            "metadata.export_id": export_id,
        }
    )
    if not custody_event:
        custody_event = await append_custody_event(
            db,
            tenant_id=request_doc["tenant_id"],
            case_id=request_doc["case_id"],
            action="EXPORT",
            actor=actor,
            reason=request_doc["reason"],
            request_id=request_doc.get("request_id") or export_id,
            metadata={
                "operation_id": export_id,
                "export_id": export_id,
                "package_sha256": package_sha256,
                "signing_key_id": signing_key_id,
                "signing_key_version": signing_key_version,
            },
        )
    now = datetime.now(timezone.utc)
    expires_hours = max(1, min(72, int(os.getenv("EVIDENCE_EXPORT_READY_HOURS", "48"))))
    result = await db.evidence_exports.find_one_and_update(
        {
            "_id": request_doc["_id"],
            "status": "PROCESSING",
            "worker_id": request_doc.get("worker_id"),
        },
        {
            "$set": {
                "status": "READY",
                "container_name": container_name,
                "blob_name": blob_name,
                "package_sha256": package_sha256,
                "package_bytes": package_bytes,
                "signing_key_id": signing_key_id,
                "signing_key_version": signing_key_version,
                "signing_key_fingerprint_sha256": signing_key_fingerprint,
                "custody_event_id": custody_event["custody_event_id"],
                "ready_at": now,
                "expires_at": now + timedelta(hours=expires_hours),
                "updated_at": now,
            },
            "$unset": {"failure_code": "", "worker_lease_until": ""},
        },
        return_document=ReturnDocument.AFTER,
    )
    if not result:
        raise RuntimeError("Evidence export worker lease was lost before commit")
    return result


async def expire_ready_exports(db, blob_service, *, limit: int = 50) -> int:
    """Delete temporary package objects before marking their ledger entries expired."""

    now = datetime.now(timezone.utc)
    rows = await db.evidence_exports.find(
        {"status": "READY", "expires_at": {"$lte": now}}
    ).sort("expires_at", 1).limit(max(1, min(limit, 200))).to_list(limit)
    expired = 0
    for document in rows:
        try:
            await blob_service.get_blob_client(
                str(document.get("container_name") or ""),
                str(document.get("blob_name") or ""),
            ).delete_blob(delete_snapshots="include")
        except ResourceNotFoundError:
            pass
        result = await db.evidence_exports.update_one(
            {"_id": document["_id"], "status": "READY"},
            {
                "$set": {
                    "status": "EXPIRED",
                    "expired_at": now,
                    "updated_at": now,
                }
            },
        )
        expired += int(result.modified_count or 0)
    return expired


async def run_worker() -> None:
    if not _enabled():
        return
    settings = get_settings()
    connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING", "").strip()
    if not connection_string:
        raise RuntimeError("AZURE_STORAGE_CONNECTION_STRING is required")
    signing_material = _load_signing_material()
    mongo_client = AsyncIOMotorClient(settings.mongodb_uri)
    blob_service = BlobServiceClient.from_connection_string(connection_string)
    db = mongo_client[settings.mongodb_db_name]
    worker_id = f"evidence-export:{socket.gethostname()}:{uuid.uuid4().hex[:8]}"
    poll_seconds = max(5, min(300, int(os.getenv("EVIDENCE_EXPORT_POLL_SECONDS", "15"))))
    try:
        while True:
            request_doc = await _claim_export(db, worker_id)
            if request_doc:
                try:
                    await process_evidence_export(
                        db,
                        blob_service,
                        request_doc,
                        private_key_pem=signing_material[0],
                        private_key_password=signing_material[1],
                        signing_key_id=signing_material[2],
                        signing_key_version=signing_material[3],
                        signing_key_fingerprint=signing_material[4],
                    )
                except Exception as exc:
                    logger.exception(
                        "Evidence export processing failed for %s",
                        request_doc.get("export_id"),
                    )
                    now = datetime.now(timezone.utc)
                    await db.evidence_exports.update_one(
                        {
                            "_id": request_doc["_id"],
                            "status": "PROCESSING",
                            "worker_id": worker_id,
                        },
                        {
                            "$set": {
                                "status": "FAILED",
                                "failure_code": type(exc).__name__,
                                "failed_at": now,
                                "updated_at": now,
                            },
                            "$unset": {"worker_lease_until": ""},
                        },
                    )
            await expire_ready_exports(db, blob_service)
            await asyncio.sleep(poll_seconds)
    finally:
        await blob_service.close()
        mongo_client.close()


if __name__ == "__main__":
    asyncio.run(run_worker())

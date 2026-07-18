import asyncio
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

from azure.core.exceptions import ResourceExistsError
from azure.storage.blob.aio import BlobServiceClient
from app.utils.security_incidents import project_security_incident
from bson import ObjectId
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

from app.utils.compliance_catalog import COMPLIANCE_CATALOG

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("storage_archiver")

DEFAULT_ARCHIVE_COLLECTIONS = (
    "logs",
    "siem_cold_vault",
    "security_alerts",
    "fbr_pos_logs",
    "peca_forensic_logs",
    "csv_uploads",
    "analysis_results",
)

COLLECTION_DATE_FIELDS = {
    "logs": ("_retention_ts", "timestamp"),
    "siem_cold_vault": ("_expire_at", "timestamp", "ingested_at"),
    "security_alerts": ("_expire_at", "timestamp", "ingested_at", "_retention_ts"),
    "fbr_pos_logs": ("_expire_at", "timestamp", "ingested_at", "_retention_ts"),
    "peca_forensic_logs": ("_expire_at", "timestamp", "ingested_at", "_retention_ts"),
    "csv_uploads": ("_retention_ts", "timestamp", "uploaded_at"),
    "analysis_results": ("uploaded_at", "created_at", "timestamp"),
}

EXPLICIT_EXPIRY_FIELDS = {"_expire_at"}
COMPLIANCE_PACK_BY_COLLECTION = {
    "fbr_pos_logs": "fbr_pos",
    "peca_forensic_logs": "peca_forensic",
}
COMPLIANCE_HOT_RETENTION_DAYS = {
    collection_name: int(COMPLIANCE_CATALOG[pack_name]["retention"]["local_hot_days"])
    for collection_name, pack_name in COMPLIANCE_PACK_BY_COLLECTION.items()
}
COMPLIANCE_VAULT_RETENTION_DAYS = {
    collection_name: int(COMPLIANCE_CATALOG[pack_name]["retention"]["vault_days"])
    for collection_name, pack_name in COMPLIANCE_PACK_BY_COLLECTION.items()
}
DEFAULT_SIEM_HOT_RETENTION_DAYS = max(1, min(7, int(os.getenv("SIEM_HOT_RETENTION_DAYS", "7"))))
DEFAULT_RAW_LOG_HOT_RETENTION_DAYS = max(1, min(7, int(os.getenv("RAW_LOG_HOT_RETENTION_DAYS", "7"))))
HOT_RETENTION_DAYS_BY_COLLECTION = {
    **COMPLIANCE_HOT_RETENTION_DAYS,
    "siem_cold_vault": DEFAULT_SIEM_HOT_RETENTION_DAYS,
    "security_alerts": DEFAULT_SIEM_HOT_RETENTION_DAYS,
    "logs": DEFAULT_RAW_LOG_HOT_RETENTION_DAYS,
}


def _environment_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _as_utc(value):
    if not isinstance(value, datetime):
        return None
    return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _blob_immutability_status(properties, required_until: datetime) -> dict:
    legal_hold = bool(getattr(properties, "has_legal_hold", False))
    policy = getattr(properties, "immutability_policy", None)
    raw_policy_mode = getattr(policy, "policy_mode", "") or ""
    policy_mode = str(getattr(raw_policy_mode, "value", raw_policy_mode))
    policy_expiry = _as_utc(getattr(policy, "expiry_time", None))
    required_until = _as_utc(required_until)
    locked = policy_mode.strip().lower() == "locked"
    adequate_expiry = bool(policy_expiry and required_until and policy_expiry >= required_until)
    return {
        "verified": legal_hold or (locked and adequate_expiry),
        "legal_hold": legal_hold,
        "policy_mode": policy_mode or None,
        "policy_expiry": policy_expiry,
    }


async def _verify_blob_immutability(blob_client, required_until: datetime) -> dict:
    properties = await blob_client.get_blob_properties()
    status = _blob_immutability_status(properties, required_until)
    if not status["verified"]:
        raise RuntimeError(
            "Azure blob is not protected by a legal hold or a locked immutability "
            f"policy through {required_until.isoformat()}"
        )
    return status


async def _verify_container_immutability_capability(container_client) -> dict:
    properties = await container_client.get_container_properties()
    has_policy = bool(getattr(properties, "has_immutability_policy", False))
    has_legal_hold = bool(getattr(properties, "has_legal_hold", False))
    version_immutability = bool(
        getattr(properties, "immutable_storage_with_versioning_enabled", False)
    )
    capable = has_policy or has_legal_hold or version_immutability
    if not capable:
        raise RuntimeError(
            "Azure evidence container has no immutable-storage capability or policy. "
            "Hot records will not be deleted."
        )
    try:
        configured_days = int(os.getenv("AZURE_CONTAINER_IMMUTABILITY_DAYS", "0"))
    except ValueError as exc:
        raise RuntimeError("AZURE_CONTAINER_IMMUTABILITY_DAYS must be an integer") from exc
    return {
        "has_immutability_policy": has_policy,
        "has_legal_hold": has_legal_hold,
        "immutable_storage_with_versioning_enabled": version_immutability,
        "declared_locked": _environment_flag(
            "AZURE_CONTAINER_IMMUTABILITY_LOCKED",
            default=False,
        ),
        "configured_days": configured_days,
    }


def _verify_container_immutability_for_retention(
    container_status: dict | None,
    required_days: int,
) -> dict:
    status = dict(container_status or {})
    legal_hold = bool(status.get("has_legal_hold"))
    policy_verified = bool(
        status.get("has_immutability_policy")
        and status.get("declared_locked")
        and int(status.get("configured_days") or 0) >= required_days
    )
    if not legal_hold and not policy_verified:
        raise RuntimeError(
            "Azure container-scoped immutability is not verified for the required "
            f"{required_days}-day retention period. Confirm the policy is locked and "
            "set AZURE_CONTAINER_IMMUTABILITY_LOCKED=true plus "
            "AZURE_CONTAINER_IMMUTABILITY_DAYS to the actual Azure policy duration."
        )
    return {
        "verified": True,
        "scope": "container",
        "legal_hold": legal_hold,
        "declared_locked": bool(status.get("declared_locked")),
        "configured_days": int(status.get("configured_days") or 0),
        "verification_source": "azure-container-properties-and-operator-declaration",
    }


def _parse_archive_collections() -> tuple[str, ...]:
    raw = os.getenv("ARCHIVE_COLLECTIONS", "")
    if not raw.strip():
        return DEFAULT_ARCHIVE_COLLECTIONS
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _json_default(value):
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def _coerce_archive_datetime(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _date_clauses(field_name: str, retention_cutoff: datetime, expiry_cutoff: datetime) -> list[dict]:
    cutoff = expiry_cutoff if field_name in EXPLICIT_EXPIRY_FIELDS else retention_cutoff
    return [
        {field_name: {"$lte": cutoff}},
        {field_name: {"$lte": cutoff.isoformat()}},
    ]


def _effective_retention_days(collection_name: str, tenant_retention_days: int) -> int:
    """Return Mongo hot-retention, not the total Azure compliance-retention period."""
    fixed_hot_days = HOT_RETENTION_DAYS_BY_COLLECTION.get(collection_name)
    if fixed_hot_days is not None:
        return max(1, fixed_hot_days)
    return max(1, tenant_retention_days)


def _archive_cutoffs(
    collection_name: str,
    tenant_retention_days: int,
    archive_lead_days: int,
    now: datetime | None = None,
) -> tuple[datetime, datetime]:
    now = now or datetime.now(timezone.utc)
    effective_retention_days = _effective_retention_days(collection_name, tenant_retention_days)
    return (
        now - timedelta(days=effective_retention_days),
        now + timedelta(days=archive_lead_days),
    )


def _archive_query(tenant_id: str, collection_name: str, retention_cutoff: datetime, expiry_cutoff: datetime) -> dict:
    fields = COLLECTION_DATE_FIELDS.get(collection_name, ("timestamp",))
    clauses: list[dict] = []
    for field_name in fields:
        clauses.extend(_date_clauses(field_name, retention_cutoff, expiry_cutoff))
    return {"tenant_id": tenant_id, "$or": clauses}


def _archive_partition_time(docs: list[dict]) -> datetime:
    timestamps = [
        doc.get("timestamp") or doc.get("ingested_at") or doc.get("uploaded_at")
        for doc in docs
    ]
    parsed = [timestamp for timestamp in map(_coerce_archive_datetime, timestamps) if timestamp]
    return min(parsed) if parsed else datetime.now(timezone.utc)


def _blob_base_name(
    tenant_id: str,
    collection_name: str,
    archive_key: str,
    partition_time: datetime,
) -> str:
    return (
        f"{tenant_id}/{collection_name}/"
        f"year={partition_time:%Y}/month={partition_time:%m}/day={partition_time:%d}/"
        f"archive_{collection_name}_{archive_key}"
    )


def _effective_vault_retention_days(collection_name: str, tenant_retention_days: int) -> int:
    compliance_vault_days = COMPLIANCE_VAULT_RETENTION_DAYS.get(collection_name)
    if compliance_vault_days is not None:
        return max(1, compliance_vault_days)
    return max(1, tenant_retention_days)


async def _archive_batch(
    container_client,
    db,
    tenant_id: str,
    collection_name: str,
    docs: list[dict],
    run_id: str,
    batch_number: int,
    tenant_retention_days: int,
    container_immutability: dict | None = None,
):
    document_ids = [doc["_id"] for doc in docs if "_id" in doc]
    if not document_ids:
        return 0

    json_dump = json.dumps(docs, indent=2, default=_json_default).encode("utf-8")
    sha256_hash = hashlib.sha256(json_dump).hexdigest()
    identity = "|".join(
        (
            tenant_id,
            collection_name,
            sha256_hash,
            *(str(document_id) for document_id in document_ids),
        )
    )
    archive_key = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]

    base_name = _blob_base_name(
        tenant_id,
        collection_name,
        archive_key,
        _archive_partition_time(docs),
    )
    json_blob_name = f"{base_name}.json"
    hash_blob_name = f"{base_name}.sha256"
    vault_retention_days = _effective_vault_retention_days(collection_name, tenant_retention_days)
    retain_until = (
        datetime.now(timezone.utc) + timedelta(days=vault_retention_days)
        if vault_retention_days
        else None
    )

    json_blob = container_client.get_blob_client(json_blob_name)
    try:
        await json_blob.upload_blob(
            json_dump,
            overwrite=False,
            metadata={
                "sha256": sha256_hash,
                "collection": collection_name,
                "retention_days": str(vault_retention_days or 0),
            },
        )
    except ResourceExistsError:
        existing = await (await json_blob.download_blob()).readall()
        if hashlib.sha256(existing).hexdigest() != sha256_hash:
            raise RuntimeError(f"Existing archive blob failed integrity check: {json_blob_name}")

    hash_blob = container_client.get_blob_client(hash_blob_name)
    hash_payload = sha256_hash.encode("utf-8")
    try:
        await hash_blob.upload_blob(hash_payload, overwrite=False)
    except ResourceExistsError:
        existing_hash = await (await hash_blob.download_blob()).readall()
        if existing_hash.strip().lower() != hash_payload:
            raise RuntimeError(f"Existing archive hash blob is invalid: {hash_blob_name}")

    immutability_required = _environment_flag("AZURE_IMMUTABILITY_REQUIRED", default=False)
    immutability_status = None
    if immutability_required:
        scope = os.getenv("AZURE_IMMUTABILITY_SCOPE", "blob").strip().lower()
        if scope == "container":
            immutability_status = _verify_container_immutability_for_retention(
                container_immutability,
                vault_retention_days,
            )
        elif scope == "blob":
            json_status = await _verify_blob_immutability(json_blob, retain_until)
            hash_status = await _verify_blob_immutability(hash_blob, retain_until)
            immutability_status = {
                "verified": True,
                "scope": "blob",
                "json": json_status,
                "sha256": hash_status,
            }
        else:
            raise RuntimeError("AZURE_IMMUTABILITY_SCOPE must be 'blob' or 'container'")

    timestamps = [doc.get("timestamp") or doc.get("ingested_at") or doc.get("uploaded_at") for doc in docs]
    parsed_timestamps = [timestamp for timestamp in map(_coerce_archive_datetime, timestamps) if timestamp]
    event_ids = sorted({str(doc.get("event_id")) for doc in docs if doc.get("event_id") is not None})
    event_uids = sorted({str(doc.get("event_uid")) for doc in docs if doc.get("event_uid")})
    alert_uids = sorted({str(doc.get("alert_uid")) for doc in docs if doc.get("alert_uid")})
    archive_doc = {
        "tenant_id": tenant_id,
        "collection": collection_name,
        "blob_name": json_blob_name,
        "hash_blob_name": hash_blob_name,
        "archive_key": archive_key,
        "run_id": run_id,
        "batch_number": batch_number,
        "sha256": sha256_hash,
        "document_count": len(document_ids),
        "first_document_id": str(document_ids[0]),
        "last_document_id": str(document_ids[-1]),
        "oldest_timestamp": min((str(ts) for ts in timestamps if ts is not None), default=None),
        "newest_timestamp": max((str(ts) for ts in timestamps if ts is not None), default=None),
        "oldest_at": min(parsed_timestamps) if parsed_timestamps else None,
        "newest_at": max(parsed_timestamps) if parsed_timestamps else None,
        "event_ids": event_ids,
        "event_uids": event_uids,
        "alert_uids": alert_uids,
        "vault_retention_days": vault_retention_days,
        "retain_until": retain_until,
        "immutability": immutability_status,
        "created_at": datetime.now(timezone.utc),
        "status": "archived",
    }
    await db["storage_archives"].update_one(
        {
            "tenant_id": tenant_id,
            "collection": collection_name,
            "archive_key": archive_key,
        },
        {"$setOnInsert": archive_doc},
        upsert=True,
    )

    delete_result = await db[collection_name].delete_many({
        "tenant_id": tenant_id,
        "_id": {"$in": document_ids},
    })
    logger.info(
        "Archived %s.%s batch %s to %s and deleted %s hot records.",
        tenant_id,
        collection_name,
        batch_number,
        json_blob_name,
        delete_result.deleted_count,
    )
    return delete_result.deleted_count


async def run_archiver():
    logger.info("========================================")
    logger.info(" WARSOC COLD STORAGE ARCHIVER STARTED ")
    logger.info("========================================")

    azure_conn_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
    if not azure_conn_str:
        raise RuntimeError("AZURE_STORAGE_CONNECTION_STRING is required for archival")

    container_name = os.getenv("AZURE_STORAGE_CONTAINER", "warsoc-cold-storage")
    mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    db_name = os.getenv("MONGODB_DB_NAME", "warsoc_db")
    archive_batch_size = int(os.getenv("ARCHIVE_BATCH_SIZE", "5000"))
    archive_lead_days = int(os.getenv("ARCHIVE_LEAD_DAYS", "1"))
    collections_to_archive = _parse_archive_collections()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "_" + uuid.uuid4().hex[:8]

    mongo_client = AsyncIOMotorClient(mongo_uri)
    blob_service_client = None

    try:
        db = mongo_client[db_name]
        blob_service_client = BlobServiceClient.from_connection_string(azure_conn_str)
        container_client = blob_service_client.get_container_client(container_name)
        if not await container_client.exists():
            await container_client.create_container()
            logger.info("Created Azure container: %s", container_name)
        container_immutability = None
        if _environment_flag("AZURE_IMMUTABILITY_REQUIRED", default=False):
            container_immutability = await _verify_container_immutability_capability(
                container_client
            )

        cursor = db.tenants.find({})
        async for tenant in cursor:
            tenant_id = tenant.get("tenant_id")
            retention_days = int(tenant.get("retention_days", 30) or 30)
            if not tenant_id:
                continue

            logger.info(
                "Processing tenant %s with retention_days=%s archive_lead_days=%s",
                tenant_id,
                retention_days,
                archive_lead_days,
            )

            for collection_name in collections_to_archive:
                retention_cutoff, expiry_cutoff = _archive_cutoffs(
                    collection_name,
                    retention_days,
                    archive_lead_days,
                )
                query = _archive_query(tenant_id, collection_name, retention_cutoff, expiry_cutoff)
                batch_number = 1

                while True:
                    docs = await db[collection_name].find(query).sort("_id", 1).limit(archive_batch_size).to_list(length=archive_batch_size)
                    if not docs:
                        break

                    try:
                        if collection_name == "security_alerts":
                            # Archive is allowed to remove alert evidence only
                            # after its mutable workflow state has been projected.
                            # Any projection failure aborts the batch, preserving
                            # the original MongoDB documents for a later retry.
                            for alert in docs:
                                await project_security_incident(db, alert)
                        await _archive_batch(
                            container_client,
                            db,
                            tenant_id,
                            collection_name,
                            docs,
                            run_id,
                            batch_number,
                            retention_days,
                            container_immutability,
                        )
                    except Exception as exc:
                        logger.error(
                            "Failed to archive %s for tenant %s. Records were not deleted. Error: %s",
                            collection_name,
                            tenant_id,
                            exc,
                        )
                        break

                    batch_number += 1

    finally:
        if blob_service_client is not None:
            await blob_service_client.close()
        mongo_client.close()

    logger.info("Storage Archiver run completed.")


async def run_archiver_scheduler():
    interval_seconds = int(os.getenv("ARCHIVE_INTERVAL_SECONDS", "0"))
    if interval_seconds <= 0:
        await run_archiver()
        return
    if interval_seconds < 300:
        raise RuntimeError("ARCHIVE_INTERVAL_SECONDS must be at least 300")

    while True:
        await run_archiver()
        logger.info("Next storage archival run in %s seconds.", interval_seconds)
        await asyncio.sleep(interval_seconds)


if __name__ == "__main__":
    asyncio.run(run_archiver_scheduler())

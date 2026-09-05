import asyncio
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

from azure.core.exceptions import ResourceExistsError
from azure.storage.blob import BlobImmutabilityPolicyMode, ImmutabilityPolicy
from azure.storage.blob.aio import BlobServiceClient
from app.utils.security_incidents import project_security_incident
from bson import ObjectId
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

from app.utils.compliance_catalog import COMPLIANCE_CATALOG
from app.utils.fbr_retention import FBR_ACTIVE_RETENTION_MODEL
from app.utils.peca_retention import PECA_ACTIVE_RETENTION_MODEL
from app.utils.evidence_locks import acquire_retention_fence, release_retention_fence
from app.utils.archive_legal_holds import protect_archive_for_hold

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("storage_archiver")

DEFAULT_ARCHIVE_COLLECTIONS = (
    "logs",
    "siem_cold_vault",
    "security_alerts",
    "fbr_pos_logs",
    "peca_forensic_logs",
    "source_envelopes_siem",
    "source_envelopes_peca",
    "source_envelopes_fbr",
    "csv_uploads",
    "analysis_results",
)

COLLECTION_DATE_FIELDS = {
    "logs": ("_retention_ts", "timestamp"),
    "siem_cold_vault": ("_expire_at", "timestamp", "ingested_at"),
    "security_alerts": ("_expire_at", "timestamp", "ingested_at", "_retention_ts"),
    "fbr_pos_logs": ("_expire_at", "timestamp", "ingested_at", "_retention_ts"),
    "peca_forensic_logs": ("_expire_at", "timestamp", "ingested_at", "_retention_ts"),
    "source_envelopes_siem": ("timestamp", "received_at"),
    "source_envelopes_peca": ("timestamp", "received_at"),
    "source_envelopes_fbr": ("timestamp", "received_at"),
    "csv_uploads": ("_retention_ts", "timestamp", "uploaded_at"),
    "analysis_results": ("uploaded_at", "created_at", "timestamp"),
}

EXPLICIT_EXPIRY_FIELDS = {"_expire_at"}
COMPLIANCE_PACK_BY_COLLECTION = {
    "peca_forensic_logs": "peca_forensic",
    "source_envelopes_peca": "peca_forensic",
}
COMPLIANCE_HOT_RETENTION_DAYS = {
    collection_name: int(COMPLIANCE_CATALOG[pack_name]["retention"]["local_hot_days"])
    for collection_name, pack_name in COMPLIANCE_PACK_BY_COLLECTION.items()
}
COMPLIANCE_VAULT_RETENTION_DAYS = {
    collection_name: int(COMPLIANCE_CATALOG[pack_name]["retention"]["vault_days"])
    for collection_name, pack_name in COMPLIANCE_PACK_BY_COLLECTION.items()
    if COMPLIANCE_CATALOG[pack_name]["retention"]["vault_days"] is not None
}
DEFAULT_SIEM_HOT_RETENTION_DAYS = max(1, min(7, int(os.getenv("SIEM_HOT_RETENTION_DAYS", "7"))))
DEFAULT_RAW_LOG_HOT_RETENTION_DAYS = max(1, min(7, int(os.getenv("RAW_LOG_HOT_RETENTION_DAYS", "7"))))
HOT_RETENTION_DAYS_BY_COLLECTION = {
    **COMPLIANCE_HOT_RETENTION_DAYS,
    "fbr_pos_logs": int(COMPLIANCE_CATALOG["fbr_pos"]["retention"]["local_hot_days"]),
    "source_envelopes_fbr": int(
        COMPLIANCE_CATALOG["fbr_pos"]["retention"]["local_hot_days"]
    ),
    "siem_cold_vault": DEFAULT_SIEM_HOT_RETENTION_DAYS,
    "security_alerts": DEFAULT_SIEM_HOT_RETENTION_DAYS,
    "logs": DEFAULT_RAW_LOG_HOT_RETENTION_DAYS,
    "source_envelopes_siem": DEFAULT_SIEM_HOT_RETENTION_DAYS,
}

ARCHIVE_RETENTION_CLASS_BY_COLLECTION = {
    "fbr_pos_logs": "GENERAL",
    "peca_forensic_logs": "GENERAL",
    "siem_cold_vault": "SIEM",
    "security_alerts": "SIEM",
    "logs": "SIEM",
    "source_envelopes_siem": "SIEM",
    "source_envelopes_peca": "GENERAL",
    "source_envelopes_fbr": "GENERAL",
}


def _archive_retention_class(collection_name: str) -> str:
    return ARCHIVE_RETENTION_CLASS_BY_COLLECTION.get(collection_name, "GENERAL")


def _archive_routing_key(collection_name: str, vault_retention_days: int | None = None) -> str:
    retention_class = _archive_retention_class(collection_name)
    if retention_class in {"SIEM", "GENERAL"} and vault_retention_days:
        return f"{retention_class}_{max(1, int(vault_retention_days))}"
    return retention_class


def _archive_container_name(
    collection_name: str,
    vault_retention_days: int | None = None,
) -> str:
    retention_class = _archive_retention_class(collection_name)
    routing_key = _archive_routing_key(collection_name, vault_retention_days)
    exact = os.getenv(f"AZURE_STORAGE_CONTAINER_{routing_key}", "").strip()
    class_fallback = os.getenv(f"AZURE_STORAGE_CONTAINER_{retention_class}", "").strip()
    return exact or class_fallback or os.getenv(
        "AZURE_STORAGE_CONTAINER", "warsoc-cold-storage"
    ).strip()


def _container_policy_setting(
    collection_name: str,
    setting: str,
    default: str,
    vault_retention_days: int | None = None,
) -> str:
    retention_class = _archive_retention_class(collection_name)
    routing_key = _archive_routing_key(collection_name, vault_retention_days)
    exact = os.getenv(f"AZURE_CONTAINER_IMMUTABILITY_{setting}_{routing_key}", "").strip()
    class_fallback = os.getenv(
        f"AZURE_CONTAINER_IMMUTABILITY_{setting}_{retention_class}", ""
    ).strip()
    return exact or class_fallback or os.getenv(
        f"AZURE_CONTAINER_IMMUTABILITY_{setting}", default
    )


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


async def _ensure_blob_immutability(blob_client, required_until: datetime) -> dict:
    properties = await blob_client.get_blob_properties()
    status = _blob_immutability_status(properties, required_until)
    if status["verified"]:
        return status
    if not _environment_flag("AZURE_BLOB_IMMUTABILITY_AUTO_LOCK", default=False):
        raise RuntimeError(
            "Azure blob is not protected by a legal hold or a locked immutability "
            f"policy through {required_until.isoformat()}"
        )
    await blob_client.set_immutability_policy(
        ImmutabilityPolicy(
            expiry_time=required_until,
            policy_mode=BlobImmutabilityPolicyMode.LOCKED,
        )
    )
    return await _verify_blob_immutability(blob_client, required_until)


async def _verify_container_immutability_capability(
    container_client,
    collection_name: str = "",
    vault_retention_days: int | None = None,
) -> dict:
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
        configured_days = int(
            _container_policy_setting(
                collection_name,
                "DAYS",
                "0",
                vault_retention_days,
            )
        )
    except ValueError as exc:
        raise RuntimeError("AZURE_CONTAINER_IMMUTABILITY_DAYS must be an integer") from exc
    return {
        "has_immutability_policy": has_policy,
        "has_legal_hold": has_legal_hold,
        "immutable_storage_with_versioning_enabled": version_immutability,
        "declared_locked": _container_policy_setting(
            collection_name,
            "LOCKED",
            "false",
            vault_retention_days,
        ).strip().lower() in {"1", "true", "yes", "on"},
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
    query = {"tenant_id": tenant_id, "$or": clauses}
    if collection_name in {"fbr_pos_logs", "source_envelopes_fbr"}:
        # Existing records from the retired tax-period model are deliberately
        # left untouched. Only evidence created under the active tenant model
        # can be moved and deleted by this archiver.
        query["retention_model"] = FBR_ACTIVE_RETENTION_MODEL
    if collection_name in {"peca_forensic_logs", "source_envelopes_peca"}:
        # Unmarked PECA evidence predates the tenant-entitlement model. It may
        # already carry a longer retention obligation or reference a locked
        # Azure object, so only explicitly versioned new evidence is eligible.
        query["retention_model"] = PECA_ACTIVE_RETENTION_MODEL
    if collection_name.startswith("source_envelopes_"):
        query["dispatch_complete"] = True
    return query


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


def _batch_vault_retention(
    collection_name: str,
    documents: list[dict],
    tenant_retention_days: int,
) -> tuple[int, str | None]:
    return _effective_vault_retention_days(collection_name, tenant_retention_days), None


def _archive_cohorts(collection_name: str, documents: list[dict]) -> list[list[dict]]:
    return [documents] if documents else []


def _bounded_archive_documents(documents: list[dict], max_encoded_bytes: int) -> list[dict]:
    selected = []
    encoded_bytes = 2
    for document in documents:
        document_bytes = len(
            json.dumps(document, default=_json_default, separators=(",", ":")).encode("utf-8")
        )
        if selected and encoded_bytes + document_bytes + 1 > max_encoded_bytes:
            break
        if document_bytes + 2 > max_encoded_bytes:
            raise RuntimeError("A single archive document exceeds ARCHIVE_BATCH_MAX_BYTES")
        selected.append(document)
        encoded_bytes += document_bytes + 1
    return selected


async def _active_holds_for_batch(db, tenant_id: str, collection_name: str, docs: list[dict]) -> list[dict]:
    event_uids = [str(doc.get("event_uid")) for doc in docs if doc.get("event_uid")]
    scope_queries: list[dict] = [
        {"scope_type": "TENANT"},
        {"scope_type": "COLLECTION", "collection": collection_name},
    ]
    if event_uids:
        scope_queries.append(
            {
                "scope_type": "EVENT",
                "collection": collection_name,
                "event_uid": {"$in": event_uids},
            }
        )
    holds = await db["legal_holds"].find(
        {
            "tenant_id": tenant_id,
            "status": {"$in": ["ACTIVE", "PENDING_RELEASE"]},
            "$or": scope_queries,
        },
        {"_id": 1, "hold_id": 1, "tenant_id": 1, "scope_type": 1, "collection": 1, "event_uid": 1},
    ).limit(500).to_list(500)
    return holds


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
    container_name: str | None = None,
):
    document_ids = [doc["_id"] for doc in docs if "_id" in doc]
    if not document_ids:
        return 0

    json_dump = json.dumps(docs, default=_json_default, separators=(",", ":")).encode("utf-8")
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
    vault_retention_days, retention_state = _batch_vault_retention(
        collection_name,
        docs,
        tenant_retention_days,
    )
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
                "retention_state": str(retention_state or "configured"),
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
            json_status = await _ensure_blob_immutability(json_blob, retain_until)
            hash_status = await _ensure_blob_immutability(hash_blob, retain_until)
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
    archived_at = datetime.now(timezone.utc)
    resolved_container_name = container_name or _archive_container_name(
        collection_name,
        vault_retention_days,
    )
    archive_doc = {
        "tenant_id": tenant_id,
        "collection": collection_name,
        "container_name": resolved_container_name,
        "blob_name": json_blob_name,
        "hash_blob_name": hash_blob_name,
        "archive_key": archive_key,
        "run_id": run_id,
        "batch_number": batch_number,
        "sha256": sha256_hash,
        "blob_size_bytes": len(json_dump),
        "hash_blob_size_bytes": len(hash_payload),
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
        "retention_state": retention_state,
        "automatic_final_expiry_allowed": retention_state != "UNRESOLVED",
        "immutability": immutability_status,
        "created_at": archived_at,
        "status": "archived",
    }
    ledger_result = await db["storage_archives"].update_one(
        {
            "tenant_id": tenant_id,
            "collection": collection_name,
            "archive_key": archive_key,
        },
        {"$setOnInsert": archive_doc},
        upsert=True,
    )
    if ledger_result.upserted_id is not None:
        retention_class = _archive_retention_class(collection_name)
        try:
            await db["archive_storage_daily"].update_one(
                {
                    "tenant_id": tenant_id,
                    "day": f"{archived_at:%Y-%m-%d}",
                    "retention_class": retention_class,
                },
                {
                    "$setOnInsert": {
                        "tenant_id": tenant_id,
                        "day": f"{archived_at:%Y-%m-%d}",
                        "retention_class": retention_class,
                        "created_at": archived_at,
                    },
                    "$inc": {
                        "archived_bytes": len(json_dump),
                        "hash_bytes": len(hash_payload),
                        "archive_blobs": 1,
                        "documents": len(document_ids),
                    },
                    "$set": {"updated_at": archived_at},
                },
                upsert=True,
            )
        except Exception:
            # The immutable archive ledger remains the billing source of truth.
            # A derived daily rollup must never block hot-data cleanup after the
            # Azure blob and its ledger record have been committed.
            logger.exception(
                "Unable to update archive storage rollup for %s/%s/%s",
                tenant_id,
                collection_name,
                archive_key,
            )

    fence_owner = f"archive-delete:{run_id}:{collection_name}:{archive_key}"
    if not await acquire_retention_fence(db, tenant_id, fence_owner):
        logger.warning("Archive delete fence is busy for tenant %s; preserving hot records.", tenant_id)
        return 0
    try:
        active_holds = await _active_holds_for_batch(
            db,
            tenant_id,
            collection_name,
            docs,
        )
        if active_holds:
            archive_record = await db["storage_archives"].find_one(
                {
                    "tenant_id": tenant_id,
                    "collection": collection_name,
                    "archive_key": archive_key,
                }
            )
            if not archive_record:
                raise RuntimeError("Archive ledger disappeared before legal-hold protection")
            try:
                for hold in active_holds:
                    await protect_archive_for_hold(
                        db,
                        None,
                        hold,
                        archive_record,
                        container_client=container_client,
                    )
            except Exception as exc:
                await db["storage_archives"].update_one(
                    {"_id": archive_record["_id"]},
                    {
                        "$set": {
                            "status": "archive_hold_protection_failed",
                            "legal_hold_error": type(exc).__name__,
                            "hot_delete_blocked_at": datetime.now(timezone.utc),
                        }
                    },
                )
                raise
            active_hold_ids = sorted(
                str(hold.get("hold_id") or hold.get("_id")) for hold in active_holds
            )
            await db["storage_archives"].update_one(
                {
                    "tenant_id": tenant_id,
                    "collection": collection_name,
                    "archive_key": archive_key,
                },
                {
                    "$set": {
                        "status": "archived_hot_preserved_hold",
                        "active_hold_ids": active_hold_ids,
                        "hot_delete_blocked_at": datetime.now(timezone.utc),
                    }
                },
            )
            logger.warning(
                "Archived %s.%s batch %s but preserved hot records due to active hold %s.",
                tenant_id,
                collection_name,
                batch_number,
                active_hold_ids,
            )
            return 0

        delete_result = await db[collection_name].delete_many({
            "tenant_id": tenant_id,
            "_id": {"$in": document_ids},
        })
    finally:
        await release_retention_fence(db, tenant_id, fence_owner)
    await db["storage_archives"].update_one(
        {
            "tenant_id": tenant_id,
            "collection": collection_name,
            "archive_key": archive_key,
        },
        {
            "$set": {
                "status": "archived_hot_deleted",
                "hot_deleted_at": datetime.now(timezone.utc),
                "hot_deleted_count": delete_result.deleted_count,
            },
            "$unset": {
                "active_hold_ids": "",
                "hot_delete_blocked_at": "",
            },
        },
    )
    logger.info(
        "Archived %s.%s batch %s to %s/%s and deleted %s hot records.",
        tenant_id,
        collection_name,
        batch_number,
        resolved_container_name,
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

    mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    db_name = os.getenv("MONGODB_DB_NAME", "warsoc_db")
    archive_batch_size = max(1, min(int(os.getenv("ARCHIVE_BATCH_SIZE", "100")), 500))
    archive_fetch_size = min(archive_batch_size, 25)
    archive_batch_max_bytes = max(
        1024 * 1024,
        min(int(os.getenv("ARCHIVE_BATCH_MAX_BYTES", str(32 * 1024 * 1024))), 64 * 1024 * 1024),
    )
    archive_lead_days = int(os.getenv("ARCHIVE_LEAD_DAYS", "1"))
    collections_to_archive = _parse_archive_collections()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "_" + uuid.uuid4().hex[:8]

    mongo_client = AsyncIOMotorClient(mongo_uri)
    blob_service_client = None

    try:
        db = mongo_client[db_name]
        blob_service_client = BlobServiceClient.from_connection_string(azure_conn_str)
        container_contexts = {}

        async def get_container_context(
            collection_name: str,
            tenant_retention_days: int,
            required_vault_days: int | None = None,
        ):
            retention_class = _archive_retention_class(collection_name)
            vault_retention_days = required_vault_days or _effective_vault_retention_days(
                collection_name, tenant_retention_days
            )
            routing_key = _archive_routing_key(collection_name, vault_retention_days)
            container_name = _archive_container_name(collection_name, vault_retention_days)
            context_key = (container_name, routing_key)
            if context_key in container_contexts:
                return container_contexts[context_key]

            container_client = blob_service_client.get_container_client(container_name)
            if not await container_client.exists():
                await container_client.create_container()
                logger.info("Created Azure container: %s", container_name)
            container_immutability = None
            if _environment_flag("AZURE_IMMUTABILITY_REQUIRED", default=False):
                container_immutability = await _verify_container_immutability_capability(
                    container_client,
                    collection_name,
                    vault_retention_days,
                )
            context = (container_name, container_client, container_immutability)
            container_contexts[context_key] = context
            return context

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
                    candidates = await db[collection_name].find(query).sort("_id", 1).limit(archive_fetch_size).to_list(length=archive_fetch_size)
                    docs = _bounded_archive_documents(candidates, archive_batch_max_bytes)
                    if not docs:
                        break

                    deleted_in_iteration = 0
                    try:
                        if collection_name == "security_alerts":
                            # Archive is allowed to remove alert evidence only
                            # after its mutable workflow state has been projected.
                            # Any projection failure aborts the batch, preserving
                            # the original MongoDB documents for a later retry.
                            for alert in docs:
                                await project_security_incident(db, alert)
                        for cohort_docs in _archive_cohorts(collection_name, docs):
                            required_vault_days, _ = _batch_vault_retention(
                                collection_name,
                                cohort_docs,
                                retention_days,
                            )
                            container_name, container_client, container_immutability = await get_container_context(
                                collection_name,
                                retention_days,
                                required_vault_days,
                            )
                            deleted_in_iteration += await _archive_batch(
                                container_client,
                                db,
                                tenant_id,
                                collection_name,
                                cohort_docs,
                                run_id,
                                batch_number,
                                retention_days,
                                container_immutability,
                                container_name,
                            )
                            batch_number += 1
                    except Exception as exc:
                        logger.error(
                            "Failed to archive %s for tenant %s. Records were not deleted. Error: %s",
                            collection_name,
                            tenant_id,
                            exc,
                        )
                        break

                    if deleted_in_iteration == 0:
                        break

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

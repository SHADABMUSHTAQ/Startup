import asyncio
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

from azure.storage.blob.aio import BlobServiceClient
from bson import ObjectId
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

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


def _date_clauses(field_name: str, retention_cutoff: datetime, expiry_cutoff: datetime) -> list[dict]:
    cutoff = expiry_cutoff if field_name in EXPLICIT_EXPIRY_FIELDS else retention_cutoff
    return [
        {field_name: {"$lte": cutoff}},
        {field_name: {"$lte": cutoff.isoformat()}},
    ]


def _archive_query(tenant_id: str, collection_name: str, retention_cutoff: datetime, expiry_cutoff: datetime) -> dict:
    fields = COLLECTION_DATE_FIELDS.get(collection_name, ("timestamp",))
    clauses: list[dict] = []
    for field_name in fields:
        clauses.extend(_date_clauses(field_name, retention_cutoff, expiry_cutoff))
    return {"tenant_id": tenant_id, "$or": clauses}


def _blob_base_name(tenant_id: str, collection_name: str, run_id: str, batch_number: int) -> str:
    now = datetime.now(timezone.utc)
    return (
        f"{tenant_id}/{collection_name}/"
        f"year={now:%Y}/month={now:%m}/day={now:%d}/"
        f"archive_{collection_name}_{run_id}_batch_{batch_number:04d}"
    )


async def _archive_batch(container_client, db, tenant_id: str, collection_name: str, docs: list[dict], run_id: str, batch_number: int):
    document_ids = [doc["_id"] for doc in docs if "_id" in doc]
    if not document_ids:
        return 0

    json_dump = json.dumps(docs, indent=2, default=_json_default).encode("utf-8")
    sha256_hash = hashlib.sha256(json_dump).hexdigest()

    base_name = _blob_base_name(tenant_id, collection_name, run_id, batch_number)
    json_blob_name = f"{base_name}.json"
    hash_blob_name = f"{base_name}.sha256"

    json_blob = container_client.get_blob_client(json_blob_name)
    await json_blob.upload_blob(json_dump, overwrite=False)

    hash_blob = container_client.get_blob_client(hash_blob_name)
    await hash_blob.upload_blob(sha256_hash.encode("utf-8"), overwrite=False)

    timestamps = [doc.get("timestamp") or doc.get("ingested_at") or doc.get("uploaded_at") for doc in docs]
    archive_doc = {
        "tenant_id": tenant_id,
        "collection": collection_name,
        "blob_name": json_blob_name,
        "hash_blob_name": hash_blob_name,
        "sha256": sha256_hash,
        "document_count": len(document_ids),
        "first_document_id": str(document_ids[0]),
        "last_document_id": str(document_ids[-1]),
        "oldest_timestamp": min((str(ts) for ts in timestamps if ts is not None), default=None),
        "newest_timestamp": max((str(ts) for ts in timestamps if ts is not None), default=None),
        "created_at": datetime.now(timezone.utc),
        "status": "archived",
    }
    await db["storage_archives"].insert_one(archive_doc)

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
        logger.error("CRITICAL: AZURE_STORAGE_CONNECTION_STRING is missing. Archiver cannot run.")
        return

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

        cursor = db.tenants.find({})
        async for tenant in cursor:
            tenant_id = tenant.get("tenant_id")
            retention_days = int(tenant.get("retention_days", 30) or 30)
            if not tenant_id:
                continue

            now = datetime.now(timezone.utc)
            retention_cutoff = now - timedelta(days=retention_days)
            expiry_cutoff = now + timedelta(days=archive_lead_days)
            logger.info(
                "Processing tenant %s with retention_days=%s archive_lead_days=%s",
                tenant_id,
                retention_days,
                archive_lead_days,
            )

            for collection_name in collections_to_archive:
                query = _archive_query(tenant_id, collection_name, retention_cutoff, expiry_cutoff)
                batch_number = 1

                while True:
                    docs = await db[collection_name].find(query).sort("_id", 1).limit(archive_batch_size).to_list(length=archive_batch_size)
                    if not docs:
                        break

                    try:
                        await _archive_batch(container_client, db, tenant_id, collection_name, docs, run_id, batch_number)
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


if __name__ == "__main__":
    asyncio.run(run_archiver())

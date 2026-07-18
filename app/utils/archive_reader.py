import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Iterable, Optional

from azure.storage.blob.aio import BlobServiceClient


logger = logging.getLogger("archive_reader")


def _coerce_dt(value) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _event_matches(doc: dict, event_id: Optional[str]) -> bool:
    if event_id is None:
        return True
    expected = str(event_id).strip()
    actual = str(doc.get("event_id") or "").strip()
    return actual == expected


def _event_uid_matches(
    doc: dict,
    event_uid: Optional[str],
    event_uids: Optional[Iterable[str]] = None,
) -> bool:
    expected_values = {
        str(value).strip()
        for value in ([event_uid] if event_uid is not None else [])
        + list(event_uids or [])
        if str(value or "").strip()
    }
    if not expected_values:
        return True
    candidates = (
        doc.get("event_uid"),
        (doc.get("raw_event_data") or {}).get("event_uid") if isinstance(doc.get("raw_event_data"), dict) else None,
        (doc.get("raw_data") or {}).get("event_uid") if isinstance(doc.get("raw_data"), dict) else None,
    )
    return any(str(candidate or "").strip() in expected_values for candidate in candidates)


def _document_id_matches(doc: dict, document_id: Optional[str]) -> bool:
    if document_id is None:
        return True
    return str(doc.get("_id") or "").strip() == str(document_id).strip()


def _search_matches(doc: dict, search_term: Optional[str]) -> bool:
    if not search_term:
        return True
    expected = str(search_term).strip().lower()
    if not expected:
        return True
    processed = doc.get("processed_data") if isinstance(doc.get("processed_data"), dict) else {}
    candidates = (
        doc.get("event_uid"),
        doc.get("alert_uid"),
        doc.get("event_id"),
        doc.get("source_ip"),
        doc.get("ip"),
        doc.get("user"),
        doc.get("title"),
        doc.get("message"),
        doc.get("raw_message"),
        doc.get("event_id_meaning"),
        doc.get("engine_source"),
        doc.get("severity"),
        processed.get("source_network_address"),
    )
    return any(expected in str(candidate or "").lower() for candidate in candidates)


def _document_identity(doc: dict) -> str:
    for field in ("event_uid", "alert_uid", "_id"):
        value = str(doc.get(field) or "").strip()
        if value:
            return f"{field}:{value}"
    return hashlib.sha256(
        json.dumps(doc, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _time_matches(doc: dict, start_dt: Optional[datetime], end_dt: Optional[datetime]) -> bool:
    if not start_dt and not end_dt:
        return True
    timestamp = _coerce_dt(doc.get("timestamp") or doc.get("ingested_at"))
    if not timestamp:
        return False
    if start_dt and timestamp < start_dt:
        return False
    if end_dt and timestamp > end_dt:
        return False
    return True


def _sort_key(doc: dict) -> datetime:
    return _coerce_dt(doc.get("timestamp") or doc.get("ingested_at")) or datetime.min.replace(tzinfo=timezone.utc)


async def count_archived_documents(
    db,
    *,
    tenant_id: str,
    collections: Iterable[str],
) -> tuple[int, bool]:
    """Count archived rows from the local ledger without downloading Azure blobs.

    The count is exact only when every matching archive ledger entry has the
    ``document_count`` field written by the current archiver.
    """
    collection_list = [str(name) for name in collections if name]
    if not tenant_id or not collection_list:
        return 0, True

    ledger = db["storage_archives"]
    base_query = {
        "tenant_id": tenant_id,
        "collection": {"$in": collection_list},
        "status": "archived",
    }
    try:
        missing_count = await ledger.count_documents(
            {**base_query, "document_count": {"$exists": False}}
        )
        cursor = ledger.aggregate(
            [
                {"$match": base_query},
                {"$group": {"_id": None, "total": {"$sum": "$document_count"}}},
            ]
        )
        rows = await cursor.to_list(length=1)
    except Exception as exc:
        logger.warning("Unable to count archived documents from the ledger: %s", exc)
        return 0, False

    total = int(rows[0].get("total") or 0) if rows else 0
    return total, missing_count == 0


async def fetch_archived_documents(
    db,
    *,
    tenant_id: str,
    collections: Iterable[str],
    start_dt: Optional[datetime] = None,
    end_dt: Optional[datetime] = None,
    event_id: Optional[str] = None,
    event_uid: Optional[str] = None,
    event_uids: Optional[Iterable[str]] = None,
    document_id: Optional[str] = None,
    search_term: Optional[str] = None,
    limit: int = 500,
) -> tuple[list[dict], int]:
    """
    Read bounded archived evidence from Azure using the storage_archives ledger.

    Missing Azure config intentionally returns no archived rows so hot paths keep
    working in local/dev environments.
    """
    connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
    container_name = os.getenv("AZURE_STORAGE_CONTAINER", "warsoc-cold-storage")
    if not connection_string or not container_name:
        return [], 0

    collection_list = [str(name) for name in collections if name]
    if not tenant_id or not collection_list:
        return [], 0

    try:
        max_blobs = max(1, min(500, int(os.getenv("ARCHIVE_READ_MAX_BLOBS", "100"))))
    except ValueError:
        max_blobs = 100
    archive_query = {
        "tenant_id": tenant_id,
        "collection": {"$in": collection_list},
        "status": "archived",
    }
    ledger_filters = []
    if start_dt:
        ledger_filters.append({"$or": [{"newest_at": {"$gte": start_dt}}, {"newest_at": {"$exists": False}}]})
    if end_dt:
        ledger_filters.append({"$or": [{"oldest_at": {"$lte": end_dt}}, {"oldest_at": {"$exists": False}}]})
    if event_id is not None:
        expected_event_id = str(event_id).strip()
        ledger_filters.append({"$or": [{"event_ids": expected_event_id}, {"event_ids": {"$exists": False}}]})
    expected_event_uids = {
        str(value).strip()
        for value in ([event_uid] if event_uid is not None else [])
        + list(event_uids or [])
        if str(value or "").strip()
    }
    if expected_event_uids:
        ledger_filters.append(
            {
                "$or": [
                    {"event_uids": {"$in": sorted(expected_event_uids)}},
                    {"event_uids": {"$exists": False}},
                ]
            }
        )
    if document_id is not None:
        expected_document_id = str(document_id).strip()
        ledger_filters.append({
            "$or": [
                {
                    "first_document_id": {"$lte": expected_document_id},
                    "last_document_id": {"$gte": expected_document_id},
                },
                {"first_document_id": {"$exists": False}},
            ]
        })
    if ledger_filters:
        archive_query["$and"] = ledger_filters
    cursor = db["storage_archives"].find(archive_query).sort("created_at", -1).limit(max_blobs)
    archive_entries = await cursor.to_list(length=max_blobs)
    if not archive_entries:
        return [], 0

    client = BlobServiceClient.from_connection_string(connection_string)
    docs: list[dict] = []
    identities: set[str] = set()
    unfiltered_page = not any(
        (
            start_dt,
            end_dt,
            event_id,
            event_uid,
            tuple(event_uids or ()),
            document_id,
            search_term,
        )
    )
    try:
        container = client.get_container_client(container_name)
        for entry in archive_entries:
            blob_name = entry.get("blob_name")
            collection_name = entry.get("collection")
            if not blob_name or not collection_name:
                continue
            try:
                downloader = await container.get_blob_client(blob_name).download_blob()
                raw = await downloader.readall()
            except Exception as exc:
                logger.warning("Unable to read archive blob %s: %s", blob_name, exc)
                continue
            expected_hash = str(entry.get("sha256") or "").strip().lower()
            if expected_hash and hashlib.sha256(raw).hexdigest().lower() != expected_hash:
                logger.error("Archive integrity verification failed for blob %s", blob_name)
                continue
            try:
                archived_batch = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                logger.error("Archive blob %s contains invalid JSON: %s", blob_name, exc)
                continue
            if not isinstance(archived_batch, list):
                continue
            for doc in archived_batch:
                if not isinstance(doc, dict):
                    continue
                if doc.get("tenant_id") != tenant_id:
                    continue
                if not _event_matches(doc, event_id):
                    continue
                if not _event_uid_matches(doc, event_uid, expected_event_uids):
                    continue
                if not _document_id_matches(doc, document_id):
                    continue
                if not _search_matches(doc, search_term):
                    continue
                if not _time_matches(doc, start_dt, end_dt):
                    continue
                doc["_archived"] = True
                doc["_source_collection"] = collection_name
                doc["_archive_blob_name"] = blob_name
                docs.append(doc)
                identities.add(_document_identity(doc))

            # Ledger rows are newest-first. For an unfiltered page, once the
            # requested number of unique records has been recovered, older
            # blobs cannot improve the page and only add Azure latency/cost.
            if unfiltered_page and len(identities) >= max(1, limit):
                break
    finally:
        await client.close()

    deduped = {_document_identity(doc): doc for doc in docs}
    ordered_docs = sorted(deduped.values(), key=_sort_key, reverse=True)
    total = len(ordered_docs)
    return ordered_docs[:limit], total

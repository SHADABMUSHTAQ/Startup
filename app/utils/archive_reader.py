import logging
from datetime import datetime
from typing import Iterable, Optional


logger = logging.getLogger("archive_reader")


def archive_ledger_query(
    *,
    tenant_id: str,
    collections: Iterable[str],
    start_dt: Optional[datetime] = None,
    end_dt: Optional[datetime] = None,
) -> dict:
    collection_list = sorted({str(name).strip() for name in collections if str(name).strip()})
    if not tenant_id or not collection_list:
        return {"_id": {"$exists": False}}

    query: dict = {
        "tenant_id": tenant_id,
        "collection": {"$in": collection_list},
        "status": "archived",
    }
    overlap_filters = []
    if start_dt is not None:
        overlap_filters.append(
            {"$or": [{"newest_at": {"$gte": start_dt}}, {"newest_at": {"$exists": False}}]}
        )
    if end_dt is not None:
        overlap_filters.append(
            {"$or": [{"oldest_at": {"$lte": end_dt}}, {"oldest_at": {"$exists": False}}]}
        )
    if overlap_filters:
        query["$and"] = overlap_filters
    return query


async def count_archived_documents(
    db,
    *,
    tenant_id: str,
    collections: Iterable[str],
) -> tuple[int, bool]:
    """Count archived rows from MongoDB metadata without touching Azure bytes."""
    query = archive_ledger_query(tenant_id=tenant_id, collections=collections)
    try:
        missing_count = await db["storage_archives"].count_documents(
            {**query, "document_count": {"$exists": False}}
        )
        rows = await db["storage_archives"].aggregate(
            [
                {"$match": query},
                {"$group": {"_id": None, "total": {"$sum": "$document_count"}}},
            ]
        ).to_list(length=1)
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
    """Return archive metadata only.

    API processes must never download or deserialize cold evidence. Callers keep
    their hot-data behavior, while the total lets the UI indicate that historical
    records exist and require an asynchronous retrieval request.
    """
    del event_id, event_uid, event_uids, document_id, search_term, limit
    query = archive_ledger_query(
        tenant_id=tenant_id,
        collections=collections,
        start_dt=start_dt,
        end_dt=end_dt,
    )
    try:
        rows = await db["storage_archives"].aggregate(
            [
                {"$match": query},
                {"$group": {"_id": None, "total": {"$sum": "$document_count"}}},
            ]
        ).to_list(length=1)
    except Exception as exc:
        logger.warning("Unable to resolve archived document metadata: %s", exc)
        return [], 0

    total = int(rows[0].get("total") or 0) if rows else 0
    return [], total

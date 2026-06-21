import re as _re
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from datetime import datetime, timedelta, timezone
from app.database import get_db
from app.routes.auth import get_current_user
from app.utils.rbac import RoleChecker

router = APIRouter()
RAW_RETENTION_ANCHOR_FIELD = "_retention_ts"


def _serialize_docs(docs: list[dict]) -> list[dict]:
    final_results = []
    for doc in docs:
        doc["_id"] = str(doc["_id"])
        doc.pop(RAW_RETENTION_ANCHOR_FIELD, None)
        final_results.append(doc)
    return final_results


@router.get("/status")
async def agent_status(
    request: Request,
    current_user=Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "analyst"])),
):
    """Return last-seen heartbeat status for all agents in the current tenant."""
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Unauthorized tenant scope")

    redis_client = getattr(request.app.state, "redis", None)
    if redis_client is None:
        return {"status": "success", "data": []}

    try:
        pattern = f"status:{tenant_id}:*"
        cursor = 0
        keys = []

        while True:
            cursor, batch = await redis_client.scan(cursor=cursor, match=pattern, count=200)
            if batch:
                keys.extend(batch)
            if cursor == 0:
                break

        if not keys:
            return {"status": "success", "data": []}

        values = await redis_client.mget(keys)
        data = []
        for key, last_seen in zip(keys, values):
            key_parts = str(key).split(":", 2)
            if len(key_parts) != 3:
                continue
            data.append({"agent_id": key_parts[2], "last_seen": last_seen})

        data.sort(key=lambda item: item.get("last_seen") or "", reverse=True)
        return {"status": "success", "data": data}
    except Exception as e:
        print(f" Status Fetch Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch agent status")

@router.get("/search")
async def global_search(
    q: str = "", 
    days: str = "", 
    skip: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=500),
    db=Depends(get_db), 
    current_user=Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "analyst"])),
):
    try:
        tenant_id = current_user.get("tenant_id")
        query = {"tenant_id": tenant_id}
        
        # 🕒 1. Time Filter Setup
        cutoff_date = None
        if days and days.isdigit():
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=int(days))
            query["timestamp"] = {"$gte": cutoff_date.isoformat()}
            
        # 🔍 2. Text Search Setup
        if q and q.strip() != "":
            raw_search_term = q.strip()
            exact_query = {
                "tenant_id": tenant_id,
                "$or": [
                    {"event_uid": raw_search_term},
                    {"alert_uid": raw_search_term},
                    {"source_ip": raw_search_term},
                    {"ip": raw_search_term},
                    {"processed_data.source_network_address": raw_search_term},
                    {"raw_event_data.event_uid": raw_search_term},
                    {"raw_data.event_uid": raw_search_term},
                    {"raw_data.source_ip": raw_search_term},
                    {"raw_data.ip": raw_search_term},
                    {"raw_data.processed_data.source_network_address": raw_search_term},
                ],
            }
            exact_docs = []
            for coll_name in ("siem_cold_vault", "security_alerts", "csv_uploads"):
                cursor = db[coll_name].find(exact_query).sort([("timestamp", -1), ("_id", -1)]).limit(limit)
                exact_docs.extend(await cursor.to_list(length=limit))
                if len(exact_docs) >= limit:
                    break

            if exact_docs:
                final_results = _serialize_docs(exact_docs[:limit])
                return {
                    "status": "success",
                    "data": final_results,
                    "pagination": {
                        "count": len(final_results),
                        "skip": skip,
                        "limit": limit,
                    },
                }

            search_term = _re.escape(raw_search_term)
            query["$or"] = [
                {"event_uid": {"$regex": search_term, "$options": "i"}},
                {"alert_uid": {"$regex": search_term, "$options": "i"}},
                {"event_id": {"$regex": search_term, "$options": "i"}},
                {"source_ip": {"$regex": search_term, "$options": "i"}},
                {"ip": {"$regex": search_term, "$options": "i"}},
                {"user": {"$regex": search_term, "$options": "i"}},
                {"message": {"$regex": search_term, "$options": "i"}},
                {"raw_message": {"$regex": search_term, "$options": "i"}},
                {"raw_event_data.event_uid": {"$regex": search_term, "$options": "i"}},
                {"raw_data.event_uid": {"$regex": search_term, "$options": "i"}},
                {"event_id_meaning": {"$regex": search_term, "$options": "i"}},
                {"engine_source": {"$regex": search_term, "$options": "i"}},
                {"severity": {"$regex": search_term, "$options": "i"}}
            ]
        
        #  3. THE MAGIC: Aggregation Pipeline with $unionWith
        pipeline = [
            {"$match": query},
            {
                "$unionWith": {
                    "coll": "csv_uploads",
                    "pipeline": [
                        {"$match": query},
                        {
                            "$addFields": {
                                "source_ip": {"$ifNull": ["$source_ip", "$ip"]},
                                "engine_source": {"$ifNull": ["$engine_source", "CSV-Upload"]}
                            }
                        }
                    ]
                }
            },
            {"$sort": {"timestamp": -1}},
            {"$skip": skip},
            {"$limit": limit}
        ]
        cursor = db["siem_cold_vault"].aggregate(pipeline, maxTimeMS=3000)
        docs = await cursor.to_list(length=limit)
        final_results = _serialize_docs(docs)
            
        return {
            "status": "success",
            "data": final_results,
            "pagination": {
                "count": len(final_results),
                "skip": skip,
                "limit": limit,
            },
        }
        
    except Exception as e:
        print(f" Omni-Search Error: {e}")
        raise HTTPException(status_code=500, detail="Search failed. Please try again.")

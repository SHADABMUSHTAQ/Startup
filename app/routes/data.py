import re as _re
from fastapi import APIRouter, Depends, HTTPException, Request
from datetime import datetime, timedelta, timezone
from app.database import get_db
from app.routes.auth import get_current_user

router = APIRouter()
RAW_RETENTION_ANCHOR_FIELD = "_retention_ts"


@router.get("/status")
async def agent_status(request: Request, current_user=Depends(get_current_user)):
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
        print(f"❌ Status Fetch Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch agent status")

@router.get("/search")
async def global_search(q: str = "", days: str = "", db=Depends(get_db), current_user=Depends(get_current_user)):
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
            search_term = _re.escape(q.strip())
            query["$or"] = [
                {"source_ip": {"$regex": search_term, "$options": "i"}},
                {"ip": {"$regex": search_term, "$options": "i"}},
                {"message": {"$regex": search_term, "$options": "i"}},
                {"raw_message": {"$regex": search_term, "$options": "i"}},
                {"event_id_meaning": {"$regex": search_term, "$options": "i"}},
                {"engine_source": {"$regex": search_term, "$options": "i"}},
                {"severity": {"$regex": search_term, "$options": "i"}}
            ]
        
        # 📥 3. Search in Live Logs (db["logs"])
        cursor = db["logs"].find(query).sort("timestamp", -1)
        logs_docs = await cursor.to_list(length=500)
        
        combined_results = []
        for doc in logs_docs:
            doc["_id"] = str(doc["_id"])
            doc.pop(RAW_RETENTION_ANCHOR_FIELD, None)
            combined_results.append(doc)
            
        # 🚀 4. THE MAGIC: Search INSIDE Uploaded CSV Files (db["csv_uploads"])
        csv_cursor = db["csv_uploads"].find(query).sort("timestamp", -1).limit(500)
        csv_docs = await csv_cursor.to_list(length=500)
        
        for doc in csv_docs:
            doc["_id"] = str(doc["_id"])
            doc.pop(RAW_RETENTION_ANCHOR_FIELD, None)
            # Ensure consistency with live log format
            if "source_ip" not in doc and "ip" in doc:
                doc["source_ip"] = doc["ip"]
            if "engine_source" not in doc:
                doc["engine_source"] = "CSV-Upload"
            combined_results.append(doc)
        
        # 📊 5. Sort & Return the best results
        combined_results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        final_results = combined_results[:500]
        
        return {"count": len(final_results), "results": final_results}
        
    except Exception as e:
        print(f"❌ Omni-Search Error: {e}")
        raise HTTPException(status_code=500, detail="Search failed. Please try again.")
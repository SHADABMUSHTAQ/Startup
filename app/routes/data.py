import re as _re
import json
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
    db=Depends(get_db),
    current_user=Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "analyst"])),
):
    """Return last-seen heartbeat status for all agents in the current tenant."""
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Unauthorized tenant scope")

    redis_client = getattr(request.app.state, "redis", None)

    try:
        tenant = await db["tenants"].find_one(
            {"tenant_id": tenant_id},
            {"_id": 0, "max_agents": 1, "agent_limit": 1},
        )
        tenant = tenant or {}
        max_agents = tenant.get("max_agents", tenant.get("agent_limit"))

        agents = await db["agents"].find(
            {
                "tenant_id": tenant_id,
                "status": {"$ne": "revoked"},
                "public_key": {"$exists": True, "$ne": ""},
            },
            {
                "_id": 0,
                "agent_id": 1,
                "last_seen": 1,
                "version": 1,
                "status": 1,
                "sensor_status": 1,
            },
        ).to_list(length=1000)

        data = []
        for agent in agents:
            agent_id = str(agent.get("agent_id") or "")
            if not agent_id:
                continue
            live_last_seen = (
                await redis_client.get(f"status:{tenant_id}:{agent_id}")
                if redis_client is not None
                else None
            )
            sensor_raw = (
                await redis_client.get(f"warsoc:agent_sensor:{agent_id}")
                if redis_client is not None
                else None
            )
            sensor_status = agent.get("sensor_status") if isinstance(agent.get("sensor_status"), dict) else {}
            if sensor_raw:
                try:
                    sensor_status = json.loads(sensor_raw)
                except Exception:
                    pass

            channels = sensor_status.get("channels") if isinstance(sensor_status, dict) else {}
            channels = channels if isinstance(channels, dict) else {}
            required_channels_ok = all(
                str((channels.get(channel) or {}).get("status") or "").lower() == "ok"
                for channel in ("Security", "System")
            )
            audit_configured = str(sensor_status.get("audit_policy_status") or "").lower() == "configured"
            online = bool(live_last_seen)
            health = "offline"
            if online:
                health = "active" if required_channels_ok and audit_configured else "degraded"

            last_seen = live_last_seen or agent.get("last_seen")
            if isinstance(last_seen, datetime):
                last_seen = last_seen.astimezone(timezone.utc).isoformat()
            data.append(
                {
                    "agent_id": agent_id,
                    "last_seen": last_seen,
                    "version": agent.get("version"),
                    "online": online,
                    "health": health,
                    "sensor_status": sensor_status,
                }
            )

        data.sort(key=lambda item: item.get("last_seen") or "", reverse=True)
        online_count = sum(1 for item in data if item["online"])
        degraded_count = sum(1 for item in data if item["health"] == "degraded")
        telemetry_status = (
            "active" if online_count and degraded_count == 0 else (
                "degraded" if online_count else "offline"
            )
        )
        return {
            "status": "success",
            "tenant_id": tenant_id,
            "max_agents": max_agents,
            "services_healthy": redis_client is not None,
            "endpoint_status": telemetry_status,
            "data": data,
            "agents_online": online_count,
            "registered_agents": len(data),
            "agents_degraded": degraded_count,
            "telemetry": {
                "status": telemetry_status,
                "last_pulse_at": data[0]["last_seen"] if data else None,
            },
        }
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

import re as _re
import json
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from datetime import datetime, timedelta, timezone
from app.database import get_db
from app.routes.auth import get_current_user
from app.utils.rbac import RoleChecker
from app.utils.archive_reader import fetch_archived_documents
from app.utils.security_policy import effective_agent_limit

router = APIRouter()
RAW_RETENTION_ANCHOR_FIELD = "_retention_ts"


def _serialize_docs(docs: list[dict]) -> list[dict]:
    final_results = []
    for doc in docs:
        doc["_id"] = str(doc["_id"])
        doc.pop(RAW_RETENTION_ANCHOR_FIELD, None)
        doc.pop("_expire_at", None)
        final_results.append(doc)
    return final_results


def _coerce_dt(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _sort_key(doc: dict):
    return (
        _coerce_dt(doc.get("timestamp") or doc.get("ingested_at") or doc.get("uploaded_at"))
        or datetime.min.replace(tzinfo=timezone.utc)
    )


def _time_filter(days: str) -> dict:
    if not days or not str(days).isdigit():
        return {}
    day_count = max(1, min(int(days), 365))
    cutoff = datetime.now(timezone.utc) - timedelta(days=day_count)
    return {
        "$or": [
            {"timestamp": {"$gte": cutoff}},
            {"timestamp": {"$gte": cutoff.isoformat()}},
            {"ingested_at": {"$gte": cutoff}},
            {"ingested_at": {"$gte": cutoff.isoformat()}},
            {"uploaded_at": {"$gte": cutoff}},
            {"uploaded_at": {"$gte": cutoff.isoformat()}},
        ]
    }


def _archive_start(days: str):
    if not days or not str(days).isdigit():
        return None
    day_count = max(1, min(int(days), 365))
    return datetime.now(timezone.utc) - timedelta(days=day_count)


def _exact_search_query(tenant_id: str, term: str) -> dict:
    event_id_terms = [term]
    if term.isdigit():
        event_id_terms.append(int(term))
    return {
        "tenant_id": tenant_id,
        "$or": [
            {"event_uid": term},
            {"alert_uid": term},
            {"event_id": {"$in": event_id_terms}},
            {"source_ip": term},
            {"ip": term},
            {"user": term},
            {"processed_data.source_network_address": term},
            {"raw_event_data.event_uid": term},
            {"raw_data.event_uid": term},
            {"raw_data.source_ip": term},
            {"raw_data.ip": term},
            {"raw_data.processed_data.source_network_address": term},
        ],
    }


def _prefix_search_query(tenant_id: str, term: str) -> dict:
    prefix = f"^{_re.escape(term)}"
    return {
        "tenant_id": tenant_id,
        "$or": [
            {"event_uid": {"$regex": prefix, "$options": "i"}},
            {"alert_uid": {"$regex": prefix, "$options": "i"}},
            {"event_id": {"$regex": prefix, "$options": "i"}},
            {"source_ip": {"$regex": prefix, "$options": "i"}},
            {"ip": {"$regex": prefix, "$options": "i"}},
            {"user": {"$regex": prefix, "$options": "i"}},
            {"message": {"$regex": prefix, "$options": "i"}},
            {"raw_message": {"$regex": prefix, "$options": "i"}},
            {"event_id_meaning": {"$regex": prefix, "$options": "i"}},
            {"engine_source": {"$regex": prefix, "$options": "i"}},
            {"severity": {"$regex": prefix, "$options": "i"}},
        ],
    }


async def _run_safe_global_search(db, tenant_id: str, q: str, days: str, skip: int, limit: int):
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Unauthorized tenant scope")

    search_term = str(q or "").strip()
    if len(search_term) > 128:
        raise HTTPException(status_code=400, detail="Search term is too long.")
    if search_term and len(search_term) < 2:
        raise HTTPException(status_code=400, detail="Search term must be at least 2 characters.")

    time_clause = _time_filter(days)
    docs = []
    collections = ("security_alerts", "siem_cold_vault", "fbr_pos_logs", "peca_forensic_logs", "csv_uploads")
    for coll_name in collections:
        if search_term:
            exact_query = _exact_search_query(tenant_id, search_term)
            if time_clause:
                exact_query = {"$and": [exact_query, time_clause]}
            cursor = db[coll_name].find(exact_query).sort([("timestamp", -1), ("_id", -1)]).limit(limit)
            docs.extend(await cursor.to_list(length=limit))

            if len(search_term) >= 3:
                prefix_query = _prefix_search_query(tenant_id, search_term)
                if time_clause:
                    prefix_query = {"$and": [prefix_query, time_clause]}
                cursor = db[coll_name].find(prefix_query).sort([("timestamp", -1), ("_id", -1)]).limit(limit)
                docs.extend(await cursor.to_list(length=limit))
        else:
            latest_query = {"tenant_id": tenant_id}
            if time_clause:
                latest_query = {"$and": [latest_query, time_clause]}
            cursor = db[coll_name].find(latest_query).sort([("timestamp", -1), ("_id", -1)]).limit(limit)
            docs.extend(await cursor.to_list(length=limit))

    archived_docs, _ = await fetch_archived_documents(
        db,
        tenant_id=tenant_id,
        collections=("security_alerts", "siem_cold_vault", "fbr_pos_logs", "peca_forensic_logs"),
        start_dt=_archive_start(days),
        event_id=search_term if search_term.isdigit() else None,
        search_term=search_term or None,
        limit=skip + limit,
    )
    docs.extend(archived_docs)

    deduped = {str(doc.get("_id")): doc for doc in docs}
    ordered_docs = sorted(deduped.values(), key=_sort_key, reverse=True)
    final_results = _serialize_docs(ordered_docs[skip: skip + limit])
    return {
        "status": "success",
        "data": final_results,
        "pagination": {
            "count": len(final_results),
            "skip": skip,
            "limit": limit,
        },
    }


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
        max_agents = effective_agent_limit(
            tenant.get("max_agents", tenant.get("agent_limit", 10)),
            10,
        )

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
        return await _run_safe_global_search(db, tenant_id, q, days, skip, limit)
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
        
        docs = []
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
        
    except HTTPException:
        raise
    except Exception as e:
        print(f" Omni-Search Error: {e}")
        raise HTTPException(status_code=500, detail="Search failed. Please try again.")

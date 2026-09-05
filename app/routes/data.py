import json
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from datetime import datetime, timedelta, timezone
from app.database import get_db
from app.routes.auth import get_current_user
from app.utils.rbac import RoleChecker
from app.utils.endpoint_health import (
    EVENT_SIGNATURE_STATUS_KEY_PREFIX,
    decode_event_signature_status,
    event_signature_mode,
)
from app.utils.security_policy import effective_agent_limit
from app.utils.collection_profiles import sanitize_profile_report, server_profile_health

router = APIRouter()
RAW_RETENTION_ANCHOR_FIELD = "_retention_ts"
AGENT_ONLINE_WINDOW_SECONDS = 600
DEFAULT_HOT_SEARCH_DAYS = 1
MAX_HOT_SEARCH_DAYS = 7


def _serialize_docs(docs: list[dict]) -> list[dict]:
    final_results = []
    for doc in docs:
        source_collection = str(doc.get("_source_collection") or "")
        if not source_collection:
            source_collection = str(doc.pop("_hot_source_collection", "") or "")
        record_type = {
            "security_alerts": "alert_evidence",
            "siem_cold_vault": "endpoint_event",
            "csv_uploads": "upload_finding",
        }.get(source_collection, "security_record")
        doc["_id"] = str(doc["_id"])
        doc["record_type"] = record_type
        doc["storage_tier"] = "cold_archive" if doc.get("_archived") else "hot"
        doc.pop(RAW_RETENTION_ANCHOR_FIELD, None)
        doc.pop("_expire_at", None)
        doc.pop("_archived", None)
        doc.pop("_source_collection", None)
        doc.pop("_archive_blob_name", None)
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


def _is_fresh_agent_timestamp(value, now=None, max_age_seconds=AGENT_ONLINE_WINDOW_SECONDS):
    parsed = _coerce_dt(value)
    if parsed is None:
        return False
    reference = now or datetime.now(timezone.utc)
    age_seconds = (reference - parsed.astimezone(timezone.utc)).total_seconds()
    return -30 <= age_seconds <= max_age_seconds


def _sort_key(doc: dict):
    return (
        _coerce_dt(doc.get("timestamp") or doc.get("ingested_at") or doc.get("uploaded_at"))
        or datetime.min.replace(tzinfo=timezone.utc)
    )


def _hot_search_days(days: str | int | None) -> int:
    raw = str(days or "").strip().lower()
    if not raw:
        return DEFAULT_HOT_SEARCH_DAYS
    if raw in {"all", "all-time", "all_time"}:
        return MAX_HOT_SEARCH_DAYS
    if not raw.isdigit():
        raise HTTPException(status_code=400, detail="Search window must be between 1 and 7 days.")
    day_count = int(raw)
    if not 1 <= day_count <= MAX_HOT_SEARCH_DAYS:
        raise HTTPException(status_code=400, detail="Search window must be between 1 and 7 days.")
    return day_count


def _time_filter(days: str | int | None, collection_name: str) -> dict:
    day_count = _hot_search_days(days)
    cutoff = datetime.now(timezone.utc) - timedelta(days=day_count)
    time_field = RAW_RETENTION_ANCHOR_FIELD if collection_name == "csv_uploads" else "timestamp"
    return {time_field: {"$gte": cutoff}}


def _indexed_time_sort(time_field: str) -> list[tuple[str, int]]:
    """Return the newest-first sort covered by each tenant/time index."""
    return [(time_field, -1)]


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
            {"agent_id": term},
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

    docs = []
    # This is the operational dashboard search. Compliance evidence stays
    # behind the dedicated compliance routes and their stricter RBAC contract.
    collections = ("security_alerts", "siem_cold_vault", "csv_uploads")
    for coll_name in collections:
        time_clause = _time_filter(days, coll_name)
        sort_field = RAW_RETENTION_ANCHOR_FIELD if coll_name == "csv_uploads" else "timestamp"
        if search_term:
            exact_query = _exact_search_query(tenant_id, search_term)
            exact_query = {"$and": [exact_query, time_clause]}
            # Keep this sort aligned with the tenant/time compound indexes.
            # Adding _id here forces MongoDB to fetch and sort every matching
            # hot record before applying the limit.
            cursor = db[coll_name].find(exact_query).sort(_indexed_time_sort(sort_field)).limit(limit)
            rows = await cursor.to_list(length=limit)
            for row in rows:
                row["_hot_source_collection"] = coll_name
            docs.extend(rows)
        else:
            latest_query = {"$and": [{"tenant_id": tenant_id}, time_clause]}
            cursor = db[coll_name].find(latest_query).sort(_indexed_time_sort(sort_field)).limit(limit)
            rows = await cursor.to_list(length=limit)
            for row in rows:
                row["_hot_source_collection"] = coll_name
            docs.extend(rows)

    deduped = {
        f"{doc.get('_source_collection') or doc.get('_hot_source_collection') or 'unknown'}:{doc.get('_id')}": doc
        for doc in docs
    }
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
    _role: str = Depends(RoleChecker(["admin", "manager", "analyst", "auditor"])),
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
                "asset_class": 1,
                "server_role": 1,
                "environment": 1,
                "criticality": 1,
                "response_mode": 1,
                "server_monitoring_required": 1,
                "host_facts": 1,
                "host_identity_status": 1,
                "monitoring_assignment": 1,
            },
        ).to_list(length=1000)

        registered_agents = [
            (agent, str(agent.get("agent_id") or ""))
            for agent in agents
            if str(agent.get("agent_id") or "")
        ]
        signature_mode = event_signature_mode()
        live_status_by_agent = {}
        sensor_status_by_agent = {}
        event_signature_by_agent = {}
        latest_coverage_by_agent = {}
        agent_ids = [agent_id for _, agent_id in registered_agents]
        if agent_ids:
            # One indexed, newest-only lookup per enrolled agent; never load
            # the complete heartbeat history into a dashboard request.
            coverage_cursor = db["agents"].aggregate([
                {"$match": {"tenant_id": tenant_id, "agent_id": {"$in": agent_ids}}},
                {"$lookup": {
                    "from": "agent_coverage_observations",
                    "let": {"agent": "$agent_id", "tenant": "$tenant_id"},
                    "pipeline": [
                        {"$match": {"$expr": {"$and": [
                            {"$eq": ["$tenant_id", "$$tenant"]},
                            {"$eq": ["$agent_id", "$$agent"]},
                        ]}}},
                        {"$sort": {"server_received_time": -1}},
                        {"$limit": 1},
                        {"$project": {
                            "_id": 0, "agent_id": 1, "protocol_version": 1,
                            "server_received_time": 1, "clock_offset_ms": 1, "clock_state": 1,
                        }},
                    ],
                    "as": "observation",
                }},
                {"$unwind": "$observation"},
                {"$replaceRoot": {"newRoot": "$observation"}},
            ])
            async for observation in coverage_cursor:
                observed_agent_id = str(observation.get("agent_id") or "")
                if observed_agent_id and observed_agent_id not in latest_coverage_by_agent:
                    latest_coverage_by_agent[observed_agent_id] = observation
        if redis_client is not None and registered_agents:
            status_keys = [
                f"status:{tenant_id}:{agent_id}"
                for _, agent_id in registered_agents
            ]
            sensor_keys = [
                f"warsoc:agent_sensor:{agent_id}"
                for _, agent_id in registered_agents
            ]
            signature_keys = [
                f"{EVENT_SIGNATURE_STATUS_KEY_PREFIX}:{tenant_id}:{agent_id}"
                for _, agent_id in registered_agents
            ]
            values = await redis_client.mget([*status_keys, *sensor_keys, *signature_keys])
            split_at = len(registered_agents)
            live_status_by_agent = {
                agent_id: values[index]
                for index, (_, agent_id) in enumerate(registered_agents)
            }
            sensor_status_by_agent = {
                agent_id: values[split_at + index]
                for index, (_, agent_id) in enumerate(registered_agents)
            }
            signature_split_at = split_at * 2
            event_signature_by_agent = {
                agent_id: values[signature_split_at + index]
                for index, (_, agent_id) in enumerate(registered_agents)
            }

        data = []
        for agent, agent_id in registered_agents:
            live_last_seen = live_status_by_agent.get(agent_id)
            sensor_raw = sensor_status_by_agent.get(agent_id)
            signature_status = decode_event_signature_status(
                event_signature_by_agent.get(agent_id)
            )
            sensor_status = agent.get("sensor_status") if isinstance(agent.get("sensor_status"), dict) else {}
            if sensor_raw:
                try:
                    decoded_sensor = json.loads(sensor_raw)
                    if isinstance(decoded_sensor, dict):
                        sensor_status = decoded_sensor
                except (TypeError, ValueError):
                    sensor_status = agent.get("sensor_status") if isinstance(agent.get("sensor_status"), dict) else {}

            channels = sensor_status.get("channels") if isinstance(sensor_status, dict) else {}
            channels = channels if isinstance(channels, dict) else {}
            required_channels_ok = all(
                isinstance(channels.get(channel), dict)
                and str(channels[channel].get("status") or "").lower() == "ok"
                for channel in ("Security", "System")
            )
            audit_configured = str(sensor_status.get("audit_policy_status") or "").lower() == "configured"
            server_required = bool(agent.get("server_monitoring_required") or agent.get("asset_class") == "server")
            server_report = sanitize_profile_report(sensor_status.get("server_monitoring"))
            server_health = server_profile_health(agent, server_report) if server_required else None
            if server_required:
                audit_configured = server_report["audit"]["state"] == "AUDIT_OK"
            online = _is_fresh_agent_timestamp(live_last_seen)
            spool_status = sensor_status.get("spool") if isinstance(sensor_status, dict) else {}
            spool_status = spool_status if isinstance(spool_status, dict) else {}
            spool_blocked = bool(spool_status.get("blocked", False))
            signature_ready = bool(signature_status["ready"])
            observation = latest_coverage_by_agent.get(agent_id) or {}
            observation_time = _coerce_dt(observation.get("server_received_time"))
            observation_is_current = _is_fresh_agent_timestamp(observation_time)
            protocol_version = str(observation.get("protocol_version") or "").lower()
            if observation_is_current and protocol_version == "heartbeat-v2":
                time_trust_status = str(observation.get("clock_state") or "UNKNOWN").upper()
            elif observation_is_current:
                time_trust_status = "LEGACY"
            elif observation_time:
                time_trust_status = "STALE"
            else:
                time_trust_status = "UNKNOWN"
            pos_audit = sensor_status.get("pos_audit_log") if isinstance(sensor_status, dict) else {}
            pos_audit = pos_audit if isinstance(pos_audit, dict) else {}
            try:
                pos_sacl_path_count = max(0, int(sensor_status.get("pos_sacl_path_count") or 0))
            except (TypeError, ValueError):
                pos_sacl_path_count = 0
            pos_ready = pos_sacl_path_count > 0 or (
                bool(pos_audit.get("configured")) and bool(pos_audit.get("present"))
            )
            health = "offline"
            if online:
                health = (
                    "active"
                    if (
                        required_channels_ok
                        and audit_configured
                        and not spool_blocked
                        and (signature_mode != "required" or signature_ready)
                        and (not server_required or server_health == "READY")
                    )
                    else "degraded"
                )

            last_seen = live_last_seen if online else agent.get("last_seen")
            if isinstance(last_seen, datetime):
                last_seen = _coerce_dt(last_seen).isoformat()
            data.append(
                {
                    "agent_id": agent_id,
                    "endpoint_name": signature_status["endpoint_name"] or agent_id,
                    "last_seen": last_seen,
                    "version": signature_status["agent_version"] or agent.get("version"),
                    "asset_class": agent.get("asset_class") or "unclassified",
                    "server_role": agent.get("server_role"),
                    "environment": agent.get("environment"),
                    "criticality": agent.get("criticality"),
                    "response_mode": agent.get("response_mode") or "LEGACY_ENDPOINT",
                    "online": online,
                    "health": health,
                    "sensor_status": sensor_status,
                    "event_signing": {
                        "mode": signature_mode,
                        "status": signature_status["status"],
                        "ready": signature_ready,
                        "last_event_at": signature_status["last_event_at"],
                        "last_signed_event_at": signature_status["last_signed_event_at"],
                    },
                    "time_trust": {
                        "status": time_trust_status,
                        "clock_offset_ms": observation.get("clock_offset_ms"),
                        "observed_at": observation_time.isoformat() if observation_time else None,
                    },
                    "audit_coverage": {
                        "status": (
                            "UNKNOWN" if not sensor_status else "STALE" if not online else
                            "READY" if (
                                audit_configured
                                and required_channels_ok
                                and (not server_required or server_health == "READY")
                            ) else "DEGRADED"
                        ),
                    },
                    "pos_coverage": {
                        "status": (
                            "UNKNOWN" if not sensor_status else "STALE" if not online else
                            "READY" if pos_ready else "NOT_CONFIGURED"
                        ),
                        "sacl_path_count": pos_sacl_path_count,
                        "audit_log_configured": bool(pos_audit.get("configured")),
                        "audit_log_present": bool(pos_audit.get("present")),
                    },
                    "spool_health": {
                        "status": (
                            "UNKNOWN" if "blocked" not in spool_status else "STALE" if not online else
                            "BLOCKED" if spool_blocked else "HEALTHY"
                        ),
                        "blocked": spool_blocked,
                        "reason": spool_status.get("reason"),
                        "usage_bytes": spool_status.get("usage_bytes"),
                        "max_bytes": spool_status.get("max_bytes"),
                    },
                    "server_monitoring": {
                        "required": server_required,
                        "health": server_health or "NOT_APPLICABLE",
                        "desired": agent.get("monitoring_assignment"),
                        "reported": server_report if server_required else None,
                        "host": {
                            key: value for key, value in (agent.get("host_facts") or {}).items()
                            if key != "machine_fingerprint"
                        },
                        "host_identity_status": agent.get("host_identity_status"),
                    },
                }
            )

        data.sort(key=lambda item: item.get("last_seen") or "", reverse=True)
        online_count = sum(1 for item in data if item["online"])
        degraded_count = sum(1 for item in data if item["health"] == "degraded")
        offline_count = sum(1 for item in data if item["health"] == "offline")
        active_count = sum(1 for item in data if item["health"] == "active")
        signing_ready_count = sum(1 for item in data if item["event_signing"]["ready"])
        telemetry_status = (
            "active" if data and active_count == len(data) else (
                "degraded" if online_count else "offline"
            )
        )
        return {
            "status": "success",
            "tenant_id": tenant_id,
            "max_agents": max_agents,
            "services_healthy": redis_client is not None,
            "endpoint_status": telemetry_status,
            "event_signature_mode": signature_mode,
            "data": data,
            "agents_online": online_count,
            "registered_agents": len(data),
            "agents_degraded": degraded_count,
            "agents_offline": offline_count,
            "agents_signing_ready": signing_ready_count,
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
    days: str = str(DEFAULT_HOT_SEARCH_DAYS),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    db=Depends(get_db), 
    current_user=Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "analyst"])),
):
    try:
        tenant_id = current_user.get("tenant_id")
        return await _run_safe_global_search(db, tenant_id, q, days, skip, limit)
    except HTTPException:
        raise
    except Exception as e:
        print(f" Omni-Search Error: {e}")
        raise HTTPException(status_code=500, detail="Search failed. Please try again.")

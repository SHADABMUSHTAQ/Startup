from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Literal, Optional

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from cryptography.fernet import Fernet
from app.utils.limiter import limiter
from app.config.config import get_settings
from app.database import get_db
from app.routes.auth import get_current_user, require_premium_plan
from app.utils.rbac import RoleChecker
from app.utils.archive_reader import count_archived_documents, fetch_archived_documents
from app.utils.csv_security import sanitize_csv_cell
from app.utils.endpoint_health import (
    EVENT_SIGNATURE_STATUS_KEY_PREFIX,
    decode_event_signature_status,
    event_signature_mode,
)

settings = get_settings()
try:
    fernet = Fernet(settings.encryption_key.encode()) if settings.encryption_key else None
except Exception:
    fernet = None

router = APIRouter()

import csv
import io
import re

def _safe_path_segment(value: str) -> str:
    segment = Path(str(value or "")).name.strip()
    segment = re.sub(r"[^A-Za-z0-9_.-]", "_", segment)
    return segment or "unknown"

def _parse_time(time_str: str) -> Optional[datetime]:
    if not time_str:
        return None
    try:
        parsed = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None

async def csv_generator(cursor, fieldnames):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    yield buffer.getvalue()
    buffer.seek(0)
    buffer.truncate(0)

    async for doc in cursor:
        row = {}
        for field in fieldnames:
            value = doc.get(field, "")
            if isinstance(value, (dict, list)):
                value = str(value)
            row[field] = value
        writer.writerow({key: sanitize_csv_cell(value) for key, value in row.items()})
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)


async def csv_list_generator(docs: list[dict], fieldnames):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    yield buffer.getvalue()
    buffer.seek(0)
    buffer.truncate(0)

    for doc in docs:
        row = {}
        for field in fieldnames:
            value = doc.get(field, "")
            if isinstance(value, (dict, list)):
                value = str(value)
            row[field] = value
        writer.writerow({key: sanitize_csv_cell(value) for key, value in row.items()})
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)

def _load_runtime_config() -> dict:
    config_path = Path(__file__).resolve().parent.parent / "config" / "config.json"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


_RUNTIME_CONFIG = _load_runtime_config()
_EVENT_ID_MAP = _RUNTIME_CONFIG.get("event_id_map", {})
_COMPLIANCE_TARGETS = _RUNTIME_CONFIG.get("compliance_targets", {})


def _humanize_event_type(value: str) -> str:
    return str(value or "").replace("_", " ").strip().title()


def _json_default(obj: Any):
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _to_jsonable(value: Any):
    return json.loads(json.dumps(value, default=_json_default))


def _parse_iso_dt(value: Optional[str], field_name: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid {field_name}. Use ISO-8601 format.")


def _build_time_filter(start_dt: Optional[datetime], end_dt: Optional[datetime]) -> Optional[dict]:
    if not start_dt and not end_dt:
        return None

    dt_bounds = {}
    str_bounds = {}

    if start_dt:
        dt_bounds["$gte"] = start_dt
        str_bounds["$gte"] = start_dt.isoformat()
    if end_dt:
        dt_bounds["$lte"] = end_dt
        str_bounds["$lte"] = end_dt.isoformat()

    clauses = [
        {"timestamp": dt_bounds},
        {"ingested_at": dt_bounds},
        {"timestamp": str_bounds},
        {"ingested_at": str_bounds},
    ]
    return {"$or": clauses}


def _compose_query(query: dict, start_dt: Optional[datetime], end_dt: Optional[datetime]) -> dict:
    time_filter = _build_time_filter(start_dt, end_dt)
    if not time_filter:
        return dict(query)
    return {"$and": [dict(query), time_filter]}


def _coerce_dt(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            return None
    return None


def _passes_time_filter(doc: dict, start_dt: Optional[datetime], end_dt: Optional[datetime]) -> bool:
    if not start_dt and not end_dt:
        return True

    ts = _coerce_dt(doc.get("timestamp") or doc.get("ingested_at"))
    if not ts:
        return False
    if start_dt and ts < start_dt:
        return False
    if end_dt and ts > end_dt:
        return False
    return True


def _decrypt_field(value: Any) -> Any:
    if not value or not isinstance(value, str) or not fernet:
        return value
    try:
        pt = fernet.decrypt(value.encode()).decode()
        # Attempt to parse json if it was json object
        try:
            return json.loads(pt)
        except Exception:
            return pt
    except Exception:
        return value

def _event_sort_key(doc: dict):
    ts = _coerce_dt(doc.get("timestamp") or doc.get("ingested_at"))
    if not ts:
        return datetime.min.replace(tzinfo=timezone.utc)
    return ts


def _curate_evidence_record(doc: dict, evidence_source: str, data_origin: str) -> dict:
    signature = doc.get("digital_signature")
    forensic_hash = doc.get("forensic_seal")
    archived = doc.get("_archived") is True

    curated = {
        "id": str(doc.get("_id")) if doc.get("_id") is not None else None,
        "tenant_id": doc.get("tenant_id"),
        "agent_id": doc.get("agent_id"),
        "event_uid": doc.get("event_uid"),
        "timestamp": _to_jsonable(doc.get("timestamp") or doc.get("ingested_at")),
        "ingested_at": _to_jsonable(doc.get("ingested_at")),
        "event_id": doc.get("event_id"),
        "source_ip": doc.get("source_ip"),
        "user": doc.get("user"),
        "message": _decrypt_field(doc.get("message")),
        "tags": doc.get("tags"),
        "retention_policy": doc.get("retention_policy"),
        "raw_event": _decrypt_field(doc.get("raw_event")),
        "raw_event_data": _decrypt_field(doc.get("raw_event_data")),
        "raw_data": _decrypt_field(doc.get("raw_data")),
        "processed_data": _decrypt_field(doc.get("processed_data")),
        "digital_signature": signature,
        "forensic_seal": forensic_hash,
        "signed_payload": doc.get("signed_payload"),
        "rsa_signature": signature,
        "cryptographic_hash": forensic_hash,
        "evidence_source": evidence_source,
        "data_origin": data_origin,
        "storage_tier": "cold_archive" if archived else "hot",
        "archived": archived,
    }
    return curated


def _base_query(tenant_id: str, event_id: Optional[str]) -> dict:
    query = {"tenant_id": tenant_id}
    if event_id is not None:
        normalized_event_id = str(event_id).strip()
        query["event_id"] = (
            {"$in": [normalized_event_id, int(normalized_event_id)]}
            if normalized_event_id.isdigit()
            else normalized_event_id
        )
    return query


async def _fetch_docs_page(
    collection,
    query: dict,
    start_dt: Optional[datetime],
    end_dt: Optional[datetime],
    skip: int,
    limit: int,
):
    scoped_query = _compose_query(query, start_dt, end_dt)
    total = await collection.count_documents(scoped_query)
    cursor = collection.find(scoped_query).sort([
        ("timestamp", -1),
        ("ingested_at", -1),
        ("_id", -1),
    ]).skip(skip).limit(limit)
    docs = await cursor.to_list(length=limit)
    return docs, total


async def _fetch_archived_page(
    db,
    tenant_id: str,
    collection_names: list[str],
    start_dt: Optional[datetime],
    end_dt: Optional[datetime],
    event_id: Optional[str],
    skip: int,
    limit: int,
):
    archived_docs, archived_total = await fetch_archived_documents(
        db,
        tenant_id=tenant_id,
        collections=collection_names,
        start_dt=start_dt,
        end_dt=end_dt,
        event_id=event_id,
        limit=skip + limit,
    )
    return archived_docs[skip: skip + limit], archived_total


async def _resolve_archive_page(
    db,
    *,
    tenant_id: str,
    collection_names: list[str],
    hot_total: int,
    hot_docs: list[dict],
    skip: int,
    limit: int,
    start_dt: Optional[datetime],
    end_dt: Optional[datetime],
    event_id: Optional[str],
) -> tuple[list[dict], int, dict]:
    """Fill a page from cold storage only after the hot tier is exhausted."""
    unfiltered = event_id is None and start_dt is None and end_dt is None
    archived_total = 0
    total_is_exact = False

    if unfiltered:
        archived_total, total_is_exact = await count_archived_documents(
            db,
            tenant_id=tenant_id,
            collections=collection_names,
        )

    remaining = max(0, limit - len(hot_docs))
    archive_skip = max(0, skip - hot_total)
    archive_read_performed = False
    archived_docs: list[dict] = []
    should_read_archive = remaining > 0
    if unfiltered and total_is_exact:
        should_read_archive = should_read_archive and archive_skip < archived_total

    if should_read_archive:
        archived_docs, scanned_total = await _fetch_archived_page(
            db,
            tenant_id,
            collection_names,
            start_dt,
            end_dt,
            event_id,
            skip=archive_skip,
            limit=remaining,
        )
        archive_read_performed = True
        if not total_is_exact:
            archived_total = scanned_total
            # A bounded blob scan cannot prove a global filtered total.
            total_is_exact = False

    return archived_docs, hot_total + archived_total, {
        "archive_read_performed": archive_read_performed,
        "archive_rows": archived_total,
        "total_is_exact": total_is_exact,
    }


def _paginate(items: list, skip: int, limit: int):
    total = len(items)
    paged = items[skip: skip + limit]
    return paged, total


def _normalize_pack_id(pack_id: str) -> str:
    key = (pack_id or "").strip().lower()
    # Keep legacy ETO labels readable, but expose PECA as the canonical pack.
    aliases = {
        "peca_forensic": "peca_forensic",
        "peca": "peca_forensic",
        "peca_vault": "peca_forensic",
        "eto": "peca_forensic",
        "eto_forensic": "peca_forensic",
        "fbr": "fbr_pos",
        "fbr_pos": "fbr_pos"
    }
    if key not in aliases:
        raise HTTPException(status_code=404, detail="Pack not found")
    return aliases[key]


def _get_entitled_packs(current_user: dict) -> set:
    packs_raw = current_user.get("compliance_packs", [])
    if not isinstance(packs_raw, list):
        packs_raw = []

    # Keep legacy ETO labels readable, but expose PECA as the canonical pack.
    aliases = {
        "peca": "peca_forensic",
        "peca_forensic": "peca_forensic",
        "peca_vault": "peca_forensic",
        "eto": "peca_forensic",
        "eto_forensic": "peca_forensic",
        "fbr": "fbr_pos",
        "fbr_pos": "fbr_pos",
        "fbr_pos_shield": "fbr_pos",
    }

    entitled = set()
    for pack in packs_raw:
        key = (pack or "").strip().lower()
        if key in aliases:
            entitled.add(aliases[key])

    return entitled


async def _get_fbr_docs_with_fallback(db, query: dict, start_dt: Optional[datetime], end_dt: Optional[datetime]):
    primary_docs, primary_total = await _fetch_docs_page(
        db["fbr_pos_logs"],
        query,
        start_dt,
        end_dt,
        skip=0,
        limit=1,
    )
    if primary_total > 0:
        return primary_docs, primary_total, "fbr_pos_logs", False

    legacy_docs, legacy_total = await _fetch_docs_page(
        db["fbr_vault"],
        query,
        start_dt,
        end_dt,
        skip=0,
        limit=1,
    )
    return legacy_docs, legacy_total, "fbr_vault_legacy", True


async def _get_fbr_page_with_fallback(
    db,
    query: dict,
    start_dt: Optional[datetime],
    end_dt: Optional[datetime],
    skip: int,
    limit: int,
):
    _, primary_total, primary_origin, primary_fallback = await _get_fbr_docs_with_fallback(
        db,
        query,
        start_dt,
        end_dt,
    )

    if primary_total > 0 and primary_origin == "fbr_pos_logs":
        docs, _ = await _fetch_docs_page(
            db["fbr_pos_logs"],
            query,
            start_dt,
            end_dt,
            skip=skip,
            limit=limit,
        )
        return docs, primary_total, "fbr_pos_logs", primary_fallback

    docs, total = await _fetch_docs_page(
        db["fbr_vault"],
        query,
        start_dt,
        end_dt,
        skip=skip,
        limit=limit,
    )
    return docs, total, "fbr_vault_legacy", True


from app.utils.compliance_catalog import COMPLIANCE_CATALOG

def _apply_pack_curation(docs: list, pack_id: str, origin: str):
    source = "peca_forensic" if pack_id == "peca_forensic" else "fbr_pos"
    return [_curate_evidence_record(doc, source, origin) for doc in docs]


@router.get("/packs", dependencies=[Depends(get_current_user)])
async def list_compliance_packs():
    """Lists available compliance frameworks from the Master Config (SSOT)."""
    return [
        {
            "pack_id": fid,
            "name": f["name"],
            "description": f["description"],
            "retention": f["retention"]
        }
        for fid, f in COMPLIANCE_CATALOG.items()
    ]


@router.get("/coverage")
async def get_compliance_coverage(
    request: Request,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "manager", "auditor"])),
):
    """Return real tenant sensor coverage instead of a static monitoring claim."""
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Unauthorized tenant scope")

    entitled_packs = _get_entitled_packs(current_user)
    agents = await db["agents"].find(
        {
            "tenant_id": tenant_id,
            "status": {"$ne": "revoked"},
            "public_key": {"$exists": True, "$ne": ""},
        },
        {"_id": 0, "agent_id": 1, "last_seen": 1, "sensor_status": 1},
    ).to_list(length=1000)

    signature_mode = event_signature_mode()
    redis_client = getattr(request.app.state, "redis", None)
    signature_status_by_agent = {}
    agent_ids = [str(agent.get("agent_id") or "") for agent in agents]
    agent_ids = [agent_id for agent_id in agent_ids if agent_id]
    if redis_client is not None and agent_ids:
        signature_values = await redis_client.mget(
            [
                f"{EVENT_SIGNATURE_STATUS_KEY_PREFIX}:{tenant_id}:{agent_id}"
                for agent_id in agent_ids
            ]
        )
        signature_status_by_agent = {
            agent_id: decode_event_signature_status(signature_values[index])
            for index, agent_id in enumerate(agent_ids)
        }

    now = datetime.now(timezone.utc)
    agent_states = []
    for agent in agents:
        sensor = agent.get("sensor_status") if isinstance(agent.get("sensor_status"), dict) else {}
        channels = sensor.get("channels") if isinstance(sensor.get("channels"), dict) else {}
        last_seen = _coerce_dt(agent.get("last_seen"))
        online = bool(last_seen and (now - last_seen).total_seconds() <= 600)
        signature_status = signature_status_by_agent.get(
            str(agent.get("agent_id") or ""),
            decode_event_signature_status(None),
        )
        native_ready = (
            online
            and str(sensor.get("audit_policy_status") or "").lower() == "configured"
            and all(
                str((channels.get(channel) or {}).get("status") or "").lower() == "ok"
                for channel in ("Security", "System")
            )
            and (signature_mode != "required" or signature_status["ready"])
        )
        try:
            pos_sacl_path_count = int(sensor.get("pos_sacl_path_count") or 0)
        except (TypeError, ValueError):
            pos_sacl_path_count = 0
        fbr_ready = native_ready and (
            pos_sacl_path_count > 0
            or (
                bool((sensor.get("pos_audit_log") or {}).get("configured"))
                and bool((sensor.get("pos_audit_log") or {}).get("present"))
            )
        )
        agent_states.append(
            {
                "agent_id": agent.get("agent_id"),
                "online": online,
                "native_ready": native_ready,
                "fbr_ready": fbr_ready,
                "signing_ready": bool(signature_status["ready"]),
            }
        )

    coverage = []
    for pack_id in sorted(entitled_packs):
        required_key = "fbr_ready" if pack_id == "fbr_pos" else "native_ready"
        ready_count = sum(1 for state in agent_states if state[required_key])
        signing_ready_count = sum(1 for state in agent_states if state["signing_ready"])
        if not agent_states or ready_count == 0:
            status = "not_configured"
        elif ready_count == len(agent_states):
            status = "active"
        else:
            status = "degraded"

        collection_name = "fbr_pos_logs" if pack_id == "fbr_pos" else "peca_forensic_logs"
        latest = await db[collection_name].find_one(
            {"tenant_id": tenant_id},
            {"timestamp": 1, "ingested_at": 1},
            sort=[("timestamp", -1)],
        )
        coverage.append(
            {
                "pack_id": pack_id,
                "status": status,
                "registered_agents": len(agent_states),
                "ready_agents": ready_count,
                "signing_ready_agents": signing_ready_count,
                "event_signature_mode": signature_mode,
                "last_evidence_at": _to_jsonable(
                    (latest or {}).get("timestamp") or (latest or {}).get("ingested_at")
                ),
            }
        )

    return {"status": "success", "coverage": coverage}


@router.get("/packs/{pack_id}", dependencies=[Depends(get_current_user)])
async def get_pack_details(pack_id: str):
    """Returns granular controls and event monitoring rules for a specific framework (Config-Driven)."""
    normalized_id = _normalize_pack_id(pack_id)

    pack = COMPLIANCE_CATALOG.get(normalized_id)
    if not pack:
        raise HTTPException(status_code=404, detail="Compliance framework not found")

    rules = pack.get("rules", [])

    return {
        "pack_id": normalized_id,
        "name": pack["name"],
        "retention": pack["retention"],
        "monitored_events": rules
    }


@router.get("/evidence")
async def get_compliance_evidence(
    skip: int = Query(0, ge=0, description="Deep pagination over 10000 will be auto-adjusted to prevent memory exhaustion"),
    limit: int = Query(50, ge=1, le=500),
    event_id: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    db=Depends(get_db),
    current_user: dict = Depends(require_premium_plan),
    _: str = Depends(RoleChecker(["admin", "auditor"]))
):
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Unauthorized access to compliance evidence.")

    info_message = None
    if skip > 10000:
        import logging
        logging.warning(f"O(N) Mitigation Triggered: User {current_user.get('username')} requested skip={skip}. Auto-adjusting to 10000.")
        skip = 10000
        info_message = "Deep pagination is limited for performance. Showing results starting from item 10,000."

    entitled_packs = _get_entitled_packs(current_user)
    if not entitled_packs:
        return {
            "status": "success",
            "data": [],
            "pagination": {
                "total": 0,
                "skip": skip,
                "limit": limit
            },
            "meta": {
                "fbr_fallback_used": False,
                "fbr_active_collection": None
            }
        }

    start_dt = _parse_iso_dt(start_time, "start_time")
    end_dt = _parse_iso_dt(end_time, "end_time")
    if start_dt and end_dt and start_dt > end_dt:
        raise HTTPException(status_code=400, detail="start_time cannot be greater than end_time")

    query = _base_query(tenant_id, event_id)

    # BUG-12 FIX: Unified Aggregation for Efficient Pagination
    # We use $unionWith to merge PECA and FBR streams at the DB level,
    # then sort and page before returning only the required slice to the API.

    pipeline = []

    # Base Match (Tenant & Time)
    match_stage = {"$match": query}
    if start_dt or end_dt:
        time_query = {}
        if start_dt:
            time_query["$gte"] = start_dt.isoformat()
        if end_dt:
            time_query["$lte"] = end_dt.isoformat()
        match_stage["$match"]["timestamp"] = time_query

    # Re-writing the core logic to be truly aggregated:
    base_collection = None
    other_collections = []

    if "peca_forensic" in entitled_packs:
        base_collection = db["peca_forensic_logs"]
        if "fbr_pos" in entitled_packs:
            # Check FBR origin for union
            _, _, fbr_origin, _ = await _get_fbr_docs_with_fallback(db, query, start_dt, end_dt)
            other_collections.append(fbr_origin)
    elif "fbr_pos" in entitled_packs:
        _, _, fbr_origin, _ = await _get_fbr_docs_with_fallback(db, query, start_dt, end_dt)
        base_collection = db[fbr_origin]

    if base_collection is None:
        return {"status": "success", "data": [], "pagination": {"total": 0, "skip": skip, "limit": limit}}

    # Memory Exhaustion Fix: Multi-Cursor Merge Pagination
    # Avoids $unionWith memory limits by fetching cursors separately and merging.

    collections_to_query = []
    if "peca_forensic" in entitled_packs:
        collections_to_query.append("peca_forensic_logs")
    if "fbr_pos" in entitled_packs:
        _, _, fbr_origin, _ = await _get_fbr_docs_with_fallback(db, query, start_dt, end_dt)
        collections_to_query.append(fbr_origin)

    if not collections_to_query:
        return {"status": "success", "data": [], "pagination": {"total": 0, "skip": skip, "limit": limit}}

    scoped_query = _compose_query(query, start_dt, end_dt)

    total = 0
    for coll_name in collections_to_query:
        total += await db[coll_name].count_documents(scoped_query)

    cursors = []
    for coll_name in collections_to_query:
        cursor = db[coll_name].find(scoped_query).sort([
            ("timestamp", -1),
            ("ingested_at", -1),
            ("_id", -1)
        ])
        cursors.append({"name": coll_name, "cursor": cursor, "current": None})

    docs = []
    skipped = 0

    async def _next_document(cursor):
        try:
            return await cursor.__anext__()
        except StopAsyncIteration:
            return None

    try:
        for c in cursors:
            c["current"] = await _next_document(c["cursor"])

        while len(docs) < limit:
            best_c = None
            for c in cursors:
                if c["current"] is not None:
                    if best_c is None:
                        best_c = c
                    else:
                        ts_c = _coerce_dt(c["current"].get("timestamp") or c["current"].get("ingested_at"))
                        ts_best = _coerce_dt(best_c["current"].get("timestamp") or best_c["current"].get("ingested_at"))

                        if ts_c is None:
                            ts_c = datetime.min.replace(tzinfo=timezone.utc)
                        if ts_best is None:
                            ts_best = datetime.min.replace(tzinfo=timezone.utc)

                        if ts_c > ts_best:
                            best_c = c

            if best_c is None:
                break

            doc = best_c["current"]
            doc["_source_collection"] = best_c["name"]
            best_c["current"] = await _next_document(best_c["cursor"])

            if skipped < skip:
                skipped += 1
            else:
                docs.append(doc)
    finally:
        for c in cursors:
            await c["cursor"].close()

    archive_collections = []
    if "peca_forensic" in entitled_packs:
        archive_collections.append("peca_forensic_logs")
    if "fbr_pos" in entitled_packs:
        archive_collections.append("fbr_pos_logs")

    archived_docs, total, archive_meta = await _resolve_archive_page(
        db,
        tenant_id=tenant_id,
        collection_names=archive_collections,
        hot_total=total,
        hot_docs=docs,
        skip=skip,
        limit=limit,
        start_dt=start_dt,
        end_dt=end_dt,
        event_id=event_id,
    )

    curated = []
    for doc in [*docs, *archived_docs]:
        origin = doc.get("_source_collection") or doc.get("_archive_collection") or "unknown"
        source = "peca_forensic" if origin == "peca_forensic_logs" else "fbr_pos"
        curated.append(_curate_evidence_record(doc, source, origin))
    curated = sorted(curated, key=_event_sort_key, reverse=True)[:limit]

    response = {
        "status": "success",
        "data": curated,
        "pagination": {
            "total": total,
            "skip": skip,
            "limit": limit
        },
        "meta": archive_meta,
    }
    if info_message:
        response["info"] = info_message
    return response


@router.get("/evidence/{pack_id}")
async def get_compliance_evidence_by_pack(
    pack_id: str,
    skip: int = Query(0, ge=0, description="Deep pagination over 10000 will be auto-adjusted to prevent memory exhaustion"),
    limit: int = Query(50, ge=1, le=500),
    event_id: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "auditor"]))
):
    normalized_pack = _normalize_pack_id(pack_id)
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Unauthorized access to compliance evidence.")

    plan_type = current_user.get("plan_type", "Free")
    if plan_type.lower() in ["free", "basic", "trial", "starter"]:
        raise HTTPException(status_code=403, detail="Compliance evidence vault access requires an active WarSOC custom contract entitlement.")

    info_message = None
    if skip > 10000:
        import logging
        logging.warning(f"O(N) Mitigation Triggered: User {current_user.get('username')} requested skip={skip}. Auto-adjusting to 10000.")
        skip = 10000
        info_message = "Deep pagination is limited for performance. Showing results starting from item 10,000."

    entitled_packs = _get_entitled_packs(current_user)
    if normalized_pack not in entitled_packs:
        raise HTTPException(status_code=403, detail="Not entitled to this compliance pack")

    start_dt = _parse_iso_dt(start_time, "start_time")
    end_dt = _parse_iso_dt(end_time, "end_time")
    if start_dt and end_dt and start_dt > end_dt:
        raise HTTPException(status_code=400, detail="start_time cannot be greater than end_time")

    query = _base_query(tenant_id, event_id)

    if normalized_pack == "peca_forensic":
        docs, total = await _fetch_docs_page(
            db["peca_forensic_logs"],
            query,
            start_dt,
            end_dt,
            skip=skip,
            limit=limit,
        )
        origin = "peca_forensic_logs"
        fallback_used = False
    else:
        docs, total, origin, fallback_used = await _get_fbr_page_with_fallback(
            db,
            query,
            start_dt,
            end_dt,
            skip=skip,
            limit=limit,
        )

    archived_collection = "peca_forensic_logs" if normalized_pack == "peca_forensic" else "fbr_pos_logs"
    archived_docs, total, archive_meta = await _resolve_archive_page(
        db,
        tenant_id=tenant_id,
        collection_names=[archived_collection],
        hot_total=total,
        hot_docs=docs,
        skip=skip,
        limit=limit,
        start_dt=start_dt,
        end_dt=end_dt,
        event_id=event_id,
    )

    curated = []
    for doc in [*docs, *archived_docs]:
        doc_origin = doc.get("_source_collection") or doc.get("_archive_collection") or origin
        curated.extend(_apply_pack_curation([doc], normalized_pack, doc_origin))
    curated = sorted(curated, key=_event_sort_key, reverse=True)[:limit]

    response = {
        "status": "success",
        "pack_id": normalized_pack,
        "data": curated,
        "pagination": {
            "total": total,
            "skip": skip,
            "limit": limit
        },
        "meta": {
            "fbr_fallback_used": fallback_used,
            "active_collection": origin,
            **archive_meta,
        }
    }
    if info_message:
        response["info"] = info_message
    return response

@router.get("/export")
async def export_compliance_evidence(
    type: Literal["fbr", "peca"] = Query("fbr", description="Type of compliance data to export: 'fbr' or 'peca'"),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    limit: int = Query(5000, ge=1, le=50000),
    db = Depends(get_db),
    current_user: dict = Depends(require_premium_plan),
    _: str = Depends(RoleChecker(["admin", "auditor"])),
):
    """
    Dedicated Compliance Export Engine (Uncapped).
    Mandatory for FBR and PECA auditing.
    """
    tenant_id = _safe_path_segment(current_user.get("tenant_id"))
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    requested_pack = "fbr_pos" if type == "fbr" else "peca_forensic"
    if requested_pack not in _get_entitled_packs(current_user):
        raise HTTPException(status_code=403, detail="Not entitled to this compliance pack")
    collection_name = "fbr_pos_logs" if requested_pack == "fbr_pos" else "peca_forensic_logs"

    collection = db[collection_name]
    query = {"tenant_id": tenant_id}

    start_dt = _parse_time(start_time)
    end_dt = _parse_time(end_time)
    if start_dt or end_dt:
        query["timestamp"] = {}
        if start_dt: query["timestamp"]["$gte"] = start_dt
        if end_dt: query["timestamp"]["$lte"] = end_dt

    cursor = collection.find(query).sort("timestamp", -1).limit(limit)
    hot_docs = await cursor.to_list(length=limit)
    archived_docs, _ = await fetch_archived_documents(
        db,
        tenant_id=tenant_id,
        collections=[collection_name],
        start_dt=start_dt,
        end_dt=end_dt,
        event_id=None,
        limit=limit,
    )
    export_docs = sorted([*hot_docs, *archived_docs], key=_event_sort_key, reverse=True)[:limit]

    if export_docs:
        fieldnames = set()
        for doc in export_docs[:100]:
            fieldnames.update(doc.keys())
        for internal in ("_id", "tenant_id", "_retention_ts", "_expire_at", "_archived", "_source_collection", "_archive_blob_name"):
            fieldnames.discard(internal)
        fieldnames = sorted(fieldnames)
    else:
        fieldnames = ["timestamp", "event_id", "severity", "message"]

    filename = f"{type}_compliance_export_{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"

    return StreamingResponse(
        csv_list_generator(export_docs, fieldnames),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

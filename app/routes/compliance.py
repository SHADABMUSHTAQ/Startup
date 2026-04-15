from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Optional

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from app.database import get_db
from app.routes.auth import get_current_user
from app.utils.rbac import RoleChecker

router = APIRouter()


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


def _build_monitored_events(target_key: str, fallback: list[dict]) -> list[dict]:
    fallback_by_id = {
        int(item.get("id")): {
            "name": item.get("name"),
            "severity": item.get("severity"),
        }
        for item in fallback
        if item.get("id") is not None
    }

    raw_targets = _COMPLIANCE_TARGETS.get(target_key, [])
    monitored_events = []

    for raw_event_id in raw_targets:
        try:
            event_id = int(raw_event_id)
        except (TypeError, ValueError):
            continue

        event_rule = _EVENT_ID_MAP.get(str(event_id), {})
        fallback_item = fallback_by_id.get(event_id, {})

        event_name = _humanize_event_type(event_rule.get("event_type")) or fallback_item.get("name") or f"Event {event_id}"
        severity = str(event_rule.get("severity") or fallback_item.get("severity") or "Info").title()

        monitored_events.append({
            "id": event_id,
            "name": event_name,
            "severity": severity,
        })

    return monitored_events or fallback


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


def _event_sort_key(doc: dict):
    ts = _coerce_dt(doc.get("timestamp") or doc.get("ingested_at"))
    if not ts:
        return datetime.min.replace(tzinfo=timezone.utc)
    return ts


def _curate_evidence_record(doc: dict, evidence_source: str, data_origin: str) -> dict:
    signature = doc.get("digital_signature")
    forensic_hash = doc.get("forensic_seal")

    curated = {
        "id": str(doc.get("_id")) if doc.get("_id") is not None else None,
        "tenant_id": doc.get("tenant_id"),
        "timestamp": _to_jsonable(doc.get("timestamp") or doc.get("ingested_at")),
        "event_id": doc.get("event_id"),
        "source_ip": doc.get("source_ip"),
        "user": doc.get("user"),
        "message": doc.get("message"),
        "tags": doc.get("tags"),
        "retention_policy": doc.get("retention_policy"),
        "raw_event_data": _to_jsonable(doc.get("raw_event_data")),
        "raw_data": _to_jsonable(doc.get("raw_data")),
        "digital_signature": signature,
        "forensic_seal": forensic_hash,
        "rsa_signature": signature,
        "cryptographic_hash": forensic_hash,
        "evidence_source": evidence_source,
        "data_origin": data_origin
    }
    return curated


def _base_query(tenant_id: str, event_id: Optional[int]) -> dict:
    query = {"tenant_id": tenant_id}
    if event_id is not None:
        query["event_id"] = event_id
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


def _paginate(items: list, skip: int, limit: int):
    total = len(items)
    paged = items[skip: skip + limit]
    return paged, total


def _normalize_pack_id(pack_id: str) -> str:
    key = (pack_id or "").strip().lower()
    aliases = {
        "peca": "peca_forensic",
        "peca_forensic": "peca_forensic",
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

    aliases = {
        "peca": "peca_forensic",
        "peca_forensic": "peca_forensic",
        "fbr": "fbr_pos",
        "fbr_pos": "fbr_pos",
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


def _apply_pack_curation(docs: list, pack_id: str, origin: str):
    source = "peca_forensic" if pack_id == "peca_forensic" else "fbr_pos"
    return [_curate_evidence_record(doc, source, origin) for doc in docs]

@router.get("/packs", dependencies=[Depends(get_current_user)])
async def get_compliance_packs():
    """Returns the full catalog of regulatory compliance frameworks."""
    mock_packs = [
        {
            "pack_id": "fbr_pos",
            "name": "FBR Point-of-Sale (SRO 288)",
            "description": "Mandatory real-time sales and modification tracking as per FBR S.R.O. 288(I)/2026.",
            "retention": {"vault_days": 30}
        },
        {
            "pack_id": "peca_forensic",
            "name": "PECA Forensic Trail (Section 46)",
            "description": "Non-repudiable log integrity and court-admissible forensic evidence (PECA 2016).",
            "retention": {"vault_days": 365}
        }
    ]
    return mock_packs

@router.get("/packs/{pack_id}", dependencies=[Depends(get_current_user)])
async def get_pack_details(pack_id: str):
    """Returns granular controls and event monitoring rules for a specific pack."""
    if pack_id == "fbr_pos":
        fallback_events = [
            {"id": 4660, "name": "Object Deleted", "severity": "Warning"},
            {"id": 4663, "name": "File System Modification", "severity": "Alert"},
            {"id": 4670, "name": "Permissions Changed", "severity": "High"}
        ]
        return {
            "pack_id": "fbr_pos",
            "name": "FBR Point-of-Sale (SRO 288)",
            "retention": {"local_hot_days": 7, "vault_days": 30},
            "monitored_events": _build_monitored_events("fbr", fallback_events)
        }
    elif pack_id == "peca_forensic":
        fallback_events = [
            {"id": 4624, "name": "Success Logon", "severity": "Informational"},
            {"id": 4625, "name": "Failed Logon", "severity": "Critical"},
            {"id": 1102, "name": "Audit Log Cleared", "severity": "Security Alert"},
            {"id": 4688, "name": "Process Creation", "severity": "High"}
        ]
        return {
            "pack_id": "peca_forensic",
            "name": "PECA Forensic Trail (Section 46)",
            "retention": {"local_hot_days": 30, "vault_days": 365},
            "monitored_events": _build_monitored_events("peca", fallback_events)
        }
    return JSONResponse(status_code=404, content={"detail": "Pack not found"})


@router.get("/evidence")
async def get_compliance_evidence(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    event_id: Optional[int] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "auditor"]))
):
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Unauthorized access to compliance evidence.")

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
        
    if not base_collection:
        return {"status": "success", "data": [], "pagination": {"total": 0, "skip": skip, "limit": limit}}

    # Build Pipeline
    final_pipeline = [match_stage]
    for coll_name in other_collections:
        final_pipeline.append({
            "$unionWith": {
                "coll": coll_name,
                "pipeline": [match_stage]
            }
        })
    
    # Sort and Page
    final_pipeline.append({"$sort": {"timestamp": -1}})
    
    # 📊 Count Total First
    count_pipeline = final_pipeline + [{"$count": "total"}]
    count_result = await base_collection.aggregate(count_pipeline).to_list(1)
    total = count_result[0]["total"] if count_result else 0
    
    # 📑 Limit/Skip
    final_pipeline.extend([
        {"$skip": skip},
        {"$limit": limit}
    ])
    
    docs = await base_collection.aggregate(final_pipeline).to_list(limit)
    
    # Apply Standard Forensic Curation (BUG-12 Polish)
    # This restores aliases like 'cryptographic_hash' and 'rsa_signature' that the UI expects.
    curated = []
    for doc in docs:
        # Determine source for curation metadata
        source = "peca_forensic" if "peca_forensic" in entitled_packs else "fbr_pos"
        origin = "peca_forensic_logs" if "peca_forensic" in entitled_packs else (fbr_origin or "fbr_pos_logs")
        
        curated_doc = _curate_evidence_record(doc, source, origin)
        curated.append(curated_doc)

    return {
        "status": "success",
        "data": curated,
        "pagination": {
            "total": total,
            "skip": skip,
            "limit": limit
        }
    }


@router.get("/evidence/{pack_id}")
async def get_compliance_evidence_by_pack(
    pack_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    event_id: Optional[int] = Query(None),
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

    curated = _apply_pack_curation(docs, normalized_pack, origin)

    return {
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
            "active_collection": origin
        }
    }

from fastapi import APIRouter, Depends, Query, HTTPException, Request
from app.database import get_db
from app.routes.auth import get_current_user
from app.utils.rbac import RoleChecker as RequireRole
from bson import ObjectId
from datetime import datetime, timezone, timedelta
import json
import asyncio
import logging
import time
from cryptography.fernet import Fernet
from prometheus_client import Counter, Histogram
from app.config.config import get_settings
from app.utils.archive_reader import fetch_archived_documents
from app.utils.alert_incidents import aggregate_security_alerts
from app.utils.alert_context import operator_alert_document
from app.utils.telemetry_groups import aggregate_endpoint_events

# 📊 MASTER BUILD: Logs Gateway
# Strictly Decoupled, Paginated, and Tenant-Isolated

router = APIRouter()
logger = logging.getLogger("warsoc.logs")

LIVE_READ_SECONDS = Histogram(
    "warsoc_dashboard_live_read_seconds",
    "Latency of bounded MongoDB reads used by the live dashboard.",
    ["source"],
)
LIVE_READ_ROWS = Histogram(
    "warsoc_dashboard_live_read_rows",
    "Raw MongoDB rows returned to a live dashboard reconciliation.",
    ["source"],
    buckets=(0, 1, 10, 25, 50, 100, 250, 500),
)
LIVE_READ_FAILURES = Counter(
    "warsoc_dashboard_live_read_failures_total",
    "Failed bounded live-dashboard reads.",
    ["source"],
)

def json_serializer(obj):
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

from app.utils.audit import audit_log

RAW_RETENTION_ANCHOR_FIELD = "_retention_ts"
_settings = get_settings()
_fernet = Fernet(_settings.encryption_key.encode()) if _settings.encryption_key else None
_LIST_PROJECTION = {
    "raw_event_data": 0,
    "raw_event": 0,
    "raw_data": 0,
    "processed_data": 0,
    RAW_RETENTION_ANCHOR_FIELD: 0,
    "_expire_at": 0,
}


def _decrypt_evidence_field(value):
    if not value or not isinstance(value, str) or _fernet is None:
        return value
    try:
        plaintext = _fernet.decrypt(value.encode()).decode()
        try:
            return json.loads(plaintext)
        except Exception:
            return plaintext
    except Exception:
        return value

@router.get("")
@audit_log("View Logs")
async def get_logs_master(
    source: str = Query("security_alerts", pattern="^(security_alerts|siem|compliance|uploads)$"),
    pack: str | None = Query(None),
    event_uid: str | None = Query(None),
    next_cursor: str | None = Query(None),
    days: int = Query(7, ge=1, le=365),
    limit: int = Query(100, ge=1, le=500),
    aggregate: bool = Query(True, description="Group repeated security alerts into operator incidents"),
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    role: str = Depends(RequireRole(["admin", "manager", "analyst", "auditor"])),
    request: Request = None # Required for the @audit_log decorator
):
    """
    MASTER BUILD: Securely fetches paginated logs with strict Tenant Isolation.
    Source Selection via ?source=siem|compliance|uploads
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        print("[!] Security Alert: User lacks tenant ID")
        raise HTTPException(status_code=403, detail="Unauthorized access to log history.")
    if role == "auditor" and source != "compliance":
        raise HTTPException(
            status_code=403,
            detail="Auditors may access entitled compliance evidence only.",
        )

    tenant = await db["tenants"].find_one({"tenant_id": tenant_id}, {"retention_days": 1})
    retention_days = int((tenant or {}).get("retention_days") or days)

    #  Enterprise Isolation Query
    hot_window_start = datetime.now(timezone.utc) - timedelta(days=min(days, max(1, retention_days)))

    query = {"tenant_id": tenant_id}
    if event_uid:
        query["$or"] = [
            {"event_uid": event_uid},
            {"raw_event_data.event_uid": event_uid},
            {"raw_data.event_uid": event_uid},
        ]
    if source == "security_alerts":
        query["$and"] = [
            {
                "$or": [
                    {"timestamp": {"$gte": hot_window_start}},
                    {"timestamp": {"$gte": hot_window_start.isoformat()}},
                    {"ingested_at": {"$gte": hot_window_start}},
                    {"ingested_at": {"$gte": hot_window_start.isoformat()}},
                ]
            }
        ]

    if next_cursor:
        try:
            query["_id"] = {"$lt": ObjectId(next_cursor)}
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid cursor format")

    #  LAZY LOADING: Exclude the heavy raw string for O(1) ingestion speed
    projection = _LIST_PROJECTION

    # 📁 Collection Selection
    if source == "security_alerts":
        collection = db["security_alerts"]
    elif source == "siem":
        collection = db["siem_cold_vault"]
    elif source == "uploads":
        collection = db["csv_uploads"]
    elif source == "compliance":
        # Enforce pack entitlement: users must be entitled to a compliance pack
        packs_raw = current_user.get("compliance_packs", [])
        if not isinstance(packs_raw, list):
            packs_raw = []

        aliases = {
            "peca": "peca_forensic",
            "peca_forensic": "peca_forensic",
            "peca_vault": "peca_forensic",
            "eto": "peca_forensic",
            "eto_forensic": "peca_forensic",
            "fbr": "fbr_pos",
            "fbr_pos": "fbr_pos"
        }

        entitled = set()
        for p in packs_raw:
            key = (p or "").strip().lower()
            if key in aliases:
                entitled.add(aliases[key])

        # If user has no entitled packs, return empty result to avoid leaking evidence
        if not entitled:
            return {
                "status": "success",
                "data": [],
                "next_cursor": None,
                "limit": limit,
                "total": 0,
            }

        requested_pack = None
        if pack:
            pack_key = pack.strip().lower()
            if pack_key not in aliases:
                raise HTTPException(status_code=404, detail="Pack not found")
            requested_pack = aliases[pack_key]

        # If a specific pack was requested, ensure the user is entitled to exactly that pack.
        if requested_pack:
            if requested_pack not in entitled:
                raise HTTPException(status_code=403, detail="Not entitled to this compliance pack")
            collection = db["fbr_pos_logs"] if requested_pack == "fbr_pos" else db["peca_forensic_logs"]
        else:
            # Default to PECA if user is entitled to it, otherwise fallback to FBR
            if "peca_forensic" in entitled:
                collection = db["peca_forensic_logs"]
            elif "fbr_pos" in entitled:
                collection = db["fbr_pos_logs"]
            else:
                return {
                    "status": "success",
                    "data": [],
                    "next_cursor": None,
                    "limit": limit,
                    "total": 0,
                }
    else:
        collection = db["security_alerts"]

    # Historical/search callers retain exact count semantics. The automatic
    # dashboard reconciliation path uses /logs/live and never reaches this scan.
    raw_total = await collection.count_documents(query)
    total = raw_total

    # ⚡ Paginated Fetch (Meta-only)
    cursor = collection.find(query, projection).sort([("timestamp", -1), ("_id", -1)]).limit(limit)
    logs_raw = await cursor.to_list(length=limit)
    if source == "compliance":
        archived_docs, archived_total = await fetch_archived_documents(
            db,
            tenant_id=tenant_id,
            collections=[collection.name],
            event_uid=event_uid,
            limit=limit,
        )
        if archived_docs:
            for doc in archived_docs:
                for field, include in projection.items():
                    if include == 0:
                        doc.pop(field, None)
            logs_raw = sorted(
                [*logs_raw, *archived_docs],
                key=lambda doc: str(doc.get("timestamp") or doc.get("ingested_at") or ""),
                reverse=True,
            )[:limit]
            total += archived_total

    # Manual BSON -> JSON serialization (offloaded to thread to avoid blocking event loop)
    logs_data = await asyncio.to_thread(
        lambda: json.loads(json.dumps(logs_raw, default=json_serializer))
    )

    if source == "security_alerts":
        logs_data = [operator_alert_document(log) for log in logs_data]

    new_cursor = logs_data[-1]["_id"] if logs_data else None
    incident_count = len(logs_data)
    if source == "security_alerts" and aggregate:
        logs_data = aggregate_security_alerts(logs_data)
        incident_count = len(logs_data)

    return {
        "status": "success",
        "data": logs_data,
        "next_cursor": new_cursor,
        "limit": limit,
        "total": total,
        "incident_count": incident_count,
        "raw_total": raw_total,
    }


@router.get("/live")
async def get_live_logs(
    source: str = Query("security_alerts", pattern="^(security_alerts|siem)$"),
    limit: int = Query(100, ge=1, le=500),
    aggregate: bool = Query(True, description="Group repeated alert or telemetry rows for operator presentation"),
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    role: str = Depends(RequireRole(["admin", "manager", "analyst"])),
):
    """Return a bounded hot-tier reconciliation page for automatic dashboard refreshes.

    This route deliberately performs no exact count, no Azure read and no
    management-audit write. Complete historical/search semantics remain on
    GET /logs and compliance/export routes.
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Unauthorized access to live telemetry.")

    collection = db["security_alerts" if source == "security_alerts" else "siem_cold_vault"]
    started = time.perf_counter()
    try:
        # Fetch one extra row to expose bounded-page completeness without an
        # expensive count_documents scan. Timestamp is normalized on current
        # worker writes and covered by the tenant/timestamp indexes.
        cursor = (
            collection.find({"tenant_id": tenant_id}, _LIST_PROJECTION)
            .sort("timestamp", -1)
            .limit(limit + 1)
        )
        documents = await cursor.to_list(length=limit + 1)
        has_more = len(documents) > limit
        documents = documents[:limit]
        raw_returned = len(documents)

        rows = await asyncio.to_thread(
            lambda: json.loads(json.dumps(documents, default=json_serializer))
        )
        if source == "security_alerts":
            rows = [operator_alert_document(row) for row in rows]
            if aggregate:
                rows = aggregate_security_alerts(rows)
        elif source == "siem" and aggregate:
            rows = aggregate_endpoint_events(rows)

        LIVE_READ_ROWS.labels(source=source).observe(raw_returned)
        return {
            "status": "success",
            "mode": "hot_live",
            "source": source,
            "data": rows,
            "limit": limit,
            "returned": len(rows),
            "raw_returned": raw_returned,
            "has_more": has_more,
        }
    except Exception:
        LIVE_READ_FAILURES.labels(source=source).inc()
        raise
    finally:
        elapsed = time.perf_counter() - started
        LIVE_READ_SECONDS.labels(source=source).observe(elapsed)
        if elapsed >= 2.0:
            logger.warning(
                "Slow live dashboard read source=%s duration_ms=%.1f limit=%s",
                source,
                elapsed * 1000,
                limit,
            )

@router.get("/{log_id}/evidence")
@audit_log("View Forensic Evidence")
async def get_forensic_evidence(
    log_id: str,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    request: Request = None
):
    """
    🔬 MASTER BUILD: Surgical Evidence Retrieval.
    Lazy-loads the 100% original raw telemetry string for forensic trust.
    """
    tenant_id = current_user.get("tenant_id")

    # Surgical Fetch across both pools
    try:
        log_obj_id = ObjectId(log_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid log reference")

    doc = await db.siem_cold_vault.find_one({"_id": log_obj_id, "tenant_id": tenant_id})
    if not doc:
        doc = await db.peca_forensic_logs.find_one({"_id": log_obj_id, "tenant_id": tenant_id})
    if not doc:
        doc = await db.fbr_pos_logs.find_one({"_id": log_obj_id, "tenant_id": tenant_id})
    if not doc:
        archived_docs, _ = await fetch_archived_documents(
            db,
            tenant_id=tenant_id,
            collections=["siem_cold_vault", "peca_forensic_logs", "fbr_pos_logs"],
            document_id=log_id,
            limit=1,
        )
        doc = archived_docs[0] if archived_docs else None

    if not doc:
        raise HTTPException(status_code=404, detail="Forensic evidence purged or inaccessible")

    raw_event_data = doc.get("raw_event_data")
    if raw_event_data is None:
        raw_event_data = doc.get("raw_event")
    if raw_event_data is None:
        raw_event_data = doc.get("raw_data")
    if raw_event_data is None:
        raw_event_data = doc.get("message", "Forensic Data Inaccessible (Format Mismatch)")

    return {
        "status": "success",
        "raw_event_data": _decrypt_evidence_field(raw_event_data),
        "processed_data": _decrypt_evidence_field(doc.get("processed_data")),
    }

@router.post("/inject")
@audit_log("Manual Log Injection")
async def inject_manual_log(
    payload: dict,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    role: str = Depends(RequireRole(["admin", "manager"])),
    request: Request = None
):
    """
     TOOL: Allows analysts to manually inject logs for testing and simulation.
    """
    if not _settings.enable_manual_log_injection:
        raise HTTPException(status_code=404, detail="Not found")

    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Unauthorized.")

    log_entry = {
        **payload,
        "tenant_id": tenant_id,
        "timestamp": payload.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "injected_by": current_user["username"]
    }

    # Insert into logs collection
    result = await db["logs"].insert_one(log_entry)

    # Also broadcast to WebSocket via Redis if needed, but for now we'll just rely on polling
    # or the UI fetching new logs.

    return {"status": "success", "id": str(result.inserted_id)}

@router.get("/management-audit")
@audit_log("View Management Trails")
async def get_management_audit(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    request: Request = None
):


    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Unauthorized access to management audit.")

    query = {"tenant_id": tenant_id}

    cursor = db.management_audit.find(query).sort("timestamp", -1).skip(skip).limit(limit)
    audit_raw = await cursor.to_list(length=limit)

    return {
        "status": "success",
        "data": json.loads(json.dumps(audit_raw, default=json_serializer))
    }

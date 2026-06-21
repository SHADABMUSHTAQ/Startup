from fastapi import APIRouter, Depends, Query, HTTPException, Request
from app.database import get_db
from app.routes.auth import get_current_user
from app.utils.rbac import RoleChecker as RequireRole
from bson import ObjectId
from datetime import datetime, timezone, timedelta
import json
import asyncio

# 📊 MASTER BUILD: Logs Gateway
# Strictly Decoupled, Paginated, and Tenant-Isolated

router = APIRouter()

def json_serializer(obj):
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

from app.utils.audit import audit_log

RAW_RETENTION_ANCHOR_FIELD = "_retention_ts"

@router.get("")
@audit_log("View Logs")
async def get_logs_master(
    source: str = Query("security_alerts", pattern="^(security_alerts|siem|compliance|uploads)$"),
    pack: str | None = Query(None),
    event_uid: str | None = Query(None),
    next_cursor: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
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

    #  Enterprise Isolation Query
    hot_window_start = datetime.now(timezone.utc) - timedelta(days=7)

    query = {"tenant_id": tenant_id}
    if event_uid:
        query["$or"] = [
            {"event_uid": event_uid},
            {"raw_event_data.event_uid": event_uid},
            {"raw_data.event_uid": event_uid},
        ]
    if source == "security_alerts":
        query["timestamp"] = {"$gte": hot_window_start.isoformat()}

    if next_cursor:
        try:
            query["_id"] = {"$lt": ObjectId(next_cursor)}
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid cursor format")

    #  LAZY LOADING: Exclude the heavy raw string for O(1) ingestion speed
    projection = {"raw_event_data": 0, RAW_RETENTION_ANCHOR_FIELD: 0}

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
            return {"data": [], "next_cursor": None, "limit": limit, "total": 0}

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
                return {"data": [], "next_cursor": None, "limit": limit, "total": 0}
    else:
        collection = db["security_alerts"]

    #  Count total documents
    total = await collection.count_documents(query)

    # ⚡ Paginated Fetch (Meta-only)
    cursor = collection.find(query, projection).sort([("timestamp", -1), ("_id", -1)]).limit(limit)
    logs_raw = await cursor.to_list(length=limit)

    # Manual BSON -> JSON serialization (offloaded to thread to avoid blocking event loop)
    logs_data = await asyncio.to_thread(
        lambda: json.loads(json.dumps(logs_raw, default=json_serializer))
    )

    new_cursor = logs_data[-1]["_id"] if logs_data else None

    return {
        "data": logs_data,
        "next_cursor": new_cursor,
        "limit": limit,
        "total": total
    }

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
        "raw_event_data": raw_event_data
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

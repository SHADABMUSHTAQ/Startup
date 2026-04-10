from fastapi import APIRouter, Depends, Query, HTTPException, Request
from app.database import get_db
from app.routes.auth import get_current_user
from bson import ObjectId
from datetime import datetime
import json

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

@router.get("/")
@audit_log("View Logs")
async def get_logs_master(
    source: str = Query("siem", pattern="^(siem|compliance|uploads)$"),
    pack: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
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

    # 🔐 Enterprise Isolation Query
    query = {"tenant_id": tenant_id}
    
    # 🚀 LAZY LOADING: Exclude the heavy raw string for O(1) ingestion speed
    projection = {"raw_event_data": 0, RAW_RETENTION_ANCHOR_FIELD: 0}

    # 📁 Collection Selection
    if source == "siem":
        collection = db["logs"]
    elif source == "uploads":
        collection = db["csv_uploads"]
    elif source == "compliance":
        if pack and "fbr" in pack.lower():
            collection = db["fbr_pos_logs"]
        else:
            collection = db["peca_forensic_logs"]
    else:
        collection = db["logs"]

    # ✅ Count total documents
    total = await collection.count_documents(query)
    
    # ⚡ Paginated Fetch (Meta-only)
    cursor = collection.find(query, projection).sort("timestamp", -1).skip(skip).limit(limit)
    logs_raw = await cursor.to_list(length=limit)

    # Manual BSON -> JSON serialization
    logs_data = json.loads(json.dumps(logs_raw, default=json_serializer))

    return {
        "status": "success",
        "data": logs_data,
        "pagination": {"total": total, "skip": skip, "limit": limit}
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

    doc = await db.logs.find_one({"_id": log_obj_id, "tenant_id": tenant_id})
    if not doc:
        doc = await db.peca_forensic_logs.find_one({"_id": log_obj_id, "tenant_id": tenant_id})
    
    if not doc:
        raise HTTPException(status_code=404, detail="Forensic evidence purged or inaccessible")

    return {
        "status": "success",
        "raw_event_data": doc.get("raw_event_data", "Forensic Data Inaccessible (Format Mismatch)")
    }

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

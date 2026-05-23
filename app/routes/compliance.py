from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Optional

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
import base64
import copy
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
try:
    from canonicaljson import encode_canonical_json
    CANONICALJSON_AVAILABLE = True
except Exception:
    CANONICALJSON_AVAILABLE = False

from app.schemas.compliance import VerifyEvidenceRequest
from app.utils.limiter import limiter
from cryptography.fernet import Fernet
from app.config.config import get_settings
from app.database import get_db
from app.routes.auth import get_current_user, require_premium_plan
from app.utils.rbac import RoleChecker

settings = get_settings()
fernet = None
encryption_key = getattr(settings, "encryption_key", "")
if encryption_key:
    try:
        fernet = Fernet(encryption_key.encode())
    except Exception as e:
        print(f"Compliance Router: Failed to initialize Fernet (Check encryption key): {e}")

router = APIRouter()

# 🔐 Load RSA Public Key for Verification
repo_root = Path(__file__).resolve().parent.parent.parent
public_key_path = repo_root / "keys" / "public_key.pem"
public_key = None
try:
    if getattr(settings, "public_key_b64", ""):
        key_data = base64.b64decode(settings.public_key_b64)
    else:
        with open(public_key_path, "rb") as key_file:
            key_data = key_file.read()
    public_key = serialization.load_pem_public_key(key_data)
except Exception as e:
    print(f"Compliance Router: Failed to load RSA Public Key: {e}. Verification will fail.")

def _to_canonical_bytes(obj) -> bytes:
    """Exact 1:1 replica of worker canonicalization for mathematical validation."""
    o = copy.deepcopy(obj)

    def _convert(value):
        if isinstance(value, dict):
            for k, v in list(value.items()):
                if isinstance(v, datetime):
                    value[k] = v.astimezone(timezone.utc).isoformat()
                else:
                    _convert(v)
        elif isinstance(value, list):
            for i in range(len(value)):
                v = value[i]
                if isinstance(v, datetime):
                    value[i] = v.astimezone(timezone.utc).isoformat()
                else:
                    _convert(v)

    _convert(o)

    if CANONICALJSON_AVAILABLE:
        try:
            return encode_canonical_json(o)
        except Exception:
            pass
    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


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

    curated = {
        "id": str(doc.get("_id")) if doc.get("_id") is not None else None,
        "tenant_id": doc.get("tenant_id"),
        "timestamp": _to_jsonable(doc.get("timestamp") or doc.get("ingested_at")),
        "event_id": doc.get("event_id"),
        "source_ip": doc.get("source_ip"),
        "user": doc.get("user"),
        "message": _decrypt_field(doc.get("message")),
        "tags": doc.get("tags"),
        "retention_policy": doc.get("retention_policy"),
        "raw_event": _decrypt_field(doc.get("raw_event")),
        "raw_event_data": _decrypt_field(doc.get("raw_event_data")),
        "raw_data": _decrypt_field(doc.get("raw_data")),
        "digital_signature": signature,
        "forensic_seal": forensic_hash,
        "signed_payload": doc.get("signed_payload"),
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
    # 🚨 CRITICAL FIX: Must align with _get_entitled_packs() which normalizes
    # all PECA/ETO variants to "eto_forensic". Previous mapping produced
    # "peca_forensic" which never matched the entitled set, causing 403s.
    aliases = {
        "peca": "peca_forensic",
        "peca_forensic": "peca_forensic",
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

    # 🚨 CRITICAL FIX: All PECA/ETO variants must normalize to "peca_forensic"
    # to align with _normalize_pack_id(). Previously "eto_forensic" was used here
    # but "peca_forensic" was used in _normalize_pack_id, causing 403 mismatches.
    aliases = {
        "eto": "peca_forensic",
        "eto_forensic": "peca_forensic",
        "peca": "peca_forensic",
        "peca_forensic": "peca_forensic",
        "peca_vault": "peca_forensic",
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


def _apply_pack_curation(docs: list, pack_id: str, origin: str):
    source = "peca_forensic" if pack_id == "peca_forensic" else "fbr_pos"
    return [_curate_evidence_record(doc, source, origin) for doc in docs]


@router.get("/packs", dependencies=[Depends(get_current_user)])
async def list_compliance_packs():
    """Lists available compliance frameworks from the Master Config (SSOT)."""
    frameworks = _RUNTIME_CONFIG.get("compliance_frameworks", {})
    return [
        {
            "pack_id": fid,
            "name": f["name"],
            "description": f["description"],
            "retention": f["retention"]
        }
        for fid, f in frameworks.items()
    ]


@router.get("/packs/{pack_id}", dependencies=[Depends(get_current_user)])
async def get_pack_details(pack_id: str):
    """Returns granular controls and event monitoring rules for a specific framework (Config-Driven)."""
    frameworks = _RUNTIME_CONFIG.get("compliance_frameworks", {})
    
    # 🛡️ NORMALIZATION: Support both legacy 'peca' and new 'eto_forensic' aliases
    normalized_id = pack_id.lower()
    if normalized_id in ["peca", "peca_forensic"]: normalized_id = "eto_forensic"
    if normalized_id == "fbr": normalized_id = "fbr_pos"
    
    pack = frameworks.get(normalized_id)
    if not pack:
        raise HTTPException(status_code=404, detail="Compliance framework not found")
        
    rules = pack.get("rules", [])
    print(f"DEBUG: Serving {len(rules)} rules for framework {normalized_id}")
    
    return {
        "pack_id": normalized_id,
        "name": pack["name"],
        "retention": pack["retention"],
        "monitored_events": rules
    }


@router.get("/evidence")
async def get_compliance_evidence(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    event_id: Optional[int] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    db=Depends(get_db),
    current_user: dict = Depends(require_premium_plan),
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
        
    if base_collection is None:
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

    plan_type = current_user.get("plan_type", "Free")
    if plan_type.lower() in ["free", "basic", "trial", "starter"]:
        raise HTTPException(status_code=403, detail="Compliance evidence vault access requires Professional or Enterprise tier. Please upgrade.")

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

@router.post("/verify")
@limiter.limit("5/minute")
async def verify_compliance_evidence(request: Request, payload: VerifyEvidenceRequest):
    """
    Independent cryptographic validation endpoint for auditors.
    Does not require authentication. Re-hashes the raw payload and verifies against RSA-2048 public key.
    """
    if not public_key:
        raise HTTPException(status_code=500, detail="Public Key is not configured on the server.")

    try:
        # If caller supplies the original signed payload (base64), prefer it.
        if getattr(payload, "signed_payload", None):
            try:
                canonical_bytes = base64.b64decode(payload.signed_payload)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid signed_payload base64")
        else:
            # Convert the received raw event back to bytes exactly as signed
            # The worker canonicalizes a dictionary payload.
            canonical_bytes = _to_canonical_bytes(payload.raw_event)

        # Decode the Base64 signature
        signature_bytes = base64.b64decode(payload.digital_signature)

        # Mathematically verify using the Public Key
        public_key.verify(
            signature_bytes,
            canonical_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        return JSONResponse(status_code=200, content={
            "status": "VALID",
            "message": "Cryptographic signature verified. Chain of custody is intact."
        })
    except InvalidSignature:
        return JSONResponse(status_code=400, content={
            "status": "TAMPERED",
            "message": "Signature verification failed. Data has been altered."
        })
    except Exception as e:
        return JSONResponse(status_code=400, content={
            "status": "ERROR",
            "message": f"Verification processing error: {str(e)}"
        })

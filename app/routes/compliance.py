from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Literal, Optional
import uuid

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from cryptography.fernet import Fernet
from pydantic import BaseModel, ConfigDict, Field, model_validator
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
from app.utils.evidence_locks import acquire_retention_fence, release_retention_fence
from app.utils.evidence_holds import archive_query_for_hold
from app.utils.fbr_retention import (
    FBR_ACTIVE_RETENTION_MODEL,
    normalize_tenant_retention_days,
)
from app.utils.peca_retention import PECA_ACTIVE_RETENTION_MODEL

settings = get_settings()
try:
    fernet = Fernet(settings.encryption_key.encode()) if settings.encryption_key else None
except Exception:
    fernet = None

router = APIRouter()

HOLDABLE_EVIDENCE_COLLECTIONS = {
    "fbr_pos_logs",
    "source_envelopes_fbr",
    "peca_forensic_logs",
    "source_envelopes_peca",
    "siem_cold_vault",
    "source_envelopes_siem",
    "security_alerts",
    "agent_coverage_observations",
}


class EvidenceHoldRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    scope_type: Literal["TENANT", "COLLECTION", "EVENT"]
    collection: str | None = Field(default=None, max_length=100)
    event_uid: str | None = Field(default=None, max_length=200)
    reason: str = Field(min_length=10, max_length=2000)
    authority: str = Field(min_length=2, max_length=300)
    proceeding_reference: str | None = Field(default=None, max_length=300)

    @model_validator(mode="after")
    def validate_scope(self):
        if self.scope_type in {"COLLECTION", "EVENT"}:
            if self.collection not in HOLDABLE_EVIDENCE_COLLECTIONS:
                raise ValueError("collection is not holdable evidence")
        elif self.collection is not None:
            raise ValueError("tenant holds must not specify a collection")
        if self.scope_type == "EVENT" and not self.event_uid:
            raise ValueError("event holds require event_uid")
        if self.scope_type != "EVENT" and self.event_uid is not None:
            raise ValueError("event_uid is only valid for event holds")
        return self


class EvidenceHoldReleaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    reason: str = Field(min_length=10, max_length=2000)
    authority: str = Field(min_length=2, max_length=300)

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


def _public_hold(document: dict) -> dict:
    return {
        key: value
        for key, value in document.items()
        if key not in {"_id", "created_by_user_id", "released_by_user_id"}
    }


async def _record_hold_operation(
    db,
    *,
    operation_id: str,
    hold_id: str,
    tenant_id: str,
    action: str,
    actor: dict,
    reason: str,
    authority: str,
    status: str,
):
    now = datetime.now(timezone.utc)
    await db.evidence_hold_audit.update_one(
        {"operation_id": operation_id},
        {
            "$setOnInsert": {
                "operation_id": operation_id,
                "hold_id": hold_id,
                "tenant_id": tenant_id,
                "action": action,
                "actor_user_id": str(actor.get("_id") or ""),
                "actor_email": str(actor.get("email") or actor.get("username") or ""),
                "actor_role": str(actor.get("role") or ""),
                "reason": reason,
                "authority": authority,
                "created_at": now,
            },
            "$set": {"status": status, "updated_at": now},
        },
        upsert=True,
    )


async def _event_evidence_exists(db, tenant_id: str, collection: str, event_uid: str) -> bool:
    hot = await db[collection].find_one(
        {"tenant_id": tenant_id, "event_uid": event_uid},
        {"_id": 1},
    )
    if hot:
        return True
    archived = await db.storage_archives.find_one(
        {
            "tenant_id": tenant_id,
            "collection": collection,
            "event_uids": event_uid,
        },
        {"_id": 1},
    )
    return bool(archived)


async def _finalize_hold_release_without_archives(
    db,
    *,
    hold: dict,
    actor: dict,
) -> dict:
    """Commit a release synchronously when no Azure archive can match the hold."""
    operation_id = str(hold["release_operation_id"])
    tenant_id = str(hold["tenant_id"])
    hold_id = str(hold["hold_id"])
    await _record_hold_operation(
        db,
        operation_id=operation_id,
        hold_id=hold_id,
        tenant_id=tenant_id,
        action="RELEASE",
        actor=actor,
        reason=str(hold["release_reason"]),
        authority=str(hold["release_authority"]),
        status="COMMITTED",
    )
    released_at = datetime.now(timezone.utc)
    result = await db.legal_holds.update_one(
        {
            "_id": hold["_id"],
            "status": "PENDING_RELEASE",
            "release_operation_id": operation_id,
        },
        {
            "$set": {
                "status": "RELEASED",
                "archive_protection_status": "RELEASED",
                "released_at": released_at,
                "updated_at": released_at,
            }
        },
    )
    if result.modified_count != 1:
        raise HTTPException(status_code=409, detail="Evidence hold state changed; retry the request")
    return await db.legal_holds.find_one({"_id": hold["_id"]})


@router.post("/holds", status_code=201)
@limiter.limit("10/minute")
async def apply_evidence_hold(
    request: Request,
    body: EvidenceHoldRequest,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin"])),
    db=Depends(get_db),
):
    tenant_id = str(current_user.get("tenant_id") or "").strip()
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Tenant context is required")
    now = datetime.now(timezone.utc)
    hold_id = f"HOLD-{uuid.uuid4().hex.upper()}"
    operation_id = uuid.uuid4().hex
    fence_owner = f"hold-apply:{operation_id}"
    if not await acquire_retention_fence(db, tenant_id, fence_owner):
        raise HTTPException(status_code=409, detail="Evidence retention state is changing; retry the request")
    document = {
        "hold_id": hold_id,
        "tenant_id": tenant_id,
        "status": "ACTIVE",
        "archive_protection_status": "PENDING",
        "scope_type": body.scope_type,
        "collection": body.collection,
        "event_uid": body.event_uid,
        "reason": body.reason,
        "authority": body.authority,
        "proceeding_reference": body.proceeding_reference,
        "created_by_user_id": str(current_user.get("_id") or ""),
        "created_by": str(current_user.get("email") or current_user.get("username") or ""),
        "created_at": now,
        "updated_at": now,
    }
    try:
        if body.scope_type == "EVENT" and not await _event_evidence_exists(
            db,
            tenant_id,
            str(body.collection),
            str(body.event_uid),
        ):
            raise HTTPException(status_code=404, detail="Tenant-scoped evidence event was not found")
        await _record_hold_operation(
            db,
            operation_id=operation_id,
            hold_id=hold_id,
            tenant_id=tenant_id,
            action="APPLY",
            actor=current_user,
            reason=body.reason,
            authority=body.authority,
            status="PENDING",
        )
        await db.legal_holds.insert_one(document)
        await _record_hold_operation(
            db,
            operation_id=operation_id,
            hold_id=hold_id,
            tenant_id=tenant_id,
            action="APPLY",
            actor=current_user,
            reason=body.reason,
            authority=body.authority,
            status="COMMITTED",
        )
    finally:
        await release_retention_fence(db, tenant_id, fence_owner)
    return {"hold": _public_hold(document)}


@router.get("/holds")
async def list_evidence_holds(
    status: Literal["ACTIVE", "PENDING_RELEASE", "RELEASED"] | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "auditor"])),
    db=Depends(get_db),
):
    query: dict[str, Any] = {"tenant_id": current_user["tenant_id"]}
    if status:
        query["status"] = status
    documents = await db.legal_holds.find(query).sort("created_at", -1).limit(limit).to_list(limit)
    return {"holds": [_public_hold(document) for document in documents]}


@router.post("/holds/{hold_id}/release")
@limiter.limit("10/minute")
async def release_evidence_hold(
    request: Request,
    hold_id: str,
    body: EvidenceHoldReleaseRequest,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin"])),
    db=Depends(get_db),
):
    tenant_id = str(current_user.get("tenant_id") or "")
    operation_id = uuid.uuid4().hex
    fence_owner = f"hold-release:{operation_id}"
    if not await acquire_retention_fence(db, tenant_id, fence_owner):
        raise HTTPException(status_code=409, detail="Evidence retention state is changing; retry the request")
    try:
        hold = await db.legal_holds.find_one(
            {
                "tenant_id": tenant_id,
                "hold_id": hold_id,
                "status": {"$in": ["ACTIVE", "PENDING_RELEASE"]},
            }
        )
        if not hold:
            raise HTTPException(status_code=404, detail="Active evidence hold was not found")
        if hold.get("status") == "PENDING_RELEASE":
            if (
                hold.get("release_reason") != body.reason
                or hold.get("release_authority") != body.authority
            ):
                raise HTTPException(status_code=409, detail="A different release is already in progress")
            return {"hold": _public_hold(hold)}
        await _record_hold_operation(
            db,
            operation_id=operation_id,
            hold_id=hold_id,
            tenant_id=tenant_id,
            action="RELEASE",
            actor=current_user,
            reason=body.reason,
            authority=body.authority,
            status="PENDING",
        )
        release_requested_at = datetime.now(timezone.utc)
        result = await db.legal_holds.update_one(
            {"_id": hold["_id"], "status": "ACTIVE"},
            {
                "$set": {
                    "status": "PENDING_RELEASE",
                    "archive_protection_status": "RELEASE_PENDING",
                    "release_operation_id": operation_id,
                    "release_reason": body.reason,
                    "release_authority": body.authority,
                    "released_by_user_id": str(current_user.get("_id") or ""),
                    "released_by": str(current_user.get("email") or current_user.get("username") or ""),
                    "release_requested_at": release_requested_at,
                    "updated_at": release_requested_at,
                }
            },
        )
        if result.modified_count != 1:
            raise HTTPException(status_code=409, detail="Evidence hold state changed; retry the request")
        hold = await db.legal_holds.find_one({"_id": hold["_id"]})
        archive_exists = await db.storage_archives.find_one(
            archive_query_for_hold(hold),
            {"_id": 1},
        )
        if not archive_exists:
            hold = await _finalize_hold_release_without_archives(
                db,
                hold=hold,
                actor=current_user,
            )
    finally:
        await release_retention_fence(db, tenant_id, fence_owner)
    return {"hold": _public_hold(hold)}

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

_EVIDENCE_LIST_PROJECTION = {
    "raw_event": 0,
    "raw_event_data": 0,
    "raw_data": 0,
    "processed_data": 0,
    "signed_payload": 0,
    "_retention_ts": 0,
    "_expire_at": 0,
}


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


def _summarize_evidence_message(value: Any, max_length: int = 500) -> tuple[str, bool]:
    decrypted = _decrypt_field(value)
    if decrypted is None:
        return "", False
    if isinstance(decrypted, (dict, list)):
        text = json.dumps(decrypted, default=_json_default, separators=(",", ":"))
    else:
        text = str(decrypted)
    if len(text) <= max_length:
        return text, False
    return f"{text[: max_length - 3]}...", True

def _event_sort_key(doc: dict):
    ts = _coerce_dt(doc.get("timestamp") or doc.get("ingested_at"))
    if not ts:
        return datetime.min.replace(tzinfo=timezone.utc)
    return ts


def _curate_evidence_record(doc: dict, evidence_source: str, data_origin: str) -> dict:
    signature = doc.get("digital_signature")
    forensic_hash = doc.get("forensic_seal")
    archived = doc.get("_archived") is True
    message, message_truncated = _summarize_evidence_message(doc.get("message"))
    rule = get_rule_for_pack(evidence_source, str(doc.get("event_id") or ""))
    evaluation = evaluate_evidence_claim(doc, evidence_source, rule)

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
        "message": message,
        "message_truncated": message_truncated,
        "tags": doc.get("tags"),
        "retention_policy": doc.get("retention_policy"),
        "digital_signature": signature,
        "forensic_seal": forensic_hash,
        "rsa_signature": signature,
        "cryptographic_hash": forensic_hash,
        "evidence_source": evidence_source,
        "data_origin": data_origin,
        "storage_tier": "cold_archive" if archived else "hot",
        "archived": archived,
        "detail_available": doc.get("_id") is not None,
        "content_redacted_from_list": True,
        "control_id": rule.get("control_id") if rule else None,
        "evidence_state": evaluation["evidence_state"],
        "claim_state": evaluation["claim_state"],
        "time_trust_state": evaluation["time_trust_state"],
        "retention_ready": evaluation["retention_ready"],
        "evidence_checks": evaluation["evidence_checks"],
        "evidence_gaps": evaluation["evidence_gaps"],
        "claim_boundary": rule.get("claim_boundary") if rule else None,
        "evidence_source_class": rule.get("evidence_source_class") if rule else None,
        "legal_reference_ids": rule.get("legal_reference_ids", []) if rule else [],
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
    cursor = collection.find(scoped_query, _EVIDENCE_LIST_PROJECTION).sort([
        ("timestamp", -1),
        ("ingested_at", -1),
        ("_id", -1),
    ]).skip(skip).limit(limit)
    docs = await cursor.to_list(length=limit)
    return docs, total


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
    """Describe cold evidence without loading archive bytes in the API process."""
    unfiltered = event_id is None and start_dt is None and end_dt is None
    archived_total = 0
    total_is_exact = False
    archive_metadata_checked = False

    remaining = max(0, limit - len(hot_docs))
    if unfiltered or (remaining > 0 and collection_names):
        archived_total, total_is_exact = await count_archived_documents(
            db,
            tenant_id=tenant_id,
            collections=collection_names,
        )
        archive_metadata_checked = True

    archive_skip = max(0, skip - hot_total)
    archive_available = archived_total > 0 or (archive_metadata_checked and not total_is_exact)
    archive_retrieval_required = (
        remaining > 0
        and archive_available
        and (not unfiltered or not total_is_exact or archive_skip < archived_total)
    )

    # Filtered archive totals cannot be derived from batch metadata without
    # reading cold evidence, so keep their pagination total hot-tier only.
    combined_total = hot_total + archived_total if unfiltered else hot_total
    return [], combined_total, {
        "archive_read_performed": False,
        "archive_metadata_checked": archive_metadata_checked,
        "archive_available": archive_available,
        "archive_retrieval_required": archive_retrieval_required,
        "archive_rows": archived_total,
        "total_is_exact": total_is_exact if unfiltered else False,
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


from app.utils.compliance_catalog import (
    COMPLIANCE_CATALOG,
    COMPLIANCE_CATALOG_VERSION,
    get_rule_for_pack,
)
from app.utils.evidence_claims import evaluate_evidence_claim

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
            "retention": f["retention"],
            "catalog_version": COMPLIANCE_CATALOG_VERSION,
            "evidence_domain": f["evidence_domain"],
            "legal_reference_ids": f["legal_reference_ids"],
            "claim_boundary": f["claim_boundary"],
        }
        for fid, f in COMPLIANCE_CATALOG.items()
    ]


@router.get("/retention/status")
async def get_retention_status(
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "auditor"])),
):
    """Return a tenant-scoped summary of active retention and observed archives."""

    tenant_id = str(current_user.get("tenant_id") or "").strip()
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Tenant context is required")

    tenant = await db["tenants"].find_one(
        {"tenant_id": tenant_id},
        {"_id": 0, "retention_days": 1},
    )
    tenant_retention_days = normalize_tenant_retention_days(
        (tenant or {}).get("retention_days")
    )
    active_hold_count = await db["legal_holds"].count_documents(
        {"tenant_id": tenant_id, "status": {"$in": ["ACTIVE", "PENDING_RELEASE"]}}
    )
    archived_statuses = [
        "archived",
        "archived_hot_preserved_hold",
        "archived_hot_deleted",
    ]
    archive_query = {
        "tenant_id": tenant_id,
        "status": {"$in": archived_statuses},
    }
    archived_batch_count = await db["storage_archives"].count_documents(archive_query)
    latest_archives = await db["storage_archives"].find(
        archive_query,
        {"_id": 0, "created_at": 1},
    ).sort("created_at", -1).limit(1).to_list(length=1)
    latest_archive_at = latest_archives[0].get("created_at") if latest_archives else None

    fbr_retention = COMPLIANCE_CATALOG["fbr_pos"]["retention"]
    return {
        "retention": {
            "model": FBR_ACTIVE_RETENTION_MODEL,
            "tenant_retention_days": tenant_retention_days,
            "hot_storage_days": int(fbr_retention["local_hot_days"]),
            "fbr_archive_retention_days": tenant_retention_days,
            "peca_archive_retention_days": tenant_retention_days,
            "peca_retention_model": PECA_ACTIVE_RETENTION_MODEL,
            "legal_hold_state": "ACTIVE" if active_hold_count else "NONE",
            "active_hold_count": active_hold_count,
            "archive_availability": (
                "ARCHIVED_EVIDENCE_AVAILABLE"
                if archived_batch_count
                else "NO_ARCHIVED_EVIDENCE_OBSERVED"
            ),
            "archived_batch_count": archived_batch_count,
            "latest_archive_at": latest_archive_at,
            "fbr_scope": (
                "FBR POS and invoice-integrity monitoring evidence; WarSOC is not "
                "the customer's statutory tax-record repository."
            ),
        }
    }


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
    latest_coverage_by_agent = {}
    if agent_ids:
        coverage_cursor = db["agent_coverage_observations"].find(
            {"tenant_id": tenant_id, "agent_id": {"$in": agent_ids}},
            {
                "_id": 0,
                "agent_id": 1,
                "protocol_version": 1,
                "server_received_time": 1,
                "clock_state": 1,
                "sensor_status": 1,
            },
        ).sort("server_received_time", -1)
        async for observation in coverage_cursor:
            observed_agent_id = str(observation.get("agent_id") or "")
            if observed_agent_id and observed_agent_id not in latest_coverage_by_agent:
                latest_coverage_by_agent[observed_agent_id] = observation
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
        agent_id = str(agent.get("agent_id") or "")
        observation = latest_coverage_by_agent.get(agent_id)
        observation_time = _coerce_dt(
            (observation or {}).get("server_received_time")
        )
        observation_is_current = bool(
            observation_time and (now - observation_time).total_seconds() <= 600
        )
        observed_sensor = (observation or {}).get("sensor_status")
        if observation_is_current and isinstance(observed_sensor, dict):
            sensor = observed_sensor
            last_seen = observation_time
        else:
            sensor = (
                agent.get("sensor_status")
                if isinstance(agent.get("sensor_status"), dict)
                else {}
            )
            last_seen = _coerce_dt(agent.get("last_seen"))
        channels = sensor.get("channels") if isinstance(sensor.get("channels"), dict) else {}
        online = bool(last_seen and (now - last_seen).total_seconds() <= 600)
        signature_status = signature_status_by_agent.get(
            agent_id,
            decode_event_signature_status(None),
        )
        protocol_version = str(
            (observation or {}).get("protocol_version") or ""
        ).lower()
        clock_state = str((observation or {}).get("clock_state") or "UNKNOWN").upper()
        if observation_is_current and protocol_version == "heartbeat-v2":
            coverage_proof_state = (
                "trusted" if clock_state == "TRUSTED" else "degraded"
            )
        elif observation_is_current:
            coverage_proof_state = "legacy_signed"
        else:
            coverage_proof_state = "legacy_snapshot"
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
                "agent_id": agent_id,
                "online": online,
                "native_ready": native_ready,
                "fbr_ready": fbr_ready,
                "signing_ready": bool(signature_status["ready"]),
                "coverage_proof_state": coverage_proof_state,
            }
        )

    coverage = []
    for pack_id in sorted(entitled_packs):
        required_key = "fbr_ready" if pack_id == "fbr_pos" else "native_ready"
        ready_count = sum(1 for state in agent_states if state[required_key])
        signing_ready_count = sum(1 for state in agent_states if state["signing_ready"])
        signed_coverage_count = sum(
            1
            for state in agent_states
            if state["coverage_proof_state"] in {"trusted", "degraded", "legacy_signed"}
        )
        trusted_coverage_count = sum(
            1 for state in agent_states if state["coverage_proof_state"] == "trusted"
        )
        if agent_states and trusted_coverage_count == len(agent_states):
            coverage_proof_state = "trusted"
        elif signed_coverage_count:
            coverage_proof_state = "degraded"
        else:
            coverage_proof_state = "legacy_snapshot"
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
                "signed_coverage_agents": signed_coverage_count,
                "trusted_coverage_agents": trusted_coverage_count,
                "coverage_proof_state": coverage_proof_state,
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
        "description": pack["description"],
        "retention": pack["retention"],
        "catalog_version": COMPLIANCE_CATALOG_VERSION,
        "evidence_domain": pack["evidence_domain"],
        "legal_reference_ids": pack["legal_reference_ids"],
        "claim_boundary": pack["claim_boundary"],
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
        cursor = db[coll_name].find(scoped_query, _EVIDENCE_LIST_PROJECTION).sort([
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
    Bounded hot-tier compliance CSV export.

    Historical evidence requires the isolated archive-retrieval workflow.
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
    _, archived_total = await fetch_archived_documents(
        db,
        tenant_id=tenant_id,
        collections=[collection_name],
        start_dt=start_dt,
        end_dt=end_dt,
        event_id=None,
        limit=limit,
    )
    export_docs = sorted(hot_docs, key=_event_sort_key, reverse=True)[:limit]

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
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Cache-Control": "no-store",
            "X-WarSOC-Data-Scope": "hot-tier",
            "X-WarSOC-Archive-Retrieval-Required": str(archived_total > 0).lower(),
        },
    )

"""Tenant-scoped evidence cases and custody ledger."""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal
from urllib.parse import urlparse

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.database import get_db
from app.routes.auth import get_current_user
from app.utils.compliance_chain import evidence_record_digest
from app.utils.evidence_custody import (
    append_custody_event,
    recover_pending_custody_event,
    verify_custody_chain,
)
from app.utils.limiter import limiter
from app.utils.rbac import RoleChecker


router = APIRouter()
logger = logging.getLogger(__name__)

CASE_EVIDENCE_COLLECTIONS = {
    "siem_cold_vault",
    "security_alerts",
    "peca_forensic_logs",
    "fbr_pos_logs",
    "source_envelopes_siem",
    "source_envelopes_peca",
    "source_envelopes_fbr",
    "agent_coverage_observations",
}


class CreateEvidenceCaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=10, max_length=4000)
    external_reference: str | None = Field(default=None, max_length=300)


class AddEvidenceCaseItemRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    collection: str
    document_id: str | None = Field(default=None, max_length=100)
    event_uid: str | None = Field(default=None, max_length=200)
    reason: str = Field(min_length=10, max_length=2000)

    @model_validator(mode="after")
    def validate_reference(self):
        if self.collection not in CASE_EVIDENCE_COLLECTIONS:
            raise ValueError("collection is not case-referenceable evidence")
        if bool(self.document_id) == bool(self.event_uid):
            raise ValueError("provide exactly one of document_id or event_uid")
        return self


class CustodyActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["VIEW", "VERIFY", "TRANSFER"]
    reason: str = Field(min_length=10, max_length=2000)
    case_item_id: str | None = Field(default=None, max_length=100)
    transfer_to: str | None = Field(default=None, max_length=300)

    @model_validator(mode="after")
    def validate_transfer(self):
        if self.action == "TRANSFER" and not self.transfer_to:
            raise ValueError("transfer_to is required for custody transfer")
        if self.action != "TRANSFER" and self.transfer_to is not None:
            raise ValueError("transfer_to is valid only for custody transfer")
        return self


class EvidenceExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    reason: str = Field(min_length=10, max_length=2000)


def _public(document: dict) -> dict:
    return {
        key: value
        for key, value in document.items()
        if key not in {
            "_id",
            "created_by_user_id",
            "closed_by_user_id",
            "actor_user_id",
            "initialization_operation_id",
            "close_operation",
        }
    }


async def _operation_event(db, tenant_id: str, case_id: str, operation_id: str, action: str):
    if not operation_id:
        return None
    return await db.evidence_custody_events.find_one(
        {
            "tenant_id": tenant_id,
            "case_id": case_id,
            "action": action,
            "state": "COMMITTED",
            "metadata.operation_id": operation_id,
        }
    )


async def _recover_case_state(db, case: dict) -> dict:
    case = await recover_pending_custody_event(db, case)
    tenant_id = str(case.get("tenant_id") or "")
    case_id = str(case.get("case_id") or "")
    if case.get("status") == "INITIALIZING":
        operation_id = str(case.get("initialization_operation_id") or "")
        event = await _operation_event(db, tenant_id, case_id, operation_id, "CASE_CREATED")
        if event:
            await db.evidence_cases.update_one(
                {"_id": case["_id"], "status": "INITIALIZING"},
                {
                    "$set": {"status": "OPEN", "updated_at": datetime.now(timezone.utc)},
                    "$unset": {"initialization_operation_id": ""},
                },
            )
            case = await db.evidence_cases.find_one({"_id": case["_id"]}) or case
    close_operation = case.get("close_operation") or {}
    if close_operation:
        operation_id = str(close_operation.get("operation_id") or "")
        event = await _operation_event(db, tenant_id, case_id, operation_id, "CASE_CLOSED")
        if event:
            closed_at = event.get("occurred_at") or datetime.now(timezone.utc)
            await db.evidence_cases.update_one(
                {"_id": case["_id"], "close_operation.operation_id": operation_id},
                {
                    "$set": {
                        "status": "CLOSED",
                        "closed_by": event.get("actor_email"),
                        "closed_at": closed_at,
                        "updated_at": closed_at,
                    },
                    "$unset": {"close_operation": ""},
                },
            )
            case = await db.evidence_cases.find_one({"_id": case["_id"]}) or case
        else:
            started_at = close_operation.get("started_at")
            if isinstance(started_at, datetime) and started_at < datetime.now(timezone.utc) - timedelta(minutes=5):
                await db.evidence_cases.update_one(
                    {"_id": case["_id"], "close_operation.operation_id": operation_id},
                    {"$unset": {"close_operation": ""}},
                )
                case = await db.evidence_cases.find_one({"_id": case["_id"]}) or case
    return case


async def _recover_pending_items(db, tenant_id: str, case_id: str) -> None:
    pending = await db.evidence_case_items.find(
        {"tenant_id": tenant_id, "case_id": case_id, "state": "PENDING"}
    ).limit(200).to_list(200)
    now = datetime.now(timezone.utc)
    for item in pending:
        operation_id = str(item.get("operation_id") or "")
        event = await _operation_event(db, tenant_id, case_id, operation_id, "EVIDENCE_ADDED")
        if event:
            await db.evidence_case_items.update_one(
                {"_id": item["_id"], "state": "PENDING"},
                {"$set": {"state": "COMMITTED", "custody_event_id": event["custody_event_id"]}},
            )
        elif isinstance(item.get("added_at"), datetime) and item["added_at"] < now - timedelta(minutes=5):
            await db.evidence_case_items.update_one(
                {"_id": item["_id"], "state": "PENDING"},
                {"$set": {"state": "ABORTED", "aborted_at": now}},
            )


async def _case_or_404(db, tenant_id: str, case_id: str) -> dict:
    case = await db.evidence_cases.find_one({"tenant_id": tenant_id, "case_id": case_id})
    if not case:
        raise HTTPException(status_code=404, detail="Evidence case was not found")
    case = await _recover_case_state(db, case)
    if case.get("status") not in {"OPEN", "CLOSED"}:
        raise HTTPException(status_code=409, detail="Evidence case is not ready")
    if case.get("close_operation"):
        raise HTTPException(status_code=409, detail="Evidence case transition is in progress")
    return case


def _evidence_export_enabled() -> bool:
    return os.getenv("EVIDENCE_EXPORT_ENABLED", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _utc_datetime(value) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _public_export(document: dict) -> dict:
    allowed = {
        "export_id",
        "case_id",
        "status",
        "reason",
        "item_count",
        "package_sha256",
        "package_bytes",
        "signing_key_id",
        "signing_key_version",
        "created_at",
        "updated_at",
        "ready_at",
        "expires_at",
        "failed_at",
        "failure_code",
    }
    return {key: value for key, value in document.items() if key in allowed}


@router.post("/cases", status_code=201)
@limiter.limit("20/minute")
async def create_evidence_case(
    request: Request,
    body: CreateEvidenceCaseRequest,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "auditor"])),
    db=Depends(get_db),
):
    tenant_id = str(current_user.get("tenant_id") or "")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Tenant context is required")
    now = datetime.now(timezone.utc)
    operation_id = str(getattr(request.state, "request_id", "") or uuid.uuid4().hex)
    document = {
        "case_id": f"CASE-{uuid.uuid4().hex.upper()}",
        "tenant_id": tenant_id,
        "title": body.title,
        "description": body.description,
        "external_reference": body.external_reference,
        "status": "INITIALIZING",
        "initialization_operation_id": operation_id,
        "custody_sequence": 0,
        "custody_head_hash": "0" * 64,
        "created_by_user_id": str(current_user.get("_id") or ""),
        "created_by": str(current_user.get("email") or current_user.get("username") or ""),
        "created_at": now,
        "updated_at": now,
    }
    await db.evidence_cases.insert_one(document)
    try:
        await append_custody_event(
            db,
            tenant_id=tenant_id,
            case_id=document["case_id"],
            action="CASE_CREATED",
            actor=current_user,
            reason="Evidence case created through the authenticated custody API.",
            request_id=operation_id,
            metadata={"operation_id": operation_id},
        )
    except Exception as exc:
        event = await _operation_event(db, tenant_id, document["case_id"], operation_id, "CASE_CREATED")
        if not event:
            await db.evidence_cases.update_one(
                {"_id": document["_id"]},
                {"$set": {"status": "INITIALIZATION_FAILED", "updated_at": datetime.now(timezone.utc)}},
            )
            raise HTTPException(status_code=503, detail="Evidence case creation could not be completed") from exc
    await db.evidence_cases.update_one(
        {"_id": document["_id"], "status": "INITIALIZING"},
        {
            "$set": {"status": "OPEN", "updated_at": datetime.now(timezone.utc)},
            "$unset": {"initialization_operation_id": ""},
        },
    )
    document["status"] = "OPEN"
    document.pop("initialization_operation_id", None)
    return {"case": _public(document)}


@router.get("/cases")
async def list_evidence_cases(
    status: Literal["OPEN", "CLOSED"] | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "auditor"])),
    db=Depends(get_db),
):
    query = {"tenant_id": current_user["tenant_id"]}
    if status:
        query["status"] = status
    else:
        query["status"] = {"$in": ["OPEN", "CLOSED"]}
    cases = await db.evidence_cases.find(query).sort("created_at", -1).limit(limit).to_list(limit)
    return {"cases": [_public(case) for case in cases]}


@router.get("/cases/{case_id}")
async def get_evidence_case(
    case_id: str,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "auditor"])),
    db=Depends(get_db),
):
    tenant_id = str(current_user["tenant_id"])
    case = await _case_or_404(db, tenant_id, case_id)
    await _recover_pending_items(db, tenant_id, case_id)
    items = await db.evidence_case_items.find(
        {"tenant_id": tenant_id, "case_id": case_id, "state": "COMMITTED"}
    ).sort("added_at", 1).to_list(5000)
    events = await db.evidence_custody_events.find(
        {"tenant_id": tenant_id, "case_id": case_id, "state": "COMMITTED"}
    ).sort("sequence", 1).to_list(10000)
    verification = verify_custody_chain(events)
    if verification["head_hash"] != case.get("custody_head_hash"):
        verification["verified"] = False
        verification["status"] = "UNVERIFIED"
        verification["head_mismatch"] = True
    return {
        "case": _public(case),
        "items": [_public(item) for item in items],
        "custody": verification,
        "custody_events": [_public(event) for event in events],
    }


@router.post("/cases/{case_id}/items", status_code=201)
@limiter.limit("60/minute")
async def add_evidence_case_item(
    request: Request,
    case_id: str,
    body: AddEvidenceCaseItemRequest,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "auditor"])),
    db=Depends(get_db),
):
    tenant_id = str(current_user["tenant_id"])
    case = await _case_or_404(db, tenant_id, case_id)
    if case.get("status") != "OPEN":
        raise HTTPException(status_code=409, detail="Closed evidence cases cannot be changed")

    query = {"tenant_id": tenant_id}
    if body.document_id:
        try:
            query["_id"] = ObjectId(body.document_id)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid evidence document reference") from exc
    else:
        query["event_uid"] = body.event_uid
    evidence = await db[body.collection].find_one(query)
    if not evidence:
        raise HTTPException(
            status_code=404,
            detail="Tenant-scoped hot evidence was not found; archived evidence must be restored before case attachment",
        )

    operation_id = str(getattr(request.state, "request_id", "") or uuid.uuid4().hex)
    item = {
        "case_item_id": f"ITEM-{uuid.uuid4().hex.upper()}",
        "tenant_id": tenant_id,
        "case_id": case_id,
        "collection": body.collection,
        "document_id": str(evidence.get("_id")),
        "event_uid": evidence.get("event_uid"),
        "evidence_record_hash": evidence_record_digest(body.collection, evidence),
        "source_timestamp": evidence.get("timestamp") or evidence.get("ingested_at"),
        "reason": body.reason,
        "state": "PENDING",
        "operation_id": operation_id,
        "added_by": str(current_user.get("email") or current_user.get("username") or ""),
        "added_at": datetime.now(timezone.utc),
    }
    try:
        await db.evidence_case_items.insert_one(item)
    except DuplicateKeyError as exc:
        raise HTTPException(status_code=409, detail="Evidence is already attached to this case") from exc
    try:
        event = await append_custody_event(
            db,
            tenant_id=tenant_id,
            case_id=case_id,
            case_item_id=item["case_item_id"],
            action="EVIDENCE_ADDED",
            actor=current_user,
            reason=body.reason,
            request_id=operation_id,
            metadata={
                "operation_id": operation_id,
                "collection": body.collection,
                "event_uid": item.get("event_uid"),
                "evidence_record_hash": item["evidence_record_hash"],
            },
        )
    except Exception as exc:
        event = await _operation_event(db, tenant_id, case_id, operation_id, "EVIDENCE_ADDED")
        if not event:
            await db.evidence_case_items.update_one(
                {"_id": item["_id"], "state": "PENDING"},
                {"$set": {"state": "ABORTED", "aborted_at": datetime.now(timezone.utc)}},
            )
            raise HTTPException(status_code=503, detail="Evidence attachment could not be completed") from exc
    await db.evidence_case_items.update_one(
        {"_id": item["_id"], "state": "PENDING"},
        {"$set": {"state": "COMMITTED", "custody_event_id": event["custody_event_id"]}},
    )
    item["state"] = "COMMITTED"
    item["custody_event_id"] = event["custody_event_id"]
    return {"item": _public(item)}


@router.post("/cases/{case_id}/custody", status_code=201)
@limiter.limit("60/minute")
async def record_custody_action(
    request: Request,
    case_id: str,
    body: CustodyActionRequest,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "auditor"])),
    db=Depends(get_db),
):
    tenant_id = str(current_user["tenant_id"])
    await _case_or_404(db, tenant_id, case_id)
    if body.case_item_id:
        exists = await db.evidence_case_items.find_one(
            {"tenant_id": tenant_id, "case_id": case_id, "case_item_id": body.case_item_id},
            {"_id": 1},
        )
        if not exists:
            raise HTTPException(status_code=404, detail="Evidence case item was not found")
    event = await append_custody_event(
        db,
        tenant_id=tenant_id,
        case_id=case_id,
        case_item_id=body.case_item_id,
        action=body.action,
        actor=current_user,
        reason=body.reason,
        request_id=str(getattr(request.state, "request_id", "") or uuid.uuid4().hex),
        metadata={"transfer_to": body.transfer_to} if body.transfer_to else {},
    )
    return {"custody_event": _public(event)}


@router.post("/cases/{case_id}/close")
@limiter.limit("20/minute")
async def close_evidence_case(
    request: Request,
    case_id: str,
    body: CustodyActionRequest,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin"])),
    db=Depends(get_db),
):
    if body.action != "VERIFY":
        raise HTTPException(status_code=422, detail="Case closure requires a VERIFY custody action")
    tenant_id = str(current_user["tenant_id"])
    case = await _case_or_404(db, tenant_id, case_id)
    if case.get("status") != "OPEN":
        raise HTTPException(status_code=409, detail="Evidence case is already closed")
    await _recover_pending_items(db, tenant_id, case_id)
    committed_item_count = await db.evidence_case_items.count_documents(
        {"tenant_id": tenant_id, "case_id": case_id, "state": "COMMITTED"}
    )
    if committed_item_count < 1:
        raise HTTPException(status_code=409, detail="Attach at least one evidence item before closing the case")
    custody_events = await db.evidence_custody_events.find(
        {"tenant_id": tenant_id, "case_id": case_id, "state": "COMMITTED"}
    ).sort("sequence", 1).to_list(10000)
    verification = verify_custody_chain(custody_events)
    if (
        not verification.get("verified")
        or verification.get("head_hash") != case.get("custody_head_hash")
    ):
        raise HTTPException(status_code=409, detail="Evidence custody chain verification failed")
    operation_id = str(getattr(request.state, "request_id", "") or uuid.uuid4().hex)
    started_at = datetime.now(timezone.utc)
    acquired = await db.evidence_cases.find_one_and_update(
        {
            "_id": case["_id"],
            "status": "OPEN",
            "$or": [{"close_operation": {"$exists": False}}, {"close_operation": None}],
        },
        {
            "$set": {
                "close_operation": {"operation_id": operation_id, "started_at": started_at},
                "updated_at": started_at,
            }
        },
        return_document=ReturnDocument.AFTER,
    )
    if not acquired:
        raise HTTPException(status_code=409, detail="Evidence case transition is in progress")
    try:
        event = await append_custody_event(
            db,
            tenant_id=tenant_id,
            case_id=case_id,
            action="CASE_CLOSED",
            actor=current_user,
            reason=body.reason,
            request_id=operation_id,
            metadata={
                "operation_id": operation_id,
                "verified_previous_head_hash": verification["head_hash"],
                "verified_event_count": verification["event_count"],
                "committed_item_count": committed_item_count,
            },
        )
    except Exception as exc:
        event = await _operation_event(db, tenant_id, case_id, operation_id, "CASE_CLOSED")
        if not event:
            await db.evidence_cases.update_one(
                {"_id": case["_id"], "close_operation.operation_id": operation_id},
                {"$unset": {"close_operation": ""}},
            )
            raise HTTPException(status_code=503, detail="Evidence case closure could not be completed") from exc
    now = event.get("occurred_at") or datetime.now(timezone.utc)
    result = await db.evidence_cases.update_one(
        {
            "_id": case["_id"],
            "status": "OPEN",
            "close_operation.operation_id": operation_id,
        },
        {
            "$set": {
                "status": "CLOSED",
                "closed_by_user_id": str(current_user.get("_id") or ""),
                "closed_by": str(current_user.get("email") or current_user.get("username") or ""),
                "closed_at": now,
                "updated_at": now,
            },
            "$unset": {"close_operation": ""},
        },
    )
    if result.modified_count != 1:
        raise HTTPException(status_code=409, detail="Evidence case state changed; reload the case")
    return {"status": "CLOSED", "custody_event": _public(event)}


@router.post("/cases/{case_id}/exports", status_code=202)
@limiter.limit("10/minute")
async def request_evidence_export(
    request: Request,
    case_id: str,
    body: EvidenceExportRequest,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "auditor"])),
    db=Depends(get_db),
):
    if not _evidence_export_enabled():
        raise HTTPException(status_code=503, detail="Evidence package export is temporarily unavailable")
    tenant_id = str(current_user["tenant_id"])
    await _case_or_404(db, tenant_id, case_id)
    await _recover_pending_items(db, tenant_id, case_id)
    item_count = await db.evidence_case_items.count_documents(
        {"tenant_id": tenant_id, "case_id": case_id, "state": "COMMITTED"}
    )
    maximum_items = max(1, min(5000, int(os.getenv("EVIDENCE_EXPORT_MAX_ITEMS", "500"))))
    if item_count < 1:
        raise HTTPException(status_code=409, detail="Evidence case has no committed evidence items")
    if item_count > maximum_items:
        raise HTTPException(status_code=413, detail="Evidence case is too large for one package")
    now = datetime.now(timezone.utc)
    document = {
        "export_id": f"EXPORT-{uuid.uuid4().hex.upper()}",
        "tenant_id": tenant_id,
        "case_id": case_id,
        "status": "REQUESTED",
        "reason": body.reason,
        "item_count": item_count,
        "requested_by_user_id": str(current_user.get("_id") or ""),
        "requested_by": str(current_user.get("email") or current_user.get("username") or ""),
        "request_id": str(getattr(request.state, "request_id", "") or uuid.uuid4().hex),
        "created_at": now,
        "updated_at": now,
    }
    await db.evidence_exports.insert_one(document)
    return {"export": _public_export(document)}


@router.get("/cases/{case_id}/exports")
async def list_evidence_exports(
    case_id: str,
    limit: int = Query(default=50, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "auditor"])),
    db=Depends(get_db),
):
    tenant_id = str(current_user["tenant_id"])
    await _case_or_404(db, tenant_id, case_id)
    rows = await db.evidence_exports.find(
        {"tenant_id": tenant_id, "case_id": case_id}
    ).sort("created_at", -1).limit(limit).to_list(limit)
    return {"exports": [_public_export(row) for row in rows]}


@router.get("/cases/{case_id}/exports/{export_id}")
async def get_evidence_export(
    case_id: str,
    export_id: str,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "auditor"])),
    db=Depends(get_db),
):
    tenant_id = str(current_user["tenant_id"])
    await _case_or_404(db, tenant_id, case_id)
    document = await db.evidence_exports.find_one(
        {"tenant_id": tenant_id, "case_id": case_id, "export_id": export_id}
    )
    if not document:
        raise HTTPException(status_code=404, detail="Evidence export was not found")
    return {"export": _public_export(document)}


async def _evidence_export_sas(document: dict, expires_minutes: int) -> tuple[str, datetime]:
    connection_parts = {}
    for segment in os.getenv("AZURE_STORAGE_CONNECTION_STRING", "").split(";"):
        if "=" in segment:
            key, value = segment.split("=", 1)
            connection_parts[key.strip()] = value.strip()
    account_name = connection_parts.get("AccountName", "")
    account_key = connection_parts.get("AccountKey", "")
    account_url = os.getenv("AZURE_STORAGE_ACCOUNT_URL", "").strip().rstrip("/")
    if not account_url:
        account_url = connection_parts.get("BlobEndpoint", "").strip().rstrip("/")
    if not account_url and account_name:
        endpoint_suffix = connection_parts.get("EndpointSuffix", "core.windows.net")
        account_url = f"https://{account_name}.blob.{endpoint_suffix}"
    if not account_url.startswith("https://"):
        raise RuntimeError("Azure evidence-export account URL is unavailable")
    container_name = str(document.get("container_name") or "")
    blob_name = str(document.get("blob_name") or "")
    if not container_name or not blob_name:
        raise RuntimeError("Evidence-export storage reference is incomplete")
    from azure.storage.blob import BlobSasPermissions, generate_blob_sas

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=expires_minutes)
    if account_name and account_key:
        sas = generate_blob_sas(
            account_name=account_name,
            account_key=account_key,
            container_name=container_name,
            blob_name=blob_name,
            permission=BlobSasPermissions(read=True),
            start=now - timedelta(minutes=5),
            expiry=expires_at,
            protocol="https",
        )
        return f"{account_url}/{container_name}/{blob_name}?{sas}", expires_at

    from azure.identity.aio import DefaultAzureCredential
    from azure.storage.blob.aio import BlobServiceClient

    credential = DefaultAzureCredential()
    client = BlobServiceClient(account_url=account_url, credential=credential)
    try:
        delegation_key = await client.get_user_delegation_key(
            key_start_time=now - timedelta(minutes=5),
            key_expiry_time=expires_at + timedelta(minutes=5),
        )
        account_name = urlparse(account_url).netloc.split(".", 1)[0]
        sas = generate_blob_sas(
            account_name=account_name,
            container_name=container_name,
            blob_name=blob_name,
            user_delegation_key=delegation_key,
            permission=BlobSasPermissions(read=True),
            start=now - timedelta(minutes=5),
            expiry=expires_at,
            protocol="https",
        )
        return f"{account_url}/{container_name}/{blob_name}?{sas}", expires_at
    finally:
        await client.close()
        await credential.close()


@router.post("/cases/{case_id}/exports/{export_id}/download-link")
@limiter.limit("10/minute")
async def issue_evidence_export_download_link(
    request: Request,
    case_id: str,
    export_id: str,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "auditor"])),
    db=Depends(get_db),
):
    if not _evidence_export_enabled():
        raise HTTPException(status_code=503, detail="Evidence package export is temporarily unavailable")
    tenant_id = str(current_user["tenant_id"])
    await _case_or_404(db, tenant_id, case_id)
    document = await db.evidence_exports.find_one(
        {"tenant_id": tenant_id, "case_id": case_id, "export_id": export_id}
    )
    if not document:
        raise HTTPException(status_code=404, detail="Evidence export was not found")
    if document.get("status") != "READY":
        raise HTTPException(status_code=409, detail="Evidence export is not ready")
    expires_at = _utc_datetime(document.get("expires_at"))
    if expires_at is None or expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=410, detail="Evidence export availability has expired")
    sas_minutes = max(5, min(60, int(os.getenv("EVIDENCE_EXPORT_SAS_MINUTES", "30"))))
    try:
        url, link_expires_at = await _evidence_export_sas(document, sas_minutes)
    except Exception as exc:
        logger.exception("Evidence export authorization failed for %s", export_id)
        raise HTTPException(status_code=503, detail="Evidence export authorization is unavailable") from exc
    operation_id = str(getattr(request.state, "request_id", "") or uuid.uuid4().hex)
    await append_custody_event(
        db,
        tenant_id=tenant_id,
        case_id=case_id,
        action="EXPORT_LINK_ISSUED",
        actor=current_user,
        reason="Authorized a short-lived evidence package download link.",
        request_id=operation_id,
        metadata={"operation_id": operation_id, "export_id": export_id},
    )
    await db.evidence_exports.update_one(
        {"_id": document["_id"]},
        {
            "$set": {"last_link_issued_at": datetime.now(timezone.utc)},
            "$inc": {"link_issue_count": 1},
        },
    )
    return {
        "export_id": export_id,
        "url": url,
        "expires_at": link_expires_at,
        "package_sha256": document.get("package_sha256"),
    }

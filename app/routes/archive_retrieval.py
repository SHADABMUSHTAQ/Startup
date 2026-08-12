import logging
import os
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator, model_validator
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.database import get_db
from app.routes.admin import verify_admin
from app.routes.auth import get_current_user
from app.utils.archive_reader import archive_ledger_query
from app.utils.archive_retrieval import (
    authorized_archive_collections,
    included_retrieval_bytes,
    maximum_retrieval_blobs,
    normalize_collections,
    normalize_utc,
    retrieval_enabled,
    retrieval_month_key,
    serialize_retrieval,
    utc_now,
    validate_archive_collection_access,
)
from app.utils.rbac import RoleChecker


router = APIRouter()
logger = logging.getLogger(__name__)


class ArchiveRetrievalRequest(BaseModel):
    collections: list[str] = Field(min_length=1, max_length=6)
    start_at: datetime
    end_at: datetime
    reason: str = Field(min_length=8, max_length=500)

    @field_validator("collections")
    @classmethod
    def validate_collections(cls, value: list[str]) -> list[str]:
        try:
            return normalize_collections(value)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc

    @model_validator(mode="after")
    def validate_window(self):
        start_at = normalize_utc(self.start_at)
        end_at = normalize_utc(self.end_at)
        now = utc_now()
        if end_at <= start_at:
            raise ValueError("end_at must be later than start_at")
        if end_at > now + timedelta(minutes=5):
            raise ValueError("end_at cannot be in the future")
        if end_at - start_at > timedelta(days=2190):
            raise ValueError("Archive retrieval window cannot exceed 2190 days")
        self.start_at = start_at
        self.end_at = end_at
        return self


class ArchiveApprovalRequest(BaseModel):
    approval_reference: str = Field(min_length=3, max_length=200)
    expires_hours: int = Field(default=48, ge=1, le=72)


async def _estimate_selection(
    db,
    *,
    tenant_id: str,
    collections: list[str],
    start_at: datetime,
    end_at: datetime,
) -> dict:
    query = archive_ledger_query(
        tenant_id=tenant_id,
        collections=collections,
        start_dt=start_at,
        end_dt=end_at,
    )
    rows = await db["storage_archives"].aggregate(
        [
            {"$match": query},
            {
                "$group": {
                    "_id": None,
                    "blob_count": {"$sum": 1},
                    "estimated_bytes": {"$sum": {"$ifNull": ["$blob_size_bytes", 0]}},
                    "document_count": {"$sum": {"$ifNull": ["$document_count", 0]}},
                    "unknown_size_blobs": {
                        "$sum": {
                            "$cond": [
                                {
                                    "$gte": [
                                        {"$ifNull": ["$blob_size_bytes", -1]},
                                        0,
                                    ]
                                },
                                0,
                                1,
                            ]
                        }
                    },
                }
            },
        ]
    ).to_list(length=1)
    return rows[0] if rows else {
        "blob_count": 0,
        "estimated_bytes": 0,
        "document_count": 0,
        "unknown_size_blobs": 0,
    }


def _require_enabled() -> None:
    if not retrieval_enabled():
        raise HTTPException(
            status_code=503,
            detail="Historical retrieval is temporarily unavailable.",
        )


def _current_compliance_packs(current_user: dict) -> list[str]:
    packs = current_user.get("compliance_packs") or []
    return packs if isinstance(packs, list) else []


def _require_collection_access(current_user: dict, role: str, collections: list[str]) -> list[str]:
    try:
        return validate_archive_collection_access(
            collections,
            role=role,
            compliance_packs=_current_compliance_packs(current_user),
        )
    except PermissionError as exc:
        raise HTTPException(
            status_code=403,
            detail="Archive access is not permitted for this role or entitlement.",
        ) from exc


async def _reserve_included_allowance(db, tenant_id: str, billing_month: str) -> bool:
    now = utc_now()
    try:
        await db["archive_retrieval_allowances"].insert_one(
            {
                "tenant_id": tenant_id,
                "billing_month": billing_month,
                "reserved_at": now,
            }
        )
        return True
    except DuplicateKeyError:
        return False


async def _release_included_allowance(db, tenant_id: str, billing_month: str) -> None:
    await db["archive_retrieval_allowances"].delete_one(
        {"tenant_id": tenant_id, "billing_month": billing_month}
    )


@router.post("")
async def create_archive_retrieval(
    body: ArchiveRetrievalRequest,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "auditor"])),
):
    _require_enabled()
    tenant_id = str(current_user.get("tenant_id") or "").strip()
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Unauthorized tenant scope")
    authorized_collections = _require_collection_access(
        current_user,
        _role,
        body.collections,
    )

    estimate = await _estimate_selection(
        db,
        tenant_id=tenant_id,
        collections=authorized_collections,
        start_at=body.start_at,
        end_at=body.end_at,
    )
    blob_count = int(estimate.get("blob_count") or 0)
    if blob_count == 0:
        raise HTTPException(status_code=404, detail="No archived records match this request.")
    if blob_count > maximum_retrieval_blobs():
        raise HTTPException(
            status_code=413,
            detail="The archive request is too broad. Select a smaller date range or fewer sources.",
        )

    month_key = retrieval_month_key()
    estimated_bytes = int(estimate.get("estimated_bytes") or 0)
    estimate_exact = int(estimate.get("unknown_size_blobs") or 0) == 0
    eligible_for_included_allowance = (
        estimate_exact and estimated_bytes <= included_retrieval_bytes()
    )
    within_included_allowance = False
    if eligible_for_included_allowance:
        within_included_allowance = await _reserve_included_allowance(
            db,
            tenant_id,
            month_key,
        )
    now = utc_now()
    request_id = f"ARR-{uuid.uuid4().hex.upper()}"
    status = "APPROVED" if within_included_allowance else "PENDING_APPROVAL"
    doc = {
        "request_id": request_id,
        "tenant_id": tenant_id,
        "requested_by": str(current_user.get("username") or current_user.get("email") or ""),
        "requested_by_user_id": str(current_user.get("_id") or ""),
        "collections": authorized_collections,
        "start_at": body.start_at,
        "end_at": body.end_at,
        "reason": body.reason.strip(),
        "status": status,
        "billing_month": month_key,
        "included_allowance": within_included_allowance,
        "estimated_blob_count": blob_count,
        "estimated_document_count": int(estimate.get("document_count") or 0),
        "estimated_bytes": estimated_bytes,
        "estimate_exact": estimate_exact,
        "staging_expires_hours": 48,
        "created_at": now,
        "updated_at": now,
        "history": [
            {
                "status": "REQUESTED",
                "at": now,
                "actor": str(current_user.get("username") or current_user.get("email") or ""),
            },
            {
                "status": status,
                "at": now,
                "actor": "allowance-policy",
            },
        ],
    }
    try:
        await db["archive_retrieval_requests"].insert_one(doc)
    except Exception:
        if within_included_allowance:
            await _release_included_allowance(db, tenant_id, month_key)
        raise
    return serialize_retrieval(doc)


@router.get("")
async def list_archive_retrievals(
    limit: int = Query(default=50, ge=1, le=100),
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "auditor"])),
):
    tenant_id = str(current_user.get("tenant_id") or "").strip()
    allowed_collections = authorized_archive_collections(
        _role,
        _current_compliance_packs(current_user),
    )
    if not allowed_collections:
        return {"items": []}
    rows = await db["archive_retrieval_requests"].find(
        {
            "tenant_id": tenant_id,
            "collections": {
                "$not": {"$elemMatch": {"$nin": sorted(allowed_collections)}}
            },
        }
    ).sort("created_at", -1).limit(limit).to_list(length=limit)
    return {"items": [serialize_retrieval(row) for row in rows]}


@router.get("/{request_id}")
async def get_archive_retrieval(
    request_id: str,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "auditor"])),
):
    tenant_id = str(current_user.get("tenant_id") or "").strip()
    doc = await db["archive_retrieval_requests"].find_one(
        {"request_id": request_id, "tenant_id": tenant_id}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Archive retrieval request not found.")
    _require_collection_access(current_user, _role, doc.get("collections") or [])
    return serialize_retrieval(doc)


@router.post("/{request_id}/approve")
async def approve_archive_retrieval(
    request_id: str,
    body: ArchiveApprovalRequest,
    db=Depends(get_db),
    _admin_key: str = Depends(verify_admin),
):
    now = utc_now()
    result = await db["archive_retrieval_requests"].find_one_and_update(
        {"request_id": request_id, "status": "PENDING_APPROVAL"},
        {
            "$set": {
                "status": "APPROVED",
                "approval_reference": body.approval_reference.strip(),
                "staging_expires_hours": body.expires_hours,
                "approved_at": now,
                "updated_at": now,
            },
            "$push": {
                "history": {
                    "status": "APPROVED",
                    "at": now,
                    "actor": "warsoc-operations",
                }
            },
        },
        return_document=ReturnDocument.AFTER,
    )
    if not result:
        raise HTTPException(
            status_code=409,
            detail="Archive request is not awaiting approval.",
        )
    return serialize_retrieval(result)


async def _user_delegation_links(items: list[dict], expires_minutes: int) -> tuple[list[dict], datetime]:
    if os.getenv("AZURE_RETRIEVAL_SAS_MODE", "user_delegation").strip().lower() != "user_delegation":
        raise RuntimeError("User-delegation SAS is required")
    account_url = os.getenv("AZURE_STORAGE_ACCOUNT_URL", "").strip().rstrip("/")
    if not account_url or urlparse(account_url).scheme != "https":
        raise RuntimeError("AZURE_STORAGE_ACCOUNT_URL must be configured with HTTPS")

    from azure.identity.aio import DefaultAzureCredential
    from azure.storage.blob import BlobSasPermissions, generate_blob_sas
    from azure.storage.blob.aio import BlobServiceClient

    now = utc_now()
    expires_at = now + timedelta(minutes=expires_minutes)
    credential = DefaultAzureCredential()
    client = BlobServiceClient(account_url=account_url, credential=credential)
    try:
        delegation_key = await client.get_user_delegation_key(
            key_start_time=now - timedelta(minutes=5),
            key_expiry_time=expires_at + timedelta(minutes=5),
        )
        account_name = urlparse(account_url).netloc.split(".", 1)[0]
        links = []
        for item in items:
            container_name = str(item.get("staging_container") or "")
            blob_name = str(item.get("staging_blob_name") or "")
            if not container_name or not blob_name:
                continue
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
            links.append(
                {
                    "archive_key": item.get("archive_key"),
                    "collection": item.get("collection"),
                    "sha256": item.get("sha256"),
                    "bytes": item.get("bytes"),
                    "url": f"{account_url}/{container_name}/{blob_name}?{sas}",
                }
            )
        return links, expires_at
    finally:
        await client.close()
        await credential.close()


@router.post("/{request_id}/download-links")
async def issue_archive_download_links(
    request_id: str,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _role: str = Depends(RoleChecker(["admin", "manager", "auditor"])),
):
    _require_enabled()
    tenant_id = str(current_user.get("tenant_id") or "").strip()
    doc = await db["archive_retrieval_requests"].find_one(
        {"request_id": request_id, "tenant_id": tenant_id}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Archive retrieval request not found.")
    _require_collection_access(current_user, _role, doc.get("collections") or [])
    if doc.get("status") != "READY":
        raise HTTPException(status_code=409, detail="Archive retrieval is not ready.")
    expires_at = doc.get("expires_at")
    if not isinstance(expires_at, datetime) or normalize_utc(expires_at) <= utc_now():
        raise HTTPException(status_code=410, detail="Archive retrieval availability has expired.")

    expires_minutes = max(5, min(60, int(os.getenv("ARCHIVE_RETRIEVAL_SAS_MINUTES", "30"))))
    try:
        links, sas_expires_at = await _user_delegation_links(doc.get("items") or [], expires_minutes)
    except Exception as exc:
        logger.exception("Unable to issue archive download links for %s", request_id)
        raise HTTPException(
            status_code=503,
            detail="Archive download authorization is temporarily unavailable.",
        ) from exc
    if not links:
        raise HTTPException(status_code=409, detail="Archive retrieval has no downloadable objects.")

    now = utc_now()
    await db["archive_retrieval_requests"].update_one(
        {"request_id": request_id, "tenant_id": tenant_id},
        {
            "$set": {"last_link_issued_at": now, "updated_at": now},
            "$inc": {"download_link_issue_count": 1},
            "$push": {
                "history": {
                    "status": "DOWNLOAD_AUTHORIZED",
                    "at": now,
                    "actor": str(current_user.get("username") or current_user.get("email") or ""),
                }
            },
        },
    )
    return {"request_id": request_id, "expires_at": sas_expires_at, "items": links}

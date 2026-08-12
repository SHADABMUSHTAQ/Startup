import os
from datetime import datetime, timezone
from typing import Iterable

from app.utils.tenant_cache import normalize_pack_id


ALLOWED_ARCHIVE_COLLECTIONS = frozenset(
    {
        "logs",
        "siem_cold_vault",
        "security_alerts",
        "fbr_pos_logs",
        "peca_forensic_logs",
        "csv_uploads",
    }
)
OPERATIONAL_ARCHIVE_COLLECTIONS = frozenset(
    {
        "logs",
        "siem_cold_vault",
        "security_alerts",
        "csv_uploads",
    }
)
COMPLIANCE_ARCHIVE_PACKS = {
    "fbr_pos_logs": "fbr_pos",
    "peca_forensic_logs": "peca_forensic",
}
TERMINAL_RETRIEVAL_STATUSES = frozenset({"EXPIRED", "FAILED", "REJECTED", "CANCELLED"})


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)


def retrieval_enabled() -> bool:
    return os.getenv("ARCHIVE_RETRIEVAL_ENABLED", "false").strip().lower() == "true"


def retrieval_month_key(value: datetime | None = None) -> str:
    current = normalize_utc(value or utc_now())
    return f"{current:%Y-%m}"


def included_retrieval_bytes() -> int:
    default = 10 * 1024 * 1024 * 1024
    try:
        return max(1, int(os.getenv("ARCHIVE_RETRIEVAL_INCLUDED_BYTES", str(default))))
    except ValueError:
        return default


def maximum_retrieval_blobs() -> int:
    try:
        return max(1, min(1000, int(os.getenv("ARCHIVE_RETRIEVAL_MAX_BLOBS", "100"))))
    except ValueError:
        return 100


def normalize_collections(values: Iterable[str]) -> list[str]:
    normalized = sorted({str(value).strip() for value in values if str(value).strip()})
    invalid = sorted(set(normalized) - ALLOWED_ARCHIVE_COLLECTIONS)
    if invalid:
        raise ValueError(f"Unsupported archive collections: {', '.join(invalid)}")
    if not normalized:
        raise ValueError("At least one archive collection is required")
    return normalized


def authorized_archive_collections(role: str, compliance_packs: Iterable[str]) -> frozenset[str]:
    """Return archive classes visible to the current database-backed role."""
    normalized_role = str(role or "").strip().lower()
    entitled_packs = {
        normalize_pack_id(pack)
        for pack in compliance_packs or []
        if normalize_pack_id(pack)
    }

    allowed: set[str] = set()
    if normalized_role in {"admin", "manager"}:
        allowed.update(OPERATIONAL_ARCHIVE_COLLECTIONS)
    if normalized_role in {"admin", "auditor"}:
        allowed.update(
            collection
            for collection, pack in COMPLIANCE_ARCHIVE_PACKS.items()
            if pack in entitled_packs
        )
    return frozenset(allowed)


def validate_archive_collection_access(
    collections: Iterable[str],
    *,
    role: str,
    compliance_packs: Iterable[str],
) -> list[str]:
    normalized = normalize_collections(collections)
    allowed = authorized_archive_collections(role, compliance_packs)
    if any(collection not in allowed for collection in normalized):
        raise PermissionError("Archive collection access is outside the current role or entitlement")
    return normalized


def serialize_retrieval(doc: dict) -> dict:
    result = dict(doc)
    result.pop("_id", None)
    result.pop("worker_lease", None)
    result.pop("last_error_internal", None)
    items = []
    for item in result.get("items") or []:
        public_item = {
            "archive_key": item.get("archive_key"),
            "collection": item.get("collection"),
            "status": item.get("status"),
            "bytes": item.get("bytes"),
        }
        items.append(public_item)
    result["items"] = items
    return result

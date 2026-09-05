"""Explicit evidence holds; absence of a record never implies a hold decision."""

from __future__ import annotations

from datetime import datetime, timezone

from app.utils.fbr_retention import FBR_ACTIVE_RETENTION_MODEL, FBR_RETENTION_STATE_HELD


ACTIVE_HOLD_STATES = {"ACTIVE", "PENDING_RELEASE"}


def archive_query_for_hold(hold: dict) -> dict:
    """Build the tenant-scoped archive-ledger query for one hold."""
    query = {"tenant_id": str(hold.get("tenant_id") or "")}
    scope_type = str(hold.get("scope_type") or "").upper()
    if scope_type in {"COLLECTION", "EVENT"}:
        query["collection"] = str(hold.get("collection") or "")
    if scope_type == "EVENT":
        query["event_uids"] = str(hold.get("event_uid") or "")
    return query


def hold_applies_to_document(hold: dict, collection_name: str, document: dict) -> bool:
    if str(hold.get("status") or "").upper() not in ACTIVE_HOLD_STATES:
        return False
    scope_type = str(hold.get("scope_type") or "").upper()
    if scope_type == "TENANT":
        return True
    if scope_type == "COLLECTION":
        return str(hold.get("collection") or "") == collection_name
    if scope_type == "EVENT":
        return (
            str(hold.get("collection") or "") == collection_name
            and str(hold.get("event_uid") or "") == str(document.get("event_uid") or "")
        )
    return False


def apply_active_holds(document: dict, holds: list[dict]) -> dict:
    active = [hold for hold in holds if str(hold.get("status") or "").upper() in ACTIVE_HOLD_STATES]
    if not active:
        return document
    document["retention_state"] = FBR_RETENTION_STATE_HELD
    # Tax-period expiry fields only describe legacy records. Active evidence is
    # protected by the explicit hold ledger checked by the archiver.
    if document.get("retention_model") != FBR_ACTIVE_RETENTION_MODEL:
        document["automatic_archive_expiry_allowed"] = False
        document["effective_retention_until"] = None
    document["active_hold_ids"] = sorted(
        str(hold.get("hold_id") or hold.get("_id")) for hold in active
    )
    document["hold_evaluated_at"] = datetime.now(timezone.utc)
    return document

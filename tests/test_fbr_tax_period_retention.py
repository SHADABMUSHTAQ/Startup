from datetime import datetime, timezone

import pytest

from app.utils.evidence_holds import apply_active_holds, hold_applies_to_document
from app.utils.evidence_locks import acquire_retention_fence, release_retention_fence
from app.utils.fbr_retention import (
    FBR_ACTIVE_RETENTION_MODEL,
    FBR_RETENTION_STATE_HELD,
    FBR_RETENTION_STATE_RESOLVED,
    FBR_RETENTION_STATE_TENANT_POLICY,
    apply_fbr_tenant_retention,
    resolve_fbr_retention_metadata,
    tenant_fbr_retention_metadata,
)


PROFILE = {
    "tax_regime": "PK_SALES_TAX",
    "period_type": "CALENDAR_MONTH",
    "timezone": "Asia/Karachi",
    "period_id_prefix": "PK-ST",
    "version": "pilot-policy-1",
}


def test_active_fbr_retention_inherits_tenant_entitlement():
    metadata = tenant_fbr_retention_metadata(180)

    assert metadata["retention_model"] == FBR_ACTIVE_RETENTION_MODEL
    assert metadata["retention_state"] == FBR_RETENTION_STATE_TENANT_POLICY
    assert metadata["retention_basis"] == "TENANT_RETENTION_ENTITLEMENT"
    assert metadata["retention_policy"] == "TENANT_ENTITLEMENT"
    assert metadata["tenant_retention_days_at_ingest"] == 180


def test_active_fbr_retention_removes_legacy_tax_period_fields():
    document = apply_fbr_tenant_retention(
        {
            "timestamp": "2026-08-15T12:00:00Z",
            "_expire_at": datetime.now(timezone.utc),
            "tax_period_id": "PK-ST-2026-08",
            "effective_retention_until": datetime(2032, 8, 31, tzinfo=timezone.utc),
        },
        90,
    )
    assert document["retention_state"] == FBR_RETENTION_STATE_TENANT_POLICY
    assert document["tenant_retention_days_at_ingest"] == 90
    assert "_expire_at" not in document
    assert "tax_period_id" not in document
    assert "effective_retention_until" not in document


def test_legacy_tax_period_metadata_remains_readable_for_historical_records():
    metadata = resolve_fbr_retention_metadata("2026-08-15T12:00:00Z", PROFILE)
    assert metadata["retention_state"] == FBR_RETENTION_STATE_RESOLVED
    assert metadata["tax_period_id"] == "PK-ST-2026-08"


def test_only_explicit_applicable_hold_blocks_final_expiry():
    document = apply_fbr_tenant_retention(
        {"event_uid": "invoice-event-1", "timestamp": "2026-08-15T12:00:00Z"},
        90,
    )
    unrelated = {
        "hold_id": "hold-other",
        "status": "ACTIVE",
        "scope_type": "EVENT",
        "collection": "fbr_pos_logs",
        "event_uid": "another-event",
    }
    applicable = {
        "hold_id": "hold-invoice-1",
        "status": "ACTIVE",
        "scope_type": "EVENT",
        "collection": "fbr_pos_logs",
        "event_uid": "invoice-event-1",
    }
    assert hold_applies_to_document(unrelated, "fbr_pos_logs", document) is False
    assert hold_applies_to_document(applicable, "fbr_pos_logs", document) is True

    apply_active_holds(document, [applicable])
    assert document["retention_state"] == FBR_RETENTION_STATE_HELD
    assert "effective_retention_until" not in document
    assert "automatic_archive_expiry_allowed" not in document
    assert document["active_hold_ids"] == ["hold-invoice-1"]


def test_legacy_hold_metadata_remains_compatible():
    document = {
        "event_uid": "legacy-invoice-event",
        "retention_state": FBR_RETENTION_STATE_RESOLVED,
    }
    apply_active_holds(
        document,
        [{"hold_id": "legacy-hold", "status": "ACTIVE", "scope_type": "TENANT"}],
    )
    assert document["retention_state"] == FBR_RETENTION_STATE_HELD
    assert document["effective_retention_until"] is None
    assert document["automatic_archive_expiry_allowed"] is False


@pytest.mark.asyncio
async def test_hold_lifecycle_is_tenant_scoped_and_audited(async_client, auth_headers, db):
    applied = await async_client.post(
        "/api/v1/compliance/holds",
        headers=auth_headers,
        json={
            "scope_type": "EVENT",
            "collection": "fbr_pos_logs",
            "event_uid": "invoice-event-api-1",
            "reason": "Preserve evidence while the tax proceeding remains open.",
            "authority": "WarSOC tenant administrator",
            "proceeding_reference": "TAX-CASE-2026-001",
        },
    )
    assert applied.status_code == 201, applied.text
    hold = applied.json()["hold"]
    assert hold["status"] == "ACTIVE"
    assert "created_by_user_id" not in hold

    listed = await async_client.get(
        "/api/v1/compliance/holds?status=ACTIVE",
        headers=auth_headers,
    )
    assert listed.status_code == 200, listed.text
    assert [item["hold_id"] for item in listed.json()["holds"]] == [hold["hold_id"]]

    released = await async_client.post(
        f"/api/v1/compliance/holds/{hold['hold_id']}/release",
        headers=auth_headers,
        json={
            "reason": "The proceeding has reached a documented final decision.",
            "authority": "WarSOC tenant administrator",
        },
    )
    assert released.status_code == 200, released.text
    assert released.json()["hold"]["status"] == "RELEASED"
    audit = await db.evidence_hold_audit.find(
        {"hold_id": hold["hold_id"], "status": "COMMITTED"}
    ).sort("created_at", 1).to_list(10)
    assert [item["action"] for item in audit] == ["APPLY", "RELEASE"]


@pytest.mark.asyncio
async def test_retention_fence_excludes_competing_hold_and_archive_transitions(db):
    await db.evidence_retention_fences.create_index("lock_id", unique=True)

    assert await acquire_retention_fence(db, "TENANT-A", "hold-owner") is True
    assert await acquire_retention_fence(db, "TENANT-A", "archive-owner") is False

    await release_retention_fence(db, "TENANT-A", "wrong-owner")
    assert await acquire_retention_fence(db, "TENANT-A", "archive-owner") is False

    await release_retention_fence(db, "TENANT-A", "hold-owner")
    assert await acquire_retention_fence(db, "TENANT-A", "archive-owner") is True
    await release_retention_fence(db, "TENANT-A", "archive-owner")

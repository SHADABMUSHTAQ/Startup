from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

from app.utils.fbr_reconciliation import FBRSourceEvidence, reconcile_fbr_evidence


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)


def _record(source: str, **overrides) -> FBRSourceEvidence:
    values = {
        "tenant_id": "TENANT-A",
        "invoice_id": "INV-100",
        "source_type": source,
        "source_identity": f"approved-{source.lower()}-source",
        "source_record_id": f"{source}-record-1",
        "observed_at": NOW,
        "received_at": NOW + timedelta(seconds=2),
        "raw_sha256": {"POS": "a", "DB": "b", "EXTERNAL": "c"}[source] * 64,
    }
    if source in {"POS", "DB"}:
        values.update(
            {
                "seller_id": "SELLER-1",
                "buyer_id": "BUYER-1",
                "gross_amount": Decimal("50000.00"),
                "tax_amount": Decimal("7500.00"),
                "transaction_type": "SALE",
                "invoice_timestamp": NOW,
            }
        )
    else:
        values.update({"submission_status": "ACCEPTED", "external_reference": "FBR-REF-1"})
    values.update(overrides)
    return FBRSourceEvidence(**values)


def test_exact_three_source_match():
    result = reconcile_fbr_evidence([_record("POS"), _record("DB"), _record("EXTERNAL")])
    assert result["outcome"] == "MATCHED"
    assert result["confidence"] == "VERIFIED"
    assert result["production_claim"] == "CONTRACT_LAB_PROVEN_ONLY"


def test_field_mismatch_never_becomes_green():
    result = reconcile_fbr_evidence(
        [_record("POS"), _record("DB", gross_amount=Decimal("35000")), _record("EXTERNAL")]
    )
    assert result["outcome"] == "MISMATCH"


def test_duplicate_source_is_unverified():
    result = reconcile_fbr_evidence(
        [_record("POS"), _record("POS", source_record_id="POS-record-2"), _record("DB")]
    )
    assert result["outcome"] == "UNVERIFIED"
    assert "DUPLICATE_SOURCE_RECORD" in result["reasons"]


def test_late_db_match_is_explicitly_degraded():
    result = reconcile_fbr_evidence(
        [
            _record("POS"),
            _record("DB", observed_at=NOW + timedelta(days=2)),
            _record("EXTERNAL"),
        ]
    )
    assert result["outcome"] == "MATCHED"
    assert result["confidence"] == "DEGRADED"
    assert "LATE_DB_EVIDENCE" in result["reasons"]


def test_external_rejection_is_preserved():
    result = reconcile_fbr_evidence(
        [_record("POS"), _record("DB"), _record("EXTERNAL", submission_status="REJECTED")]
    )
    assert result["outcome"] == "REJECTED"


def test_external_timeout_remains_pending():
    result = reconcile_fbr_evidence(
        [
            _record("POS"),
            _record("DB"),
            _record("EXTERNAL", submission_status="PENDING", external_reference=None),
        ]
    )
    assert result["outcome"] == "PENDING"


def test_missing_pos_is_missing_local():
    result = reconcile_fbr_evidence([_record("DB"), _record("EXTERNAL")])
    assert result["outcome"] == "MISSING_LOCAL"
    assert "POS_EVIDENCE_MISSING" in result["reasons"]


def test_missing_db_is_missing_local():
    result = reconcile_fbr_evidence([_record("POS"), _record("EXTERNAL")])
    assert result["outcome"] == "MISSING_LOCAL"
    assert "DB_EVIDENCE_MISSING" in result["reasons"]


def test_missing_external_is_never_matched():
    result = reconcile_fbr_evidence([_record("POS"), _record("DB")])
    assert result["outcome"] == "MISSING_EXTERNAL"


def test_replay_is_unverified():
    result = reconcile_fbr_evidence(
        [_record("POS", replay_detected=True), _record("DB"), _record("EXTERNAL")]
    )
    assert result["outcome"] == "UNVERIFIED"
    assert "SOURCE_REPLAY_DETECTED" in result["reasons"]

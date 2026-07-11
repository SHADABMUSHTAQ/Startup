from datetime import datetime, timezone
from pathlib import Path

from app.utils.compliance_chain import (
    CHAIN_VERSION,
    aggregate_evidence_digest,
    compute_daily_root,
    evidence_record_digest,
    genesis_root,
    verify_ledger_entry,
    verify_ledger_sequence,
)


def _ledger(date_str: str, previous_root: str, evidence_digest: str = "a" * 64):
    source_counts = {"peca_forensic_logs": 1}
    daily_root = compute_daily_root(
        tenant_id="TENANT-A",
        date_str=date_str,
        previous_root_hash=previous_root,
        evidence_digest=evidence_digest,
        log_count=1,
        source_counts=source_counts,
    )
    return {
        "tenant_id": "TENANT-A",
        "date": date_str,
        "chain_version": CHAIN_VERSION,
        "previous_root_hash": previous_root,
        "evidence_digest": evidence_digest,
        "daily_root_hash": daily_root,
        "log_count": 1,
        "source_counts": source_counts,
    }


def test_evidence_digest_is_deterministic_and_excludes_ttl_mechanics():
    first = {
        "tenant_id": "TENANT-A",
        "event_uid": "Security:42",
        "timestamp": datetime(2026, 7, 10, tzinfo=timezone.utc),
        "raw_data": {"b": 2, "a": 1},
        "_expire_at": datetime(2026, 7, 17, tzinfo=timezone.utc),
    }
    second = {
        "raw_data": {"a": 1, "b": 2},
        "timestamp": datetime(2026, 7, 10, tzinfo=timezone.utc),
        "event_uid": "Security:42",
        "tenant_id": "TENANT-A",
        "_expire_at": datetime(2030, 1, 1, tzinfo=timezone.utc),
    }
    assert evidence_record_digest("peca_forensic_logs", first) == evidence_record_digest(
        "peca_forensic_logs", second
    )

    tampered = {**second, "raw_data": {"a": 1, "b": 3}}
    assert evidence_record_digest("peca_forensic_logs", first) != evidence_record_digest(
        "peca_forensic_logs", tampered
    )


def test_daily_chain_detects_entry_tampering_and_broken_links():
    first = _ledger("2026-07-08", genesis_root("TENANT-A"))
    second = _ledger("2026-07-09", first["daily_root_hash"], evidence_digest="b" * 64)
    assert verify_ledger_entry(first)
    assert verify_ledger_sequence([first, second])["verified"] is True

    tampered = {**second, "log_count": 2}
    result = verify_ledger_sequence([first, tampered])
    assert result["verified"] is False
    assert result["invalid_dates"] == ["2026-07-09"]

    reset = {**second, "chain_reset_reason": "previous_ledger_missing_or_unverified"}
    reset_result = verify_ledger_sequence([reset])
    assert reset_result["verified"] is True
    assert reset_result["continuous"] is False
    assert reset_result["status"] == "VERIFIED_WITH_RESET"


def test_aggregate_digest_commits_to_collection_and_record_order():
    records = [
        ("peca_forensic_logs", {"event_uid": "a", "event_id": "4625"}),
        ("fbr_pos_logs", {"event_uid": "b", "event_id": "FBR-INV-DEL"}),
    ]
    digest, count, source_counts = aggregate_evidence_digest(records)
    reversed_digest, _, _ = aggregate_evidence_digest(reversed(records))
    assert len(digest) == 64
    assert count == 2
    assert source_counts == {"peca_forensic_logs": 1, "fbr_pos_logs": 1}
    assert digest != reversed_digest


def test_reports_no_longer_make_unconditional_legal_or_sealing_claims():
    root = Path(__file__).resolve().parents[1]
    cron_text = (root / "app/workers/compliance_cron.py").read_text(encoding="utf-8")
    report_text = (root / "app/utils/report_engine.py").read_text(encoding="utf-8")
    export_text = (root / "app/routes/export.py").read_text(encoding="utf-8")
    assert "sealed-disabled" not in cron_text
    assert "serves as a legally admissible" not in report_text
    assert "verify_ledger_sequence" in report_text
    assert "legally admissible and non-repudiable" not in export_text
    assert "This PDF is an evidence summary and is not itself digitally signed" in export_text

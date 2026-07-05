from datetime import datetime, timezone

import pytest

from app.workers import storage_archiver


def test_compliance_hot_retention_is_separate_from_vault_retention():
    assert storage_archiver._effective_retention_days("fbr_pos_logs", 90) == 7
    assert storage_archiver._effective_retention_days("peca_forensic_logs", 90) == 30
    assert storage_archiver.COMPLIANCE_VAULT_RETENTION_DAYS["fbr_pos_logs"] == 2190
    assert storage_archiver.COMPLIANCE_VAULT_RETENTION_DAYS["peca_forensic_logs"] == 365
    assert storage_archiver._effective_retention_days("logs", 90) == 90


def test_archive_cutoff_uses_compliance_hot_window():
    now = datetime(2026, 6, 30, tzinfo=timezone.utc)
    fbr_cutoff, _ = storage_archiver._archive_cutoffs(
        "fbr_pos_logs",
        tenant_retention_days=90,
        archive_lead_days=1,
        now=now,
    )
    peca_cutoff, _ = storage_archiver._archive_cutoffs(
        "peca_forensic_logs",
        tenant_retention_days=90,
        archive_lead_days=1,
        now=now,
    )
    assert (now - fbr_cutoff).days == 7
    assert (now - peca_cutoff).days == 30


@pytest.mark.asyncio
async def test_archiver_fails_when_azure_configuration_is_missing(monkeypatch):
    monkeypatch.delenv("AZURE_STORAGE_CONNECTION_STRING", raising=False)
    with pytest.raises(RuntimeError, match="AZURE_STORAGE_CONNECTION_STRING"):
        await storage_archiver.run_archiver()


def test_production_archiver_is_scheduled_and_requires_azure_secret():
    from pathlib import Path

    compose_text = (
        Path(__file__).resolve().parents[1] / "docker-compose.prod.yml"
    ).read_text(encoding="utf-8")
    service = compose_text.split("  storage-archiver:", 1)[1].split("  mongodb:", 1)[0]
    assert 'profiles: ["maintenance"]' not in service
    assert "restart: on-failure" in service
    assert "AZURE_STORAGE_CONNECTION_STRING required" in service
    assert "ARCHIVE_INTERVAL_SECONDS" in service

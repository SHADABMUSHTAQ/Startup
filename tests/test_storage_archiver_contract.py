import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.workers import storage_archiver
from app.utils import archive_reader


def test_compliance_hot_retention_is_separate_from_vault_retention():
    assert storage_archiver._effective_retention_days("fbr_pos_logs", 90) == 7
    assert storage_archiver._effective_retention_days("peca_forensic_logs", 90) == 30
    assert storage_archiver._effective_retention_days("siem_cold_vault", 90) == 7
    assert storage_archiver._effective_retention_days("security_alerts", 90) == 7
    assert storage_archiver._effective_retention_days("logs", 90) == 7
    assert storage_archiver.COMPLIANCE_VAULT_RETENTION_DAYS["fbr_pos_logs"] == 2190
    assert storage_archiver.COMPLIANCE_VAULT_RETENTION_DAYS["peca_forensic_logs"] == 365
    assert storage_archiver._effective_vault_retention_days("siem_cold_vault", 365) == 365


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


def test_siem_hot_retention_is_capped_to_seven_days():
    assert 1 <= storage_archiver.DEFAULT_SIEM_HOT_RETENTION_DAYS <= 7
    assert 1 <= storage_archiver.DEFAULT_RAW_LOG_HOT_RETENTION_DAYS <= 7
    assert storage_archiver._effective_retention_days("siem_cold_vault", 90) == 7
    assert storage_archiver._effective_retention_days("security_alerts", 90) == 7
    assert storage_archiver._effective_retention_days("logs", 90) == 7


def test_blob_immutability_requires_locked_policy_through_retention():
    required_until = datetime(2032, 7, 10, tzinfo=timezone.utc)
    adequate = SimpleNamespace(
        has_legal_hold=False,
        immutability_policy=SimpleNamespace(
            policy_mode="Locked",
            expiry_time=datetime(2032, 7, 11, tzinfo=timezone.utc),
        ),
    )
    unlocked = SimpleNamespace(
        has_legal_hold=False,
        immutability_policy=SimpleNamespace(
            policy_mode="Unlocked",
            expiry_time=datetime(2035, 1, 1, tzinfo=timezone.utc),
        ),
    )
    assert storage_archiver._blob_immutability_status(adequate, required_until)["verified"] is True
    assert storage_archiver._blob_immutability_status(unlocked, required_until)["verified"] is False


@pytest.mark.asyncio
async def test_archive_never_deletes_hot_records_without_verified_immutability(monkeypatch):
    unlocked_properties = SimpleNamespace(
        has_legal_hold=False,
        immutability_policy=SimpleNamespace(
            policy_mode="Unlocked",
            expiry_time=datetime(2035, 1, 1, tzinfo=timezone.utc),
        ),
    )

    class FakeBlob:
        async def upload_blob(self, *_args, **_kwargs):
            return None

        async def get_blob_properties(self):
            return unlocked_properties

    class FakeContainer:
        def get_blob_client(self, _name):
            return FakeBlob()

    class FakeCollection:
        def __init__(self):
            self.delete_many = AsyncMock()
            self.insert_one = AsyncMock()

    collections = {
        "storage_archives": FakeCollection(),
        "fbr_pos_logs": FakeCollection(),
    }

    class FakeDb:
        def __getitem__(self, name):
            return collections[name]

    monkeypatch.setenv("AZURE_IMMUTABILITY_REQUIRED", "true")
    with pytest.raises(RuntimeError, match="not protected"):
        await storage_archiver._archive_batch(
            FakeContainer(),
            FakeDb(),
            "TENANT-A",
            "fbr_pos_logs",
            [{"_id": "doc-1", "timestamp": datetime.now(timezone.utc)}],
            "run-1",
            1,
            90,
        )
    collections["fbr_pos_logs"].delete_many.assert_not_awaited()
    collections["storage_archives"].insert_one.assert_not_awaited()


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


def test_archive_managed_collections_have_no_independent_ttl_deletion():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    database_text = (root / "app/database.py").read_text(encoding="utf-8")
    init_text = (root / "app/db/init_db.py").read_text(encoding="utf-8")

    assert 'await _ensure_ttl("fbr_pos_logs"' not in database_text
    assert 'await _ensure_ttl("peca_forensic_logs"' not in database_text
    assert 'await _ensure_ttl("security_alerts"' not in database_text
    for collection_name in (
        "logs",
        "siem_cold_vault",
        "security_alerts",
        "fbr_pos_logs",
        "peca_forensic_logs",
        "csv_uploads",
        "analysis_results",
    ):
        assert f'_drop_ttl_indexes(db.{collection_name}, "{collection_name}")' in init_text
    assert "expireAfterSeconds=" not in init_text


@pytest.mark.asyncio
async def test_archive_reader_verifies_integrity_filters_and_deduplicates(monkeypatch):
    document = {
        "_id": "abc123",
        "tenant_id": "TENANT-A",
        "event_id": "4625",
        "event_uid": "Security:42",
        "timestamp": "2026-07-01T10:00:00+00:00",
        "source_ip": "203.0.113.10",
    }
    valid_blob = json.dumps([document]).encode("utf-8")
    tampered_blob = json.dumps([{**document, "source_ip": "198.51.100.9"}]).encode("utf-8")
    entries = [
        {
            "blob_name": "valid.json",
            "collection": "siem_cold_vault",
            "sha256": hashlib.sha256(valid_blob).hexdigest(),
        },
        {
            "blob_name": "duplicate.json",
            "collection": "siem_cold_vault",
            "sha256": hashlib.sha256(valid_blob).hexdigest(),
        },
        {
            "blob_name": "tampered.json",
            "collection": "siem_cold_vault",
            "sha256": "0" * 64,
        },
    ]

    class FakeCursor:
        def __init__(self, rows):
            self.rows = rows

        def sort(self, *_args):
            return self

        def limit(self, value):
            self.rows = self.rows[:value]
            return self

        async def to_list(self, length):
            return self.rows[:length]

    class FakeLedger:
        def __init__(self):
            self.query = None

        def find(self, query):
            self.query = query
            return FakeCursor(list(entries))

    class FakeDownloader:
        def __init__(self, payload):
            self.payload = payload

        async def readall(self):
            return self.payload

    class FakeBlob:
        def __init__(self, payload):
            self.payload = payload

        async def download_blob(self):
            return FakeDownloader(self.payload)

    class FakeContainer:
        def get_blob_client(self, name):
            payloads = {
                "valid.json": valid_blob,
                "duplicate.json": valid_blob,
                "tampered.json": tampered_blob,
            }
            return FakeBlob(payloads[name])

    class FakeBlobService:
        @classmethod
        def from_connection_string(cls, _connection_string):
            return cls()

        def get_container_client(self, _container_name):
            return FakeContainer()

        async def close(self):
            return None

    ledger = FakeLedger()
    fake_db = {"storage_archives": ledger}
    monkeypatch.setenv("AZURE_STORAGE_CONNECTION_STRING", "UseDevelopmentStorage=true")
    monkeypatch.setattr(archive_reader, "BlobServiceClient", FakeBlobService)

    docs, total = await archive_reader.fetch_archived_documents(
        fake_db,
        tenant_id="TENANT-A",
        collections=["siem_cold_vault"],
        start_dt=datetime(2026, 7, 1, tzinfo=timezone.utc),
        event_id="4625",
        search_term="203.0",
        limit=10,
    )

    assert total == 1
    assert docs[0]["event_uid"] == "Security:42"
    assert docs[0]["_archived"] is True
    assert "$and" in ledger.query

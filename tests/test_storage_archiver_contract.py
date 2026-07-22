import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.workers import storage_archiver
from app.utils import archive_reader
from app.routes import compliance
from app.routes.compliance import _curate_evidence_record


def test_compliance_evidence_exposes_safe_storage_tier_provenance():
    hot = _curate_evidence_record(
        {"event_id": "4688"},
        "peca_forensic",
        "peca_forensic_logs",
    )
    archived = _curate_evidence_record(
        {"event_id": "4688", "_archived": True},
        "peca_forensic",
        "peca_forensic_logs",
    )

    assert hot["storage_tier"] == "hot"
    assert hot["archived"] is False
    assert archived["storage_tier"] == "cold_archive"
    assert archived["archived"] is True
    assert "_archive_blob_name" not in archived


def test_archive_reader_search_matches_title_and_message_substrings():
    assert archive_reader._search_matches(
        {"title": "Potential command injection activity detected"},
        "command injection",
    )
    assert archive_reader._search_matches(
        {"message": "Security Event: Network Connection Blocked"},
        "connection blocked",
    )
    assert not archive_reader._search_matches(
        {"title": "Successful login"},
        "command injection",
    )


@pytest.mark.asyncio
async def test_archive_ledger_count_does_not_download_blobs():
    class FakeAggregateCursor:
        async def to_list(self, length):
            return [{"_id": None, "total": 125}][:length]

    class FakeLedger:
        def __init__(self):
            self.count_documents = AsyncMock(return_value=0)

        def aggregate(self, pipeline):
            self.pipeline = pipeline
            return FakeAggregateCursor()

    ledger = FakeLedger()
    total, exact = await archive_reader.count_archived_documents(
        {"storage_archives": ledger},
        tenant_id="TENANT-A",
        collections=["peca_forensic_logs"],
    )

    assert total == 125
    assert exact is True
    ledger.count_documents.assert_awaited_once()
    assert ledger.pipeline[0]["$match"]["status"] == "archived"


@pytest.mark.asyncio
async def test_compliance_full_hot_page_skips_azure_blob_reads(monkeypatch):
    count_mock = AsyncMock(return_value=(900, True))
    fetch_mock = AsyncMock()
    monkeypatch.setattr(compliance, "count_archived_documents", count_mock)
    monkeypatch.setattr(compliance, "_fetch_archived_page", fetch_mock)

    archived, total, meta = await compliance._resolve_archive_page(
        object(),
        tenant_id="TENANT-A",
        collection_names=["peca_forensic_logs"],
        hot_total=100,
        hot_docs=[{"event_uid": f"hot-{i}"} for i in range(50)],
        skip=0,
        limit=50,
        start_dt=None,
        end_dt=None,
        event_id=None,
    )

    assert archived == []
    assert total == 1000
    assert meta == {
        "archive_read_performed": False,
        "archive_rows": 900,
        "total_is_exact": True,
    }
    fetch_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_compliance_boundary_page_reads_only_missing_cold_rows(monkeypatch):
    monkeypatch.setattr(
        compliance,
        "count_archived_documents",
        AsyncMock(return_value=(4, True)),
    )
    fetch_mock = AsyncMock(
        return_value=([{"event_uid": "cold-1"}, {"event_uid": "cold-2"}], 4)
    )
    monkeypatch.setattr(compliance, "_fetch_archived_page", fetch_mock)

    archived, total, meta = await compliance._resolve_archive_page(
        object(),
        tenant_id="TENANT-A",
        collection_names=["peca_forensic_logs"],
        hot_total=2,
        hot_docs=[{"event_uid": "hot-2"}],
        skip=1,
        limit=3,
        start_dt=None,
        end_dt=None,
        event_id=None,
    )

    assert [doc["event_uid"] for doc in archived] == ["cold-1", "cold-2"]
    assert total == 6
    assert meta["archive_read_performed"] is True
    assert fetch_mock.await_args.kwargs["skip"] == 0
    assert fetch_mock.await_args.kwargs["limit"] == 2


@pytest.mark.asyncio
async def test_compliance_cold_page_applies_archive_offset(monkeypatch):
    monkeypatch.setattr(
        compliance,
        "count_archived_documents",
        AsyncMock(return_value=(10, True)),
    )
    fetch_mock = AsyncMock(return_value=([{"event_uid": "cold-4"}], 10))
    monkeypatch.setattr(compliance, "_fetch_archived_page", fetch_mock)

    archived, total, _ = await compliance._resolve_archive_page(
        object(),
        tenant_id="TENANT-A",
        collection_names=["fbr_pos_logs"],
        hot_total=3,
        hot_docs=[],
        skip=7,
        limit=1,
        start_dt=None,
        end_dt=None,
        event_id=None,
    )

    assert archived[0]["event_uid"] == "cold-4"
    assert total == 13
    assert fetch_mock.await_args.kwargs["skip"] == 4


@pytest.mark.asyncio
async def test_filtered_full_hot_page_is_fast_and_marks_total_inexact(monkeypatch):
    count_mock = AsyncMock()
    fetch_mock = AsyncMock()
    monkeypatch.setattr(compliance, "count_archived_documents", count_mock)
    monkeypatch.setattr(compliance, "_fetch_archived_page", fetch_mock)

    archived, total, meta = await compliance._resolve_archive_page(
        object(),
        tenant_id="TENANT-A",
        collection_names=["peca_forensic_logs"],
        hot_total=50,
        hot_docs=[{"event_uid": f"hot-{i}"} for i in range(10)],
        skip=0,
        limit=10,
        start_dt=None,
        end_dt=None,
        event_id="4688",
    )

    assert archived == []
    assert total == 50
    assert meta["total_is_exact"] is False
    count_mock.assert_not_awaited()
    fetch_mock.assert_not_awaited()


def test_compliance_hot_retention_is_separate_from_vault_retention():
    assert storage_archiver._effective_retention_days("fbr_pos_logs", 90) == 7
    assert storage_archiver._effective_retention_days("peca_forensic_logs", 90) == 7
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
    assert (now - peca_cutoff).days == 7


def test_siem_hot_retention_is_capped_to_seven_days():
    assert 1 <= storage_archiver.DEFAULT_SIEM_HOT_RETENTION_DAYS <= 7
    assert 1 <= storage_archiver.DEFAULT_RAW_LOG_HOT_RETENTION_DAYS <= 7
    assert storage_archiver._effective_retention_days("siem_cold_vault", 90) == 7
    assert storage_archiver._effective_retention_days("security_alerts", 90) == 7
    assert storage_archiver._effective_retention_days("logs", 90) == 7


def test_archive_container_routing_is_opt_in_and_collection_specific(monkeypatch):
    monkeypatch.setenv("AZURE_STORAGE_CONTAINER", "legacy-vault")
    monkeypatch.setenv("AZURE_STORAGE_CONTAINER_SIEM", "siem-vault")
    monkeypatch.setenv("AZURE_STORAGE_CONTAINER_PECA", "peca-vault")
    monkeypatch.setenv("AZURE_STORAGE_CONTAINER_FBR", "fbr-vault")
    monkeypatch.setenv("AZURE_STORAGE_CONTAINER_SIEM_90", "siem-90-vault")
    monkeypatch.setenv("AZURE_STORAGE_CONTAINER_GENERAL_180", "general-180-vault")

    assert storage_archiver._archive_container_name("siem_cold_vault", 90) == "siem-90-vault"
    assert storage_archiver._archive_container_name("siem_cold_vault", 180) == "siem-vault"
    assert storage_archiver._archive_container_name("security_alerts") == "siem-vault"
    assert storage_archiver._archive_container_name("peca_forensic_logs") == "peca-vault"
    assert storage_archiver._archive_container_name("fbr_pos_logs") == "fbr-vault"
    assert storage_archiver._archive_container_name("analysis_results", 180) == "general-180-vault"
    assert storage_archiver._archive_container_name("analysis_results", 270) == "legacy-vault"

    monkeypatch.setenv("AZURE_CONTAINER_IMMUTABILITY_DAYS", "365")
    monkeypatch.setenv("AZURE_CONTAINER_IMMUTABILITY_DAYS_SIEM_90", "90")
    assert storage_archiver._container_policy_setting("siem_cold_vault", "DAYS", "0", 90) == "90"
    assert storage_archiver._container_policy_setting("siem_cold_vault", "DAYS", "0", 180) == "365"


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
            self.update_one = AsyncMock()

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
    collections["storage_archives"].update_one.assert_not_awaited()


def test_container_scope_requires_locked_policy_for_full_retention(monkeypatch):
    monkeypatch.setenv("AZURE_CONTAINER_IMMUTABILITY_LOCKED", "true")
    monkeypatch.setenv("AZURE_CONTAINER_IMMUTABILITY_DAYS", "2190")
    status = {
        "has_immutability_policy": True,
        "has_legal_hold": False,
        "declared_locked": True,
        "configured_days": 2190,
    }

    verified = storage_archiver._verify_container_immutability_for_retention(
        status,
        required_days=2190,
    )

    assert verified["verified"] is True
    assert verified["scope"] == "container"


def test_container_scope_rejects_retention_shorter_than_collection_requirement():
    status = {
        "has_immutability_policy": True,
        "has_legal_hold": False,
        "declared_locked": True,
        "configured_days": 365,
    }

    with pytest.raises(RuntimeError, match="2190-day"):
        storage_archiver._verify_container_immutability_for_retention(
            status,
            required_days=2190,
        )


@pytest.mark.asyncio
async def test_container_scope_archives_then_deletes_hot_records(monkeypatch):
    class FakeBlob:
        async def upload_blob(self, *_args, **_kwargs):
            return None

    class FakeContainer:
        def get_blob_client(self, _name):
            return FakeBlob()

    class FakeCollection:
        def __init__(self):
            self.update_one = AsyncMock()
            self.delete_many = AsyncMock(return_value=SimpleNamespace(deleted_count=1))

    collections = {
        "storage_archives": FakeCollection(),
        "fbr_pos_logs": FakeCollection(),
    }

    class FakeDb:
        def __getitem__(self, name):
            return collections[name]

    monkeypatch.setenv("AZURE_IMMUTABILITY_REQUIRED", "true")
    monkeypatch.setenv("AZURE_IMMUTABILITY_SCOPE", "container")
    monkeypatch.setenv("AZURE_STORAGE_CONTAINER_FBR", "fbr-vault")
    deleted = await storage_archiver._archive_batch(
        FakeContainer(),
        FakeDb(),
        "TENANT-A",
        "fbr_pos_logs",
        [{"_id": "doc-1", "timestamp": datetime(2026, 7, 1, tzinfo=timezone.utc)}],
        "run-1",
        1,
        90,
        {
            "has_immutability_policy": True,
            "has_legal_hold": False,
            "declared_locked": True,
            "configured_days": 2190,
        },
    )

    assert deleted == 1
    collections["storage_archives"].update_one.assert_awaited_once()
    archive_update = collections["storage_archives"].update_one.await_args.args[1]
    assert archive_update["$setOnInsert"]["container_name"] == "fbr-vault"
    collections["fbr_pos_logs"].delete_many.assert_awaited_once()


@pytest.mark.asyncio
async def test_archive_retry_reuses_the_same_verified_blobs(monkeypatch):
    class FakeDownloader:
        def __init__(self, payload):
            self.payload = payload

        async def readall(self):
            return self.payload

    class FakeBlob:
        def __init__(self, name, payloads):
            self.name = name
            self.payloads = payloads

        async def upload_blob(self, payload, **_kwargs):
            if self.name in self.payloads:
                raise storage_archiver.ResourceExistsError("already exists")
            self.payloads[self.name] = payload

        async def download_blob(self):
            return FakeDownloader(self.payloads[self.name])

    class FakeContainer:
        def __init__(self):
            self.payloads = {}

        def get_blob_client(self, name):
            return FakeBlob(name, self.payloads)

    class FakeCollection:
        def __init__(self):
            self.update_one = AsyncMock()
            self.delete_many = AsyncMock(return_value=SimpleNamespace(deleted_count=1))

    collections = {
        "storage_archives": FakeCollection(),
        "siem_cold_vault": FakeCollection(),
    }

    class FakeDb:
        def __getitem__(self, name):
            return collections[name]

    monkeypatch.setenv("AZURE_IMMUTABILITY_REQUIRED", "false")
    container = FakeContainer()
    docs = [{"_id": "doc-1", "timestamp": "2026-07-01T00:00:00+00:00"}]

    for run_id in ("run-1", "run-2"):
        await storage_archiver._archive_batch(
            container,
            FakeDb(),
            "TENANT-A",
            "siem_cold_vault",
            docs,
            run_id,
            1,
            90,
        )

    assert len(container.payloads) == 2
    assert sum(name.endswith(".json") for name in container.payloads) == 1
    assert sum(name.endswith(".sha256") for name in container.payloads) == 1


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


def test_async_azure_transport_is_packaged_for_archive_runtime():
    from pathlib import Path

    requirements = (
        Path(__file__).resolve().parents[1] / "requirements.txt"
    ).read_text(encoding="utf-8").lower()
    assert "azure-storage-blob" in requirements
    assert "aiohttp" in requirements


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
    assert 'name="ttl_user_activation_tokens"' in init_text
    assert 'name="ttl_security_incident_occurrences"' in init_text
    # Only short-lived activation tokens and the incident idempotency ledger
    # use TTL deletion. Evidence collections remain archive-before-delete.
    assert init_text.count("expireAfterSeconds=") == 2


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
            "container_name": "siem-vault",
            "collection": "siem_cold_vault",
            "sha256": hashlib.sha256(valid_blob).hexdigest(),
        },
        {
            "blob_name": "duplicate.json",
            "container_name": "siem-vault",
            "collection": "siem_cold_vault",
            "sha256": hashlib.sha256(valid_blob).hexdigest(),
        },
        {
            "blob_name": "tampered.json",
            "container_name": "siem-vault",
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

    requested_containers = []

    class FakeBlobService:
        @classmethod
        def from_connection_string(cls, _connection_string):
            return cls()

        def get_container_client(self, container_name):
            requested_containers.append(container_name)
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

    assert requested_containers == ["siem-vault", "siem-vault", "siem-vault"]

    assert total == 1
    assert docs[0]["event_uid"] == "Security:42"
    assert docs[0]["_archived"] is True
    assert "$and" in ledger.query


@pytest.mark.asyncio
async def test_unfiltered_archive_page_stops_after_enough_newest_records(monkeypatch):
    newest_document = {
        "_id": "newest",
        "tenant_id": "TENANT-A",
        "event_uid": "Security:newest",
        "timestamp": "2026-07-02T10:00:00+00:00",
    }
    older_document = {
        "_id": "older",
        "tenant_id": "TENANT-A",
        "event_uid": "Security:older",
        "timestamp": "2026-07-01T10:00:00+00:00",
    }
    payloads = {
        "newest.json": json.dumps([newest_document]).encode("utf-8"),
        "older.json": json.dumps([older_document]).encode("utf-8"),
    }
    entries = [
        {
            "blob_name": name,
            "collection": "peca_forensic_logs",
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        for name, payload in payloads.items()
    ]

    class FakeCursor:
        def sort(self, *_args):
            return self

        def limit(self, _value):
            return self

        async def to_list(self, length):
            return entries[:length]

    class FakeLedger:
        def find(self, _query):
            return FakeCursor()

    class FakeDownloader:
        def __init__(self, payload):
            self.payload = payload

        async def readall(self):
            return self.payload

    downloads = []

    class FakeBlob:
        def __init__(self, name):
            self.name = name

        async def download_blob(self):
            downloads.append(self.name)
            return FakeDownloader(payloads[self.name])

    class FakeContainer:
        def get_blob_client(self, name):
            return FakeBlob(name)

    class FakeBlobService:
        @classmethod
        def from_connection_string(cls, _connection_string):
            return cls()

        def get_container_client(self, _container_name):
            return FakeContainer()

        async def close(self):
            return None

    monkeypatch.setenv("AZURE_STORAGE_CONNECTION_STRING", "UseDevelopmentStorage=true")
    monkeypatch.setattr(archive_reader, "BlobServiceClient", FakeBlobService)

    docs, total = await archive_reader.fetch_archived_documents(
        {"storage_archives": FakeLedger()},
        tenant_id="TENANT-A",
        collections=["peca_forensic_logs"],
        limit=1,
    )

    assert total == 1
    assert docs[0]["event_uid"] == "Security:newest"
    assert downloads == ["newest.json"]

import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.workers import storage_archiver
from app.utils import archive_reader
from app.routes import compliance
from app.routes.compliance import (
    _EVIDENCE_LIST_PROJECTION,
    _curate_evidence_record,
    _summarize_evidence_message,
    _fetch_docs_page,
)


def test_compliance_evidence_summary_bounds_large_messages():
    summary, truncated = _summarize_evidence_message("x" * 750)

    assert len(summary) == 500
    assert summary.endswith("...")
    assert truncated is True

    short_summary, short_truncated = _summarize_evidence_message({"event": "4688"})
    assert short_summary == '{"event":"4688"}'
    assert short_truncated is False


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


def test_compliance_evidence_list_never_exposes_raw_or_signed_payloads():
    curated = _curate_evidence_record(
        {
            "_id": "record-1",
            "raw_event": "raw",
            "raw_event_data": {"secret": True},
            "raw_data": {"secret": True},
            "processed_data": {"secret": True},
            "signed_payload": "large-payload",
        },
        "peca_forensic",
        "peca_forensic_logs",
    )

    for field in (
        "raw_event",
        "raw_event_data",
        "raw_data",
        "processed_data",
        "signed_payload",
    ):
        assert field not in curated
    assert curated["detail_available"] is True
    assert curated["content_redacted_from_list"] is True


@pytest.mark.asyncio
async def test_compliance_hot_list_applies_metadata_only_projection():
    class FakeCursor:
        def sort(self, *_args, **_kwargs):
            return self

        def skip(self, *_args, **_kwargs):
            return self

        def limit(self, *_args, **_kwargs):
            return self

        async def to_list(self, length):
            return [{"event_uid": "event-1"}][:length]

    class FakeCollection:
        def __init__(self):
            self.find_args = None

        async def count_documents(self, _query):
            return 1

        def find(self, query, projection):
            self.find_args = (query, projection)
            return FakeCursor()

    collection = FakeCollection()
    docs, total = await _fetch_docs_page(
        collection,
        {"tenant_id": "TENANT-A"},
        None,
        None,
        skip=0,
        limit=50,
    )

    assert total == 1
    assert docs == [{"event_uid": "event-1"}]
    assert collection.find_args[1] == _EVIDENCE_LIST_PROJECTION


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
    monkeypatch.setattr(compliance, "count_archived_documents", count_mock)

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
        "archive_metadata_checked": True,
        "archive_available": True,
        "archive_retrieval_required": False,
        "archive_rows": 900,
        "total_is_exact": True,
    }
@pytest.mark.asyncio
async def test_compliance_boundary_page_requires_isolated_cold_retrieval(monkeypatch):
    monkeypatch.setattr(
        compliance,
        "count_archived_documents",
        AsyncMock(return_value=(4, True)),
    )
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

    assert archived == []
    assert total == 6
    assert meta["archive_read_performed"] is False
    assert meta["archive_available"] is True
    assert meta["archive_retrieval_required"] is True


@pytest.mark.asyncio
async def test_compliance_cold_page_requires_isolated_retrieval(monkeypatch):
    monkeypatch.setattr(
        compliance,
        "count_archived_documents",
        AsyncMock(return_value=(10, True)),
    )
    archived, total, meta = await compliance._resolve_archive_page(
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

    assert archived == []
    assert total == 13
    assert meta["archive_retrieval_required"] is True
@pytest.mark.asyncio
async def test_filtered_full_hot_page_is_fast_and_marks_total_inexact(monkeypatch):
    count_mock = AsyncMock()
    monkeypatch.setattr(compliance, "count_archived_documents", count_mock)

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


def test_compliance_hot_retention_is_separate_from_vault_retention():
    assert storage_archiver._effective_retention_days("fbr_pos_logs", 90) == 7
    assert storage_archiver._effective_retention_days("peca_forensic_logs", 90) == 7
    assert storage_archiver._effective_retention_days("siem_cold_vault", 90) == 7
    assert storage_archiver._effective_retention_days("security_alerts", 90) == 7
    assert storage_archiver._effective_retention_days("logs", 90) == 7
    assert "fbr_pos_logs" not in storage_archiver.COMPLIANCE_VAULT_RETENTION_DAYS
    assert "peca_forensic_logs" not in storage_archiver.COMPLIANCE_VAULT_RETENTION_DAYS
    assert storage_archiver._effective_vault_retention_days("fbr_pos_logs", 180) == 180
    assert storage_archiver._effective_vault_retention_days("peca_forensic_logs", 180) == 180
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
    monkeypatch.setenv("AZURE_STORAGE_CONTAINER_SIEM_90", "siem-90-vault")
    monkeypatch.setenv("AZURE_STORAGE_CONTAINER_GENERAL_90", "general-90-vault")
    monkeypatch.setenv("AZURE_STORAGE_CONTAINER_GENERAL_180", "general-180-vault")

    assert storage_archiver._archive_container_name("siem_cold_vault", 90) == "siem-90-vault"
    assert storage_archiver._archive_container_name("siem_cold_vault", 180) == "siem-vault"
    assert storage_archiver._archive_container_name("security_alerts") == "siem-vault"
    assert storage_archiver._archive_container_name("peca_forensic_logs", 90) == "general-90-vault"
    assert storage_archiver._archive_container_name("source_envelopes_peca", 90) == "general-90-vault"
    assert storage_archiver._archive_container_name("fbr_pos_logs", 90) == "general-90-vault"
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


def test_fbr_archive_uses_one_tenant_retention_cohort():
    documents = [
        {"_id": "a", "retention_state": "RESOLVED", "tax_period_id": "PK-ST-2026-07", "effective_retention_until": "2032-07-31"},
        {"_id": "b", "retention_state": "RESOLVED", "tax_period_id": "PK-ST-2026-08", "effective_retention_until": "2032-08-31"},
        {"_id": "c", "retention_state": "UNRESOLVED"},
        {"_id": "d", "retention_state": "RESOLVED", "tax_period_id": "PK-ST-2026-07", "effective_retention_until": "2032-07-31"},
    ]
    cohorts = storage_archiver._archive_cohorts("fbr_pos_logs", documents)
    assert cohorts == [documents]


def test_archive_batch_memory_boundary_stops_before_next_document():
    documents = [
        {"_id": "a", "message": "x" * 100},
        {"_id": "b", "message": "y" * 100},
    ]
    selected = storage_archiver._bounded_archive_documents(documents, 180)
    assert [document["_id"] for document in selected] == ["a"]


@pytest.mark.asyncio
async def test_blob_scope_can_lock_then_verify_when_explicitly_enabled(monkeypatch):
    required_until = datetime(2032, 7, 10, tzinfo=timezone.utc)

    class FakeBlob:
        def __init__(self):
            self.locked = False
            self.policy = None

        async def get_blob_properties(self):
            return SimpleNamespace(
                has_legal_hold=False,
                immutability_policy=SimpleNamespace(
                    policy_mode="Locked" if self.locked else "Unlocked",
                    expiry_time=required_until if self.locked else None,
                ),
            )

        async def set_immutability_policy(self, policy):
            self.policy = policy
            self.locked = True

    monkeypatch.setenv("AZURE_BLOB_IMMUTABILITY_AUTO_LOCK", "true")
    blob = FakeBlob()
    status = await storage_archiver._ensure_blob_immutability(blob, required_until)
    assert blob.policy is not None
    assert status["verified"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("collection_name", ["fbr_pos_logs", "peca_forensic_logs"])
async def test_archive_never_deletes_hot_records_without_verified_immutability(monkeypatch, collection_name):
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
        collection_name: FakeCollection(),
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
            collection_name,
            [{"_id": "doc-1", "timestamp": datetime.now(timezone.utc)}],
            "run-1",
            1,
            90,
        )
    collections[collection_name].delete_many.assert_not_awaited()
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
    monkeypatch.setattr(
        storage_archiver,
        "acquire_retention_fence",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        storage_archiver,
        "release_retention_fence",
        AsyncMock(return_value=None),
    )

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
            self.find_one = AsyncMock(return_value=None)

    collections = {
        "storage_archives": FakeCollection(),
        "fbr_pos_logs": FakeCollection(),
        "legal_holds": FakeCollection(),
    }

    class FakeDb:
        def __getitem__(self, name):
            return collections[name]

    monkeypatch.setenv("AZURE_IMMUTABILITY_REQUIRED", "true")
    monkeypatch.setenv("AZURE_IMMUTABILITY_SCOPE", "container")
    monkeypatch.setenv("AZURE_STORAGE_CONTAINER_GENERAL_90", "general-90-vault")
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
            "configured_days": 90,
        },
    )

    assert deleted == 1
    assert collections["storage_archives"].update_one.await_count == 2
    archive_update = collections["storage_archives"].update_one.await_args_list[0].args[1]
    assert archive_update["$setOnInsert"]["container_name"] == "general-90-vault"
    collections["fbr_pos_logs"].delete_many.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("collection_name", ["fbr_pos_logs", "peca_forensic_logs"])
async def test_archive_rechecks_hold_and_preserves_hot_records(monkeypatch, collection_name):
    monkeypatch.setattr(
        storage_archiver,
        "acquire_retention_fence",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        storage_archiver,
        "release_retention_fence",
        AsyncMock(return_value=None),
    )

    class FakeBlob:
        async def upload_blob(self, *_args, **_kwargs):
            return None

    class FakeContainer:
        def get_blob_client(self, _name):
            return FakeBlob()

    class FakeCollection:
        def __init__(self, hold=None):
            self.update_one = AsyncMock()
            self.delete_many = AsyncMock(return_value=SimpleNamespace(deleted_count=1))
            self.find_one = AsyncMock(return_value=hold)

    collections = {
        "storage_archives": FakeCollection(),
        collection_name: FakeCollection(),
        "legal_holds": FakeCollection({"hold_id": "HOLD-1", "status": "ACTIVE"}),
    }

    class FakeDb:
        def __getitem__(self, name):
            return collections[name]

    monkeypatch.setenv("AZURE_IMMUTABILITY_REQUIRED", "true")
    monkeypatch.setenv("AZURE_IMMUTABILITY_SCOPE", "container")
    deleted = await storage_archiver._archive_batch(
        FakeContainer(),
        FakeDb(),
        "TENANT-A",
        collection_name,
        [{"_id": "doc-1", "event_uid": "event-1", "timestamp": datetime(2026, 7, 1, tzinfo=timezone.utc)}],
        "run-hold",
        1,
        90,
        {
            "has_immutability_policy": True,
            "has_legal_hold": False,
            "declared_locked": True,
            "configured_days": 90,
        },
    )
    assert deleted == 0
    collections[collection_name].delete_many.assert_not_awaited()
    assert collections["storage_archives"].update_one.await_count == 2


@pytest.mark.asyncio
async def test_archive_retry_reuses_the_same_verified_blobs(monkeypatch):
    monkeypatch.setattr(
        storage_archiver,
        "acquire_retention_fence",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        storage_archiver,
        "release_retention_fence",
        AsyncMock(return_value=None),
    )

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
            self.find_one = AsyncMock(return_value=None)

    collections = {
        "storage_archives": FakeCollection(),
        "siem_cold_vault": FakeCollection(),
        "legal_holds": FakeCollection(),
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
    import re
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
    ttl_index_names = set(re.findall(r'name="(ttl_[^"]+)"', init_text))
    assert ttl_index_names == {
        "ttl_user_activation_tokens",
        "ttl_security_incident_occurrences",
        "ttl_detection_engine_health_events",
        "ttl_detection_dispatch_outbox",
        "ttl_detection_dispatch_dlq",
        "ttl_detection_engine_observations",
            "ttl_detection_candidate_quarantine",
            "ttl_source_outbox_published",
            "ttl_evidence_retention_fence",
        }
    # TTL is limited to short-lived workflow/transport ledgers. Canonical
    # evidence remains archive-before-delete and never receives an independent
    # MongoDB expiry path.
    for collection_name in (
        "logs",
        "siem_cold_vault",
        "security_alerts",
        "fbr_pos_logs",
        "peca_forensic_logs",
        "csv_uploads",
        "analysis_results",
    ):
        assert f'ttl_{collection_name}' not in ttl_index_names


@pytest.mark.asyncio
async def test_archive_reader_returns_metadata_only_and_never_reads_azure_bytes():
    class FakeAggregateCursor:
        async def to_list(self, length):
            return [{"_id": None, "total": 25}][:length]

    class FakeLedger:
        def aggregate(self, pipeline):
            self.pipeline = pipeline
            return FakeAggregateCursor()

    ledger = FakeLedger()
    docs, total = await archive_reader.fetch_archived_documents(
        {"storage_archives": ledger},
        tenant_id="TENANT-A",
        collections=["siem_cold_vault"],
        start_dt=datetime(2026, 7, 1, tzinfo=timezone.utc),
        event_id="4625",
        search_term="203.0.113.10",
        limit=10,
    )

    assert docs == []
    assert total == 25
    query = ledger.pipeline[0]["$match"]
    assert query["tenant_id"] == "TENANT-A"
    assert query["collection"] == {"$in": ["siem_cold_vault"]}
    assert "$and" in query


def test_archive_reader_has_no_azure_blob_download_dependency():
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[1] / "app" / "utils" / "archive_reader.py"
    ).read_text(encoding="utf-8")

    assert "BlobServiceClient" not in source
    assert "download_blob" not in source
    assert "readall" not in source

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pymongo.errors import DuplicateKeyError

from app.routes import archive_retrieval
from app.routes import data as data_routes
from app.utils.archive_retrieval import (
    authorized_archive_collections,
    serialize_retrieval,
    validate_archive_collection_access,
)
from app.workers import archive_retrieval_worker
from tests.helpers import provision_and_login_admin


def test_hot_search_is_exact_tenant_scoped_and_never_uses_regex():
    query = data_routes._exact_search_query("TENANT-A", "4625")

    assert query["tenant_id"] == "TENANT-A"
    assert {"event_id": {"$in": ["4625", 4625]}} in query["$or"]
    assert "$regex" not in repr(query)


def test_archive_collection_access_preserves_operational_and_compliance_rbac():
    packs = ["fbr_pos", "eto_forensic"]

    assert authorized_archive_collections("admin", packs) == {
        "logs",
        "siem_cold_vault",
        "security_alerts",
        "csv_uploads",
        "fbr_pos_logs",
        "peca_forensic_logs",
    }
    assert authorized_archive_collections("manager", packs) == {
        "logs",
        "siem_cold_vault",
        "security_alerts",
        "csv_uploads",
    }
    assert authorized_archive_collections("auditor", packs) == {
        "fbr_pos_logs",
        "peca_forensic_logs",
    }

    with pytest.raises(PermissionError):
        validate_archive_collection_access(
            ["fbr_pos_logs"],
            role="manager",
            compliance_packs=packs,
        )
    with pytest.raises(PermissionError):
        validate_archive_collection_access(
            ["siem_cold_vault"],
            role="auditor",
            compliance_packs=packs,
        )
    with pytest.raises(PermissionError):
        validate_archive_collection_access(
            ["fbr_pos_logs"],
            role="admin",
            compliance_packs=["peca_forensic"],
        )


@pytest.mark.parametrize("value", ["0", "8", "-1", "forever"])
def test_hot_search_rejects_unbounded_windows(value):
    with pytest.raises(Exception) as exc:
        data_routes._hot_search_days(value)

    assert getattr(exc.value, "status_code", None) == 400


def test_all_time_is_bounded_to_seven_hot_days():
    assert data_routes._hot_search_days("all") == 7


def test_csv_hot_search_uses_normalized_date_anchor():
    time_filter = data_routes._time_filter("7", "csv_uploads")

    assert set(time_filter) == {"_retention_ts"}
    assert isinstance(time_filter["_retention_ts"]["$gte"], datetime)


def test_hot_search_never_adds_an_unindexed_id_tiebreaker():
    assert data_routes._indexed_time_sort("timestamp") == [("timestamp", -1)]
    assert data_routes._indexed_time_sort("_retention_ts") == [("_retention_ts", -1)]


@pytest.mark.asyncio
async def test_monthly_included_allowance_reservation_is_atomic():
    collection = SimpleNamespace(
        insert_one=AsyncMock(
            side_effect=[
                SimpleNamespace(inserted_id="first"),
                DuplicateKeyError("duplicate"),
            ]
        )
    )
    db = {"archive_retrieval_allowances": collection}

    first = await archive_retrieval._reserve_included_allowance(
        db,
        "TENANT-A",
        "2026-07",
    )
    second = await archive_retrieval._reserve_included_allowance(
        db,
        "TENANT-A",
        "2026-07",
    )

    assert first is True
    assert second is False


@pytest.mark.asyncio
async def test_authenticated_tenant_can_create_bounded_retrieval_request(
    async_client,
    db,
    monkeypatch,
):
    session = await provision_and_login_admin(async_client, "archive_request")
    now = datetime.now(timezone.utc)
    await db["storage_archives"].insert_one(
        {
            "tenant_id": session["tenant_id"],
            "collection": "siem_cold_vault",
            "status": "archived",
            "archive_key": "archive-request-1",
            "container_name": "siem-90",
            "blob_name": "tenant/archive.json",
            "oldest_at": now - timedelta(days=30),
            "newest_at": now - timedelta(days=29),
            "blob_size_bytes": 1024,
            "document_count": 10,
            "created_at": now,
        }
    )
    monkeypatch.setenv("ARCHIVE_RETRIEVAL_ENABLED", "true")

    response = await async_client.post(
        "/api/v1/archive-retrievals",
        json={
            "collections": ["siem_cold_vault"],
            "start_at": (now - timedelta(days=31)).isoformat(),
            "end_at": (now - timedelta(days=28)).isoformat(),
            "reason": "Approved investigation window",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "APPROVED"
    assert body["tenant_id"] == session["tenant_id"]
    assert body["estimated_bytes"] == 1024
    assert body["estimated_blob_count"] == 1


def test_retrieval_serialization_hides_worker_and_staging_details():
    public = serialize_retrieval(
        {
            "request_id": "ARR-1",
            "worker_lease": "internal-worker",
            "last_error_internal": "SensitiveInternalError",
            "items": [
                {
                    "archive_key": "archive-1",
                    "collection": "siem_cold_vault",
                    "status": "success",
                    "bytes": 100,
                    "source_container": "private-source",
                    "source_blob_name": "secret/path.json",
                    "staging_container": "private-staging",
                    "staging_blob_name": "tenant/request/path.json",
                    "sha256": "a" * 64,
                }
            ],
        }
    )

    assert "worker_lease" not in public
    assert "last_error_internal" not in public
    assert "source_container" not in public["items"][0]
    assert "staging_blob_name" not in public["items"][0]


@pytest.mark.asyncio
async def test_worker_uses_server_side_copy_with_source_authorization(monkeypatch):
    destination = SimpleNamespace(
        get_blob_properties=AsyncMock(
            side_effect=archive_retrieval_worker.ResourceNotFoundError("missing")
        ),
        start_copy_from_url=AsyncMock(
            return_value={"copy_status": "pending", "copy_id": "copy-1"}
        ),
    )
    source = SimpleNamespace(url="https://account.blob.core.windows.net/source/blob.json")
    staging = SimpleNamespace(
        get_container_properties=AsyncMock(return_value={}),
        get_blob_client=lambda _name: destination,
    )

    class FakeBlobService:
        def get_container_client(self, _name):
            return staging

        def get_blob_client(self, _container, _name):
            return source

    class FakeCursor:
        def sort(self, *_args):
            return self

        def limit(self, _value):
            return self

        async def to_list(self, length):
            return [
                {
                    "archive_key": "archive-1",
                    "collection": "siem_cold_vault",
                    "container_name": "source",
                    "blob_name": "blob.json",
                    "sha256": "b" * 64,
                    "blob_size_bytes": 100,
                }
            ][:length]

    ledger = SimpleNamespace(find=lambda _query: FakeCursor())
    requests = SimpleNamespace(update_one=AsyncMock(return_value=SimpleNamespace()))
    db = {
        "storage_archives": ledger,
        "archive_retrieval_requests": requests,
    }
    monkeypatch.setenv("AZURE_RETRIEVAL_STAGING_CONTAINER", "staging")

    await archive_retrieval_worker._start_request_copies(
        FakeBlobService(),
        db,
        {
            "request_id": "ARR-1",
            "tenant_id": "TENANT-A",
            "collections": ["siem_cold_vault"],
            "start_at": datetime.now(timezone.utc) - timedelta(days=30),
            "end_at": datetime.now(timezone.utc),
        },
        source_authorization="Bearer test-token",
    )

    kwargs = destination.start_copy_from_url.await_args.kwargs
    assert kwargs["source_authorization"] == "Bearer test-token"
    assert kwargs["standard_blob_tier"] == archive_retrieval_worker.StandardBlobTier.COOL
    assert destination.start_copy_from_url.await_args.args[0] == source.url

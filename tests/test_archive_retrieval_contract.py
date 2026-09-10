import base64
import hashlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse
from unittest.mock import AsyncMock

import pytest
from pymongo.errors import DuplicateKeyError

from app.routes import archive_retrieval
from app.routes import data as data_routes
from app.utils.archive_reader import ARCHIVE_READABLE_STATUSES, archive_ledger_query
from app.utils.archive_retrieval import (
    authorized_archive_collections,
    serialize_retrieval,
    validate_archive_collection_access,
)
from app.workers import archive_retrieval_worker
from tests.helpers import provision_and_login_admin


def _retrieval_doc(
    *,
    request_id: str,
    tenant_id: str,
    status: str = "APPROVED",
    collections: list[str] | None = None,
    expires_at: datetime | None = None,
) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "request_id": request_id,
        "tenant_id": tenant_id,
        "requested_by": "archive-test@example.com",
        "collections": collections or ["siem_cold_vault"],
        "start_at": now - timedelta(days=30),
        "end_at": now - timedelta(days=29),
        "reason": "Maintained archive API boundary test",
        "status": status,
        "estimated_bytes": 1024,
        "estimated_blob_count": 1,
        "expires_at": expires_at,
        "created_at": now,
        "updated_at": now,
        "items": [],
    }


@pytest.mark.asyncio
async def test_service_sas_download_link_is_https_read_only_and_short_lived(monkeypatch):
    account_key = base64.b64encode(b"warsoc-test-key-material-32byte").decode("ascii")
    monkeypatch.setenv("AZURE_RETRIEVAL_SAS_MODE", "service_sas")
    monkeypatch.setenv(
        "AZURE_STORAGE_ACCOUNT_URL",
        "https://warsocevidence90prod.blob.core.windows.net",
    )
    monkeypatch.setenv(
        "AZURE_STORAGE_CONNECTION_STRING",
        "DefaultEndpointsProtocol=https;"
        "AccountName=warsocevidence90prod;"
        f"AccountKey={account_key};"
        "EndpointSuffix=core.windows.net",
    )

    links, expires_at = await archive_retrieval._archive_download_links(
        [
            {
                "archive_key": "archive-1",
                "collection": "siem_cold_vault",
                "staging_container": "warsoc-retrieval-staging",
                "staging_blob_name": "tenant/request/archive.json",
                "sha256": "a" * 64,
                "bytes": 123,
            }
        ],
        30,
    )

    assert len(links) == 1
    parsed = urlparse(links[0]["url"])
    query = parse_qs(parsed.query)
    assert parsed.scheme == "https"
    assert query["sp"] == ["r"]
    assert query["spr"] == ["https"]
    assert timedelta(minutes=29) < expires_at - datetime.now(timezone.utc) <= timedelta(
        minutes=30
    )


@pytest.mark.asyncio
async def test_service_sas_rejects_mismatched_storage_identity(monkeypatch):
    monkeypatch.setenv("AZURE_RETRIEVAL_SAS_MODE", "service_sas")
    monkeypatch.setenv(
        "AZURE_STORAGE_ACCOUNT_URL",
        "https://warsocevidence90prod.blob.core.windows.net",
    )
    monkeypatch.setenv(
        "AZURE_STORAGE_CONNECTION_STRING",
        "DefaultEndpointsProtocol=https;AccountName=wrongaccount;AccountKey=dGVzdA==;",
    )

    with pytest.raises(RuntimeError, match="does not match"):
        await archive_retrieval._archive_download_links([], 30)


def test_hot_search_is_exact_tenant_scoped_and_never_uses_regex():
    query = data_routes._exact_search_query("TENANT-A", "4625")

    assert query["tenant_id"] == "TENANT-A"
    assert {"event_id": {"$in": ["4625", 4625]}} in query["$or"]
    assert "$regex" not in repr(query)


def test_retrieval_query_accepts_completed_archives_and_enforces_access_expiry():
    now = datetime(2026, 9, 6, tzinfo=timezone.utc)
    query = archive_ledger_query(
        tenant_id="TENANT-A",
        collections=["siem_cold_vault"],
        customer_access_at=now,
    )

    assert query["status"] == {"$in": list(ARCHIVE_READABLE_STATUSES)}
    assert {"oldest_customer_access_until": {"$gte": now}} in query["$and"]


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
async def test_authenticated_retrieval_request_fails_closed_when_disabled(
    async_client,
    monkeypatch,
):
    await provision_and_login_admin(async_client, "archive_disabled")
    monkeypatch.delenv("ARCHIVE_RETRIEVAL_ENABLED", raising=False)
    now = datetime.now(timezone.utc)

    response = await async_client.post(
        "/api/v1/archive-retrievals",
        json={
            "collections": ["siem_cold_vault"],
            "start_at": (now - timedelta(days=31)).isoformat(),
            "end_at": (now - timedelta(days=28)).isoformat(),
            "reason": "Disabled capability regression proof",
        },
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "The service is temporarily unavailable."


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
            "oldest_customer_access_until": now + timedelta(days=59),
            "customer_access_until": now + timedelta(days=60),
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


@pytest.mark.asyncio
async def test_archive_list_requires_authentication(async_client):
    response = await async_client.get("/api/v1/archive-retrievals")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_archive_list_enforces_current_database_role_and_source_scope(
    async_client,
    db,
):
    session = await provision_and_login_admin(async_client, "archive_roles")
    tenant_id = session["tenant_id"]
    await db["archive_retrieval_requests"].insert_many(
        [
            _retrieval_doc(request_id="ARR-OPERATIONAL", tenant_id=tenant_id),
            _retrieval_doc(
                request_id="ARR-COMPLIANCE",
                tenant_id=tenant_id,
                collections=["fbr_pos_logs"],
            ),
        ]
    )

    admin_response = await async_client.get("/api/v1/archive-retrievals")
    assert admin_response.status_code == 200
    assert {item["request_id"] for item in admin_response.json()["items"]} == {
        "ARR-OPERATIONAL",
        "ARR-COMPLIANCE",
    }

    await db["users"].update_one(
        {"tenant_id": tenant_id},
        {"$set": {"role": "manager"}},
    )
    manager_response = await async_client.get("/api/v1/archive-retrievals")
    assert manager_response.status_code == 200
    assert [item["request_id"] for item in manager_response.json()["items"]] == [
        "ARR-OPERATIONAL"
    ]

    await db["users"].update_one(
        {"tenant_id": tenant_id},
        {"$set": {"role": "auditor"}},
    )
    auditor_response = await async_client.get("/api/v1/archive-retrievals")
    assert auditor_response.status_code == 200
    assert [item["request_id"] for item in auditor_response.json()["items"]] == [
        "ARR-COMPLIANCE"
    ]

    await db["users"].update_one(
        {"tenant_id": tenant_id},
        {"$set": {"role": "analyst"}},
    )
    analyst_response = await async_client.get("/api/v1/archive-retrievals")
    assert analyst_response.status_code == 403


@pytest.mark.asyncio
async def test_archive_create_rejects_forged_sources_for_each_role(
    async_client,
    db,
    monkeypatch,
):
    session = await provision_and_login_admin(async_client, "archive_source_roles")
    tenant_id = session["tenant_id"]
    now = datetime.now(timezone.utc)
    base_body = {
        "start_at": (now - timedelta(days=31)).isoformat(),
        "end_at": (now - timedelta(days=28)).isoformat(),
        "reason": "Forged source authorization boundary test",
    }
    monkeypatch.setenv("ARCHIVE_RETRIEVAL_ENABLED", "true")

    await db["users"].update_one(
        {"tenant_id": tenant_id},
        {"$set": {"role": "manager"}},
    )
    manager_response = await async_client.post(
        "/api/v1/archive-retrievals",
        json={**base_body, "collections": ["fbr_pos_logs"]},
    )

    await db["users"].update_one(
        {"tenant_id": tenant_id},
        {"$set": {"role": "auditor"}},
    )
    auditor_response = await async_client.post(
        "/api/v1/archive-retrievals",
        json={**base_body, "collections": ["siem_cold_vault"]},
    )

    await db["users"].update_one(
        {"tenant_id": tenant_id},
        {"$set": {"role": "analyst"}},
    )
    analyst_response = await async_client.post(
        "/api/v1/archive-retrievals",
        json={**base_body, "collections": ["siem_cold_vault"]},
    )

    assert manager_response.status_code == 403
    assert auditor_response.status_code == 403
    assert analyst_response.status_code == 403


@pytest.mark.asyncio
async def test_archive_request_and_download_ids_are_tenant_scoped(
    async_client,
    db,
    monkeypatch,
):
    session = await provision_and_login_admin(async_client, "archive_tenant_a")
    await db["archive_retrieval_requests"].insert_one(
        _retrieval_doc(
            request_id="ARR-OTHER-TENANT",
            tenant_id="WARSOC_OTHER_TENANT",
            status="READY",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
    )
    monkeypatch.setenv("ARCHIVE_RETRIEVAL_ENABLED", "true")

    get_response = await async_client.get(
        "/api/v1/archive-retrievals/ARR-OTHER-TENANT"
    )
    download_response = await async_client.post(
        "/api/v1/archive-retrievals/ARR-OTHER-TENANT/download-links",
        headers={"x-csrf-token": session["csrf_token"]},
    )

    assert get_response.status_code == 404
    assert download_response.status_code == 404


@pytest.mark.asyncio
async def test_archive_download_requires_ready_and_unexpired_request(
    async_client,
    db,
    monkeypatch,
):
    session = await provision_and_login_admin(async_client, "archive_download_state")
    tenant_id = session["tenant_id"]
    await db["archive_retrieval_requests"].insert_many(
        [
            _retrieval_doc(
                request_id="ARR-NOT-READY",
                tenant_id=tenant_id,
                status="APPROVED",
            ),
            _retrieval_doc(
                request_id="ARR-EXPIRED",
                tenant_id=tenant_id,
                status="READY",
                expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            ),
        ]
    )
    monkeypatch.setenv("ARCHIVE_RETRIEVAL_ENABLED", "true")
    headers = {"x-csrf-token": session["csrf_token"]}

    not_ready = await async_client.post(
        "/api/v1/archive-retrievals/ARR-NOT-READY/download-links",
        headers=headers,
    )
    expired = await async_client.post(
        "/api/v1/archive-retrievals/ARR-EXPIRED/download-links",
        headers=headers,
    )

    assert not_ready.status_code == 409
    assert expired.status_code == 410


@pytest.mark.asyncio
async def test_expired_archive_is_not_customer_retrievable(
    async_client,
    db,
    monkeypatch,
):
    session = await provision_and_login_admin(async_client, "archive_expired")
    now = datetime.now(timezone.utc)
    await db["storage_archives"].insert_one(
        {
            "tenant_id": session["tenant_id"],
            "collection": "siem_cold_vault",
            "status": "archived_hot_deleted",
            "archive_key": "archive-expired-1",
            "container_name": "legacy-vault",
            "blob_name": "tenant/archive.json",
            "oldest_at": now - timedelta(days=100),
            "newest_at": now - timedelta(days=99),
            "oldest_customer_access_until": now - timedelta(days=10),
            "customer_access_until": now - timedelta(days=9),
            "blob_size_bytes": 1024,
            "document_count": 10,
            "created_at": now - timedelta(days=93),
        }
    )
    monkeypatch.setenv("ARCHIVE_RETRIEVAL_ENABLED", "true")

    response = await async_client.post(
        "/api/v1/archive-retrievals",
        json={
            "collections": ["siem_cold_vault"],
            "start_at": (now - timedelta(days=101)).isoformat(),
            "end_at": (now - timedelta(days=98)).isoformat(),
            "reason": "Expired entitlement negative-case proof",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "No archived records match this request."


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


@pytest.mark.asyncio
async def test_worker_service_sas_copy_source_is_read_only(monkeypatch):
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

    db = {
        "storage_archives": SimpleNamespace(find=lambda _query: FakeCursor()),
        "archive_retrieval_requests": SimpleNamespace(update_one=AsyncMock()),
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
        source_authorization=None,
        source_account_name="account",
        source_account_key=base64.b64encode(b"warsoc-test-key-material-32byte").decode(
            "ascii"
        ),
    )

    source_url = destination.start_copy_from_url.await_args.args[0]
    query = parse_qs(urlparse(source_url).query)
    assert query["sp"] == ["r"]
    assert query["spr"] == ["https"]
    assert "source_authorization" not in destination.start_copy_from_url.await_args.kwargs


class _ChunkedDownload:
    def __init__(self, chunks):
        self._chunks = chunks

    async def chunks(self):
        for chunk in self._chunks:
            yield chunk


class _RetrievalBlobService:
    def __init__(self, destination):
        self.destination = destination

    def get_blob_client(self, _container, _name):
        return self.destination


@pytest.mark.asyncio
async def test_worker_verifies_staged_sha256_before_ready():
    payload = b"bounded archive payload"
    expected_sha256 = hashlib.sha256(payload).hexdigest()
    destination = SimpleNamespace(
        get_blob_properties=AsyncMock(
            return_value=SimpleNamespace(
                copy=SimpleNamespace(status="success"),
                size=len(payload),
            )
        ),
        download_blob=AsyncMock(return_value=_ChunkedDownload([payload[:7], payload[7:]])),
    )
    requests = SimpleNamespace(
        update_one=AsyncMock(),
        find_one_and_update=AsyncMock(return_value={"request_id": "ARR-READY"}),
    )
    usage = SimpleNamespace(update_one=AsyncMock())
    db = {
        "archive_retrieval_requests": requests,
        "archive_retrieval_usage": usage,
    }

    await archive_retrieval_worker._refresh_pending_request(
        _RetrievalBlobService(destination),
        db,
        {
            "request_id": "ARR-READY",
            "tenant_id": "TENANT-A",
            "status": "PENDING_REHYDRATION",
            "items": [
                {
                    "archive_key": "archive-1",
                    "collection": "siem_cold_vault",
                    "staging_container": "staging",
                    "staging_blob_name": "tenant/request/archive.json",
                    "sha256": expected_sha256,
                }
            ],
        },
        source_authorization="Bearer test-token",
    )

    ready_update = requests.find_one_and_update.await_args.args[1]["$set"]
    assert ready_update["status"] == "READY"
    assert ready_update["items"][0]["integrity_status"] == "verified"
    assert ready_update["items"][0]["verified_sha256"] == expected_sha256
    assert destination.download_blob.await_args.kwargs == {"max_concurrency": 1}
    usage.update_one.assert_awaited_once()


@pytest.mark.asyncio
async def test_worker_fails_closed_when_staged_sha256_mismatches():
    destination = SimpleNamespace(
        get_blob_properties=AsyncMock(
            return_value=SimpleNamespace(
                copy=SimpleNamespace(status="success"),
                size=8,
            )
        ),
        download_blob=AsyncMock(return_value=_ChunkedDownload([b"tampered"])),
    )
    requests = SimpleNamespace(
        update_one=AsyncMock(),
        find_one_and_update=AsyncMock(),
    )
    db = {
        "archive_retrieval_requests": requests,
        "archive_retrieval_usage": SimpleNamespace(update_one=AsyncMock()),
    }

    await archive_retrieval_worker._refresh_pending_request(
        _RetrievalBlobService(destination),
        db,
        {
            "request_id": "ARR-TAMPERED",
            "tenant_id": "TENANT-A",
            "status": "PENDING_REHYDRATION",
            "items": [
                {
                    "archive_key": "archive-1",
                    "collection": "siem_cold_vault",
                    "staging_container": "staging",
                    "staging_blob_name": "tenant/request/archive.json",
                    "sha256": "a" * 64,
                }
            ],
        },
        source_authorization="Bearer test-token",
    )

    failed_update = requests.update_one.await_args.args[1]["$set"]
    assert failed_update["status"] == "FAILED"
    assert failed_update["items"][0]["status"] == "integrity_failed"
    assert failed_update["last_error_internal"] == "STAGED_SHA256_MISMATCH"
    requests.find_one_and_update.assert_not_awaited()

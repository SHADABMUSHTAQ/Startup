from __future__ import annotations

import io
import zipfile
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.utils.evidence_package import verify_evidence_package
from app.workers.evidence_export_worker import expire_ready_exports, process_evidence_export


class _BlobProperties:
    def __init__(self, metadata):
        self.metadata = metadata


class _Blob:
    def __init__(self, store, metadata, name):
        self.store = store
        self.metadata_store = metadata
        self.name = name

    async def upload_blob(self, stream, **kwargs):
        self.store[self.name] = stream.read() if hasattr(stream, "read") else bytes(stream)
        self.metadata_store[self.name] = dict(kwargs.get("metadata") or {})

    async def get_blob_properties(self):
        return _BlobProperties(self.metadata_store.get(self.name, {}))

    async def delete_blob(self, **_kwargs):
        self.store.pop(self.name, None)
        self.metadata_store.pop(self.name, None)


class _Container:
    def __init__(self):
        self.store = {}
        self.metadata = {}

    async def get_container_properties(self):
        return object()

    def get_blob_client(self, name):
        return _Blob(self.store, self.metadata, name)


class _BlobService:
    def __init__(self):
        self.container = _Container()

    def get_container_client(self, _name):
        return self.container

    def get_blob_client(self, _container, name):
        return self.container.get_blob_client(name)


def _keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


async def _case_with_item(async_client, auth_headers, db):
    created = await async_client.post(
        "/api/v1/compliance/cases",
        headers=auth_headers,
        json={
            "title": "Export contract case",
            "description": "Build and independently verify a bounded evidence package.",
        },
    )
    case = created.json()["case"]
    source = {
        "tenant_id": case["tenant_id"],
        "event_uid": "EVENT-EXPORT-A",
        "event_id": "4625",
        "timestamp": datetime.now(timezone.utc),
        "raw_event_data": "fernet-v1:ciphertext",
    }
    inserted = await db.siem_cold_vault.insert_one(source)
    attached = await async_client.post(
        f"/api/v1/compliance/cases/{case['case_id']}/items",
        headers=auth_headers,
        json={
            "collection": "siem_cold_vault",
            "document_id": str(inserted.inserted_id),
            "reason": "Attach the original stored event for evidence package verification.",
        },
    )
    assert attached.status_code == 201, attached.text
    return case, inserted.inserted_id


@pytest.mark.asyncio
async def test_evidence_export_route_is_disabled_by_default(
    async_client,
    auth_headers,
    db,
    monkeypatch,
):
    monkeypatch.setenv("EVIDENCE_EXPORT_ENABLED", "false")
    case, _ = await _case_with_item(async_client, auth_headers, db)
    response = await async_client.post(
        f"/api/v1/compliance/cases/{case['case_id']}/exports",
        headers=auth_headers,
        json={"reason": "Request a signed evidence package for an authorized review."},
    )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_isolated_worker_builds_package_that_verifies_offline(
    async_client,
    auth_headers,
    db,
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("EVIDENCE_EXPORT_ENABLED", "true")
    monkeypatch.setenv("EVIDENCE_EXPORT_CONTAINER", "warsoc-evidence-exports")
    monkeypatch.setenv("EVIDENCE_EXPORT_MAX_BYTES", str(5 * 1024 * 1024))
    case, _ = await _case_with_item(async_client, auth_headers, db)
    requested = await async_client.post(
        f"/api/v1/compliance/cases/{case['case_id']}/exports",
        headers=auth_headers,
        json={"reason": "Create a signed package for independent custody verification."},
    )
    assert requested.status_code == 202, requested.text
    export_id = requested.json()["export"]["export_id"]
    request_doc = await db.evidence_exports.find_one_and_update(
        {"export_id": export_id, "status": "REQUESTED"},
        {"$set": {"status": "PROCESSING"}},
        return_document=True,
    )
    private_pem, public_pem = _keypair()
    service = _BlobService()
    result = await process_evidence_export(
        db,
        service,
        request_doc,
        private_key_pem=private_pem,
        private_key_password=None,
        signing_key_id="evidence-package-key",
        signing_key_version=1,
        signing_key_fingerprint="fingerprint",
    )
    assert result["status"] == "READY"
    assert result["package_bytes"] <= 5 * 1024 * 1024
    assert len(service.container.store) == 1

    zip_bytes = next(iter(service.container.store.values()))
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        archive.extractall(extract_dir)
    verification = verify_evidence_package(extract_dir, public_pem)
    assert verification["status"] == "VERIFIED"
    assert verification["case_id"] == case["case_id"]


@pytest.mark.asyncio
async def test_worker_requires_archive_retrieval_when_hot_source_is_gone(
    async_client,
    auth_headers,
    db,
    monkeypatch,
):
    monkeypatch.setenv("EVIDENCE_EXPORT_ENABLED", "true")
    monkeypatch.setenv("EVIDENCE_EXPORT_CONTAINER", "warsoc-evidence-exports")
    case, source_id = await _case_with_item(async_client, auth_headers, db)
    await db.siem_cold_vault.delete_one({"_id": source_id})
    requested = await async_client.post(
        f"/api/v1/compliance/cases/{case['case_id']}/exports",
        headers=auth_headers,
        json={"reason": "Request a package after its source moved to cold storage."},
    )
    export_id = requested.json()["export"]["export_id"]
    request_doc = await db.evidence_exports.find_one_and_update(
        {"export_id": export_id, "status": "REQUESTED"},
        {"$set": {"status": "PROCESSING"}},
        return_document=True,
    )
    private_pem, _ = _keypair()
    result = await process_evidence_export(
        db,
        _BlobService(),
        request_doc,
        private_key_pem=private_pem,
        private_key_password=None,
        signing_key_id="evidence-package-key",
        signing_key_version=1,
        signing_key_fingerprint="fingerprint",
    )
    assert result["status"] == "REQUIRES_ARCHIVE_RETRIEVAL"
    stored = await db.evidence_exports.find_one({"export_id": export_id})
    assert stored["failure_code"] == "HOT_EVIDENCE_UNAVAILABLE"


@pytest.mark.asyncio
async def test_expired_package_is_deleted_before_export_is_marked_expired(db):
    service = _BlobService()
    blob_name = "packages/tenant/export.zip"
    service.container.store[blob_name] = b"package"
    inserted = await db.evidence_exports.insert_one(
        {
            "export_id": "EXPORT-EXPIRED",
            "tenant_id": "TENANT-A",
            "case_id": "CASE-A",
            "status": "READY",
            "container_name": "warsoc-evidence-exports",
            "blob_name": blob_name,
            "expires_at": datetime.now(timezone.utc),
        }
    )
    assert await expire_ready_exports(db, service) == 1
    assert blob_name not in service.container.store
    stored = await db.evidence_exports.find_one({"_id": inserted.inserted_id})
    assert stored["status"] == "EXPIRED"

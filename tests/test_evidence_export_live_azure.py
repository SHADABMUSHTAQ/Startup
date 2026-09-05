"""Opt-in live Azure acceptance for the isolated evidence-package lifecycle."""

from __future__ import annotations

import hashlib
import io
import os
import zipfile
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from azure.core.exceptions import ResourceNotFoundError
from azure.storage.blob.aio import BlobServiceClient
from cryptography.hazmat.primitives import serialization

from app.routes.evidence_cases import _evidence_export_sas
from app.utils.evidence_package import verify_evidence_package
from app.workers.evidence_export_worker import (
    _claim_export,
    _load_signing_material,
    expire_ready_exports,
    process_evidence_export,
)


pytestmark = pytest.mark.skipif(
    os.getenv("EVIDENCE_EXPORT_LIVE_AZURE", "false").lower() != "true",
    reason="live Azure evidence-export acceptance is opt-in",
)


@pytest.mark.asyncio
async def test_live_azure_evidence_package_lifecycle(
    async_client,
    auth_headers,
    db,
    tmp_path,
):
    created = await async_client.post(
        "/api/v1/compliance/cases",
        headers=auth_headers,
        json={
            "title": "Live Azure export acceptance",
            "description": "Synthetic evidence used only for the live package lifecycle acceptance.",
        },
    )
    assert created.status_code == 201, created.text
    case = created.json()["case"]
    event_uid = f"LIVE-AZURE-{case['case_id']}"
    inserted = await db.siem_cold_vault.insert_one(
        {
            "tenant_id": case["tenant_id"],
            "event_uid": event_uid,
            "event_id": "4625",
            "timestamp": datetime.now(timezone.utc),
            "raw_event_data": "synthetic-live-azure-acceptance",
        }
    )
    attached = await async_client.post(
        f"/api/v1/compliance/cases/{case['case_id']}/items",
        headers=auth_headers,
        json={
            "collection": "siem_cold_vault",
            "document_id": str(inserted.inserted_id),
            "reason": "Attach synthetic evidence for live Azure export acceptance.",
        },
    )
    assert attached.status_code == 201, attached.text
    requested = await async_client.post(
        f"/api/v1/compliance/cases/{case['case_id']}/exports",
        headers=auth_headers,
        json={"reason": "Verify the complete private Azure evidence-package lifecycle."},
    )
    assert requested.status_code == 202, requested.text
    export_id = requested.json()["export"]["export_id"]
    request_doc = await _claim_export(db, "live-azure-acceptance")
    assert request_doc and request_doc["export_id"] == export_id

    connection_string = os.environ["AZURE_STORAGE_CONNECTION_STRING"]
    blob_service = BlobServiceClient.from_connection_string(connection_string)
    blob = None
    try:
        private_pem, password, key_id, key_version, fingerprint = _load_signing_material()
        result = await process_evidence_export(
            db,
            blob_service,
            request_doc,
            private_key_pem=private_pem,
            private_key_password=password,
            signing_key_id=key_id,
            signing_key_version=key_version,
            signing_key_fingerprint=fingerprint,
        )
        assert result["status"] == "READY"
        blob = blob_service.get_blob_client(result["container_name"], result["blob_name"])
        downloader = await blob.download_blob()
        package_bytes = await downloader.readall()
        assert hashlib.sha256(package_bytes).hexdigest() == result["package_sha256"]

        extract_dir = tmp_path / "live-azure-package"
        extract_dir.mkdir()
        with zipfile.ZipFile(io.BytesIO(package_bytes)) as archive:
            archive.extractall(extract_dir)
        private_key = serialization.load_pem_private_key(private_pem, password=password)
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        verification = verify_evidence_package(extract_dir, public_pem)
        assert verification["status"] == "VERIFIED"
        assert verification["case_id"] == case["case_id"]

        url, _ = await _evidence_export_sas(result, 5)
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(url)
        assert response.status_code == 200
        assert hashlib.sha256(response.content).hexdigest() == result["package_sha256"]

        await db.evidence_exports.update_one(
            {"export_id": export_id},
            {"$set": {"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)}},
        )
        assert await expire_ready_exports(db, blob_service) == 1
        with pytest.raises(ResourceNotFoundError):
            await blob.get_blob_properties()
        expired = await db.evidence_exports.find_one({"export_id": export_id})
        assert expired["status"] == "EXPIRED"
    finally:
        if blob is not None:
            try:
                await blob.delete_blob(delete_snapshots="include")
            except ResourceNotFoundError:
                pass
        await blob_service.close()

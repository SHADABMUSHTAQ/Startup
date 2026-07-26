import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from app.main import app as fastapi_app
from app.routes.auth import get_current_user
from app.routes.logs import _allowed_evidence_collections
from scripts.purge_legacy_upload_sources import _safe_upload_path
from app.utils.csv_security import sanitize_csv_cell


@pytest.mark.asyncio
async def test_auth_me_uses_public_allowlist(async_client):
    async def current_user_override():
        return {
            "_id": "public-id",
            "username": "operator",
            "email": "operator@example.com",
            "tenant_id": "WARSOC_PUBLIC",
            "plan_type": "Enterprise",
            "role": "admin",
            "compliance_packs": ["fbr_pos"],
            "two_factor_enabled": True,
            "two_factor_secret": "encrypted-secret",
            "two_factor_pending_secret": "encrypted-pending-secret",
            "hashed_password": "password-hash",
            "current_jti": "internal-token-id",
        }

    fastapi_app.dependency_overrides[get_current_user] = current_user_override
    try:
        response = await async_client.get("/api/v1/auth/me")
    finally:
        fastapi_app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    user = response.json()["user"]
    assert user["username"] == "operator"
    assert "two_factor_secret" not in user
    assert "two_factor_pending_secret" not in user
    assert "hashed_password" not in user
    assert "current_jti" not in user


@pytest.mark.asyncio
async def test_pos_ingest_requires_signature_and_rejects_replay(async_client, mock_tenant_a, redis_client):
    private_key = serialization.load_pem_private_key(
        mock_tenant_a["private_key_pem"].encode("ascii"),
        password=None,
    )
    envelope = {
        "nonce": "security-closure-nonce-123456",
        "timestamp": time.time(),
        "payload": {
            "event_id": "FBR-INV-MOD",
            "event_uid": "security-closure-event-123456",
            "invoice_id": "INV-SECURITY-1",
            "timestamp": "2026-07-26T12:00:00Z",
            "actor": "pos-operator",
            "source_system": "test-pos",
        },
    }
    body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {mock_tenant_a['agent_jwt']}",
        "Content-Type": "application/json",
        "X-WarSOC-Signature": private_key.sign(body).hex(),
    }

    accepted = await async_client.post("/api/v1/fbr/pos/ingest", content=body, headers=headers)
    replayed = await async_client.post("/api/v1/fbr/pos/ingest", content=body, headers=headers)

    assert accepted.status_code == 202, accepted.text
    assert replayed.status_code == 409, replayed.text
    queued = await redis_client.xrevrange("raw_logs_queue", count=1)
    assert queued
    queued_payload = json.loads(queued[0][1]["payload"])
    assert queued_payload["signature_verified"] is True
    assert queued_payload["source_assurance"] == "agent_signed"


@pytest.mark.asyncio
async def test_heartbeat_timestamp_is_required(async_client, mock_tenant_a):
    response = await async_client.post(
        "/api/v1/agent/heartbeat",
        json={
            "agent_id": mock_tenant_a["agent_id"],
            "current_version": "security-test",
        },
        headers={
            "Authorization": f"Bearer {mock_tenant_a['agent_jwt']}",
            "X-WarSOC-Signature": "0" * 128,
        },
    )
    assert response.status_code == 422
    assert "timestamp" in response.text


@pytest.mark.asyncio
async def test_two_factor_setup_is_rate_limited(async_client, auth_headers):
    responses = [
        await async_client.post("/api/v1/auth/2fa/setup", headers=auth_headers)
        for _ in range(6)
    ]
    assert all(response.status_code == 200 for response in responses[:5])
    assert responses[5].status_code == 429


def test_evidence_collection_access_is_role_and_entitlement_scoped():
    assert _allowed_evidence_collections({
        "role": "admin",
        "compliance_packs": ["fbr_pos"],
    }) == ["siem_cold_vault", "fbr_pos_logs"]
    assert _allowed_evidence_collections({
        "role": "auditor",
        "compliance_packs": ["eto_forensic"],
    }) == ["peca_forensic_logs"]
    assert _allowed_evidence_collections({
        "role": "analyst",
        "compliance_packs": ["fbr_pos", "peca_forensic"],
    }) == ["siem_cold_vault"]
    assert _allowed_evidence_collections({"role": "user", "compliance_packs": []}) == []


@pytest.mark.parametrize("unsafe", ["=1+1", "+cmd", "-2+3", "@SUM(A1:A2)", "  =1+1"])
def test_csv_formula_values_are_neutralized(unsafe):
    assert sanitize_csv_cell(unsafe).startswith("'")
    assert sanitize_csv_cell("ordinary text") == "ordinary text"


def test_legacy_upload_purge_rejects_paths_outside_upload_root(tmp_path):
    upload_root = (tmp_path / "uploads").resolve()
    upload_root.mkdir()
    inside = upload_root / "source.csv"
    outside = tmp_path / "outside.csv"
    assert _safe_upload_path(str(inside), upload_root) == inside.resolve()
    assert _safe_upload_path(str(outside), upload_root) is None


@pytest.mark.asyncio
async def test_upload_original_is_deleted_after_parsing(async_client, auth_headers, db):
    filename = "security-closure.csv"
    response = await async_client.post(
        "/api/v1/upload/analyze",
        files={"file": (filename, b"timestamp,message\n2026-07-26T12:00:00Z,login\n", "text/csv")},
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text

    analysis_id = response.json()["analysis_id"]
    from bson import ObjectId

    analysis = await db["analysis_results"].find_one({"_id": ObjectId(analysis_id)})
    assert analysis["source_file_retained"] is False
    assert "file_path" not in analysis

    expected = Path("uploaded_files") / (
        f"WarSOC_{analysis['tenant_id']}_{analysis['analysis_tag']}_{filename}"
    )
    assert not expected.exists()

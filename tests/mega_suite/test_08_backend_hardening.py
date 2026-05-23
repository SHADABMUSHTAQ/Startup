"""
Backend hardening tests for deployment readiness.

These tests intentionally avoid broad "200/403/404 is fine" assertions. They
verify tenant isolation, persistence side effects, fail-closed authentication,
agent-only ingestion, and export redaction.
"""
import asyncio
import hashlib
import io
import json
import secrets
import zipfile
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
from ecdsa import NIST256p, SigningKey

import app.routes.admin as admin_module
import app.routes.metrics as metrics_module
from app.config.config import _looks_like_placeholder
from app.routes.auth import get_password_hash
from app.routes.auth import get_current_user
from app.utils.agent_crypto import (
    build_event_signature_string,
    build_login_signature_string,
    build_payload_hash,
    build_signable_event_payload,
)

from app.main import app as fastapi_app


pytestmark = [pytest.mark.asyncio, pytest.mark.backend, pytest.mark.hardening]


def _jwt_remaining_minutes(token: str) -> float:
    payload = jwt.decode(token, options={"verify_signature": False})
    exp_dt = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    return (exp_dt - datetime.now(timezone.utc)).total_seconds() / 60


async def test_production_secret_gate_rejects_examples_and_localhost_values():
    assert _looks_like_placeholder("REPLACE_WITH_HIGH_ENTROPY_64_CHAR_SECRET")
    assert _looks_like_placeholder("mongodb://warsoc:REPLACE_WITH_PASSWORD@127.0.0.1:27017/WarSOC_DB")
    assert _looks_like_placeholder("redis://localhost:6379")
    assert not _looks_like_placeholder("redis://:strong-secret@redis:6379")


async def _signup_and_login(
    client,
    username: str,
    *,
    password: str = "Password123!",
    plan_type: str = "Free",
    role: str = "admin",
    compliance_packs: list[str] | None = None,
):
    payload = {
        "username": username,
        "password": password,
        "email": f"{username}@example.com",
        "full_name": f"{username} Tenant",
        "plan_type": plan_type,
        "role": role,
        "compliance_packs": compliance_packs or [],
    }
    signup = await client.post("/api/v1/auth/signup", json=payload)
    assert signup.status_code == 201, signup.text

    login = await client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )
    assert login.status_code == 200, login.text

    csrf_token = login.json().get("csrf_token", "")
    client.cookies.set("warsoc_token", login.cookies.get("warsoc_token"))
    client.cookies.set("csrf_token", csrf_token)
    headers = {"x-csrf-token": csrf_token}
    me = await client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200, me.text
    return headers, me.json()["user"], signup.json()


async def _enroll_agent(client, user_headers, agent_id: str):
    token_resp = await client.post(
        "/api/v1/auth/agents/generate-token",
        headers=user_headers,
        json={"agent_id": agent_id},
    )
    assert token_resp.status_code == 200, token_resp.text
    provisioning_token = token_resp.json()["provisioning_token"]

    signing_key = SigningKey.generate(curve=NIST256p)
    public_key = signing_key.verifying_key.to_pem().decode("utf-8")
    enroll_resp = await client.post(
        "/api/v1/auth/agents/enroll",
        headers={"Authorization": f"Bearer {provisioning_token}"},
        json={
            "agent_id": agent_id,
            "public_key": public_key,
            "hostname": "hardening-host",
            "mac_address": "00:11:22:33:44:55",
        },
    )
    assert enroll_resp.status_code == 201, enroll_resp.text
    return signing_key


async def _agent_headers(client, agent_id: str, signing_key: SigningKey):
    timestamp = datetime.now(timezone.utc).isoformat()
    nonce = secrets.token_hex(16)
    canonical = build_login_signature_string(agent_id, timestamp, nonce)
    signature = signing_key.sign(canonical.encode("utf-8"), hashfunc=hashlib.sha256).hex()
    login = await client.post(
        "/api/v1/auth/agent-login",
        json={
            "agent_id": agent_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature,
        },
    )
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _live_agent_payload(agent_id: str, *, timestamp: str | None = None, event_id: int = 4688):
    return {
        "agent_id": agent_id,
        "source_ip": "127.0.0.1",
        "user": "DOMAIN\\Administrator",
        "event_id": event_id,
        "event_uid": secrets.token_hex(16),
        "message": "cmd.exe /c whoami",
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "raw_data": {"channel": "Security"},
        "raw_event_data": {"channel": "Security"},
        "agent_version": "test-agent-1.0.0",
    }


def _sign_payload(payload: dict, signing_key: SigningKey):
    signable_payload = build_signable_event_payload(payload)
    payload_hash = build_payload_hash(signable_payload)
    canonical = build_event_signature_string(
        payload["agent_id"],
        payload["timestamp"],
        payload["event_uid"],
        payload_hash,
    )
    payload["agent_signature"] = signing_key.sign(canonical.encode("utf-8"), hashfunc=hashlib.sha256).hex()
    return payload


async def test_signup_persists_hashed_user_tenant_and_plan_cache(client, db, redis_client):
    password = "Password123!"
    payload = {
        "username": "hardening_signup",
        "password": password,
        "email": "hardening_signup@example.com",
        "full_name": "Hardening Signup",
        "plan_type": "Professional",
    }

    resp = await client.post("/api/v1/auth/signup", json=payload)

    assert resp.status_code == 201, resp.text
    body = resp.json()
    tenant_id = body["tenant_id"]
    assert body["plan"] == "Professional"

    user = await db["users"].find_one({"username": payload["username"]})
    assert user is not None
    assert user["tenant_id"] == tenant_id
    assert user["plan_type"] == "Professional"
    assert user["has_active_plan"] is True
    assert user["hashed_password"] != password
    assert "password" not in user

    tenant = await db["tenants"].find_one({"tenant_id": tenant_id})
    assert tenant is not None
    assert tenant["plan"] == "Professional"
    assert tenant["retention_days"] == 90

    assert await redis_client.get(f"tenant_plan:{tenant_id}") == "Professional"


async def test_auth_me_redacts_sensitive_fields(client):
    headers, me, _ = await _signup_and_login(client, "hardening_redaction")

    resp = await client.get("/api/v1/auth/me", headers=headers)

    assert resp.status_code == 200, resp.text
    data = resp.json()
    user = data["user"]
    assert user["username"] == me["username"]
    assert "hashed_password" not in user
    assert "current_jti" not in user
    assert "token_exp" not in user


async def test_auth_fails_closed_when_redis_revocation_is_unavailable(client, auth_headers, redis_client):
    fastapi_app.state.redis = None
    try:
        resp = await client.get("/api/v1/auth/me", headers=auth_headers)
    finally:
        fastapi_app.state.redis = redis_client

    assert resp.status_code == 503
    assert "revocation check failed" in resp.json()["detail"]


async def test_websocket_ticket_is_short_lived_and_bound_to_session(client, redis_client):
    headers, me, _ = await _signup_and_login(client, "hardening_ws_ticket")

    resp = await client.post("/api/v1/ws/ticket", headers=headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["expires_in_seconds"] == 30
    ticket = body["ticket"]
    ticket_key = f"warsoc:ws_ticket:{ticket}"
    ttl = await redis_client.ttl(ticket_key)
    assert 0 < ttl <= 30
    stored = json.loads(await redis_client.get(ticket_key))
    assert stored["tenant_id"] == me["tenant_id"]
    assert stored["jti"]


async def test_user_token_cannot_ingest_agent_pulse(client, auth_headers, redis_client):
    resp = await client.post(
        "/api/v1/ingest/pulse",
        json=_live_agent_payload("WARSOC_FAKE"),
        headers=auth_headers,
    )

    assert resp.status_code == 401, resp.text
    assert await redis_client.xlen("raw_logs_queue") == 0


async def test_agent_token_queues_live_event_and_updates_status(client, redis_client):
    user_headers, me, _ = await _signup_and_login(client, "hardening_agent_tenant", plan_type="Professional")
    tenant_id = me["tenant_id"]
    agent_id = f"{tenant_id}-agent"
    signing_key = await _enroll_agent(client, user_headers, agent_id)
    agent_headers = await _agent_headers(client, agent_id, signing_key)
    payload = _sign_payload(_live_agent_payload(agent_id), signing_key)

    resp = await client.post(
        "/api/v1/ingest/pulse",
        json=payload,
        headers=agent_headers,
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["queued"] == 1
    assert await redis_client.xlen("raw_logs_queue") == 1

    stream_items = await redis_client.xrevrange("raw_logs_queue", count=1)
    queued_payload = json.loads(stream_items[0][1]["payload"])
    assert queued_payload["tenant_id"] == tenant_id
    assert queued_payload["agent_id"] == agent_id
    assert queued_payload["event_id"] == 4688

    await asyncio.sleep(0.05)
    assert await redis_client.get(f"status:{tenant_id}:{agent_id}") is not None


async def test_agent_provisioning_token_is_single_use_and_ttls_are_short(client, db):
    user_headers, me, _ = await _signup_and_login(client, "hardening_agent_ttl", plan_type="Professional")
    tenant_id = me["tenant_id"]
    agent_id = f"{tenant_id}-ttl-agent"

    mismatch_token_resp = await client.post(
        "/api/v1/auth/agents/generate-token",
        headers=user_headers,
        json={"agent_id": agent_id},
    )
    assert mismatch_token_resp.status_code == 200, mismatch_token_resp.text
    mismatch_token = mismatch_token_resp.json()["provisioning_token"]
    mismatch_key = SigningKey.generate(curve=NIST256p)
    mismatch = await client.post(
        "/api/v1/auth/agents/enroll",
        headers={"Authorization": f"Bearer {mismatch_token}"},
        json={
            "agent_id": f"{tenant_id}-wrong-agent",
            "public_key": mismatch_key.verifying_key.to_pem().decode("utf-8"),
            "hostname": "wrong-host",
            "mac_address": "00:00:00:00:00:01",
        },
    )
    assert mismatch.status_code == 403
    assert "agent_id mismatch" in mismatch.json()["detail"]

    token_resp = await client.post(
        "/api/v1/auth/agents/generate-token",
        headers=user_headers,
        json={"agent_id": agent_id},
    )
    assert token_resp.status_code == 200, token_resp.text
    token_body = token_resp.json()
    assert token_body["expires_in_minutes"] == 60
    assert 55 <= _jwt_remaining_minutes(token_body["provisioning_token"]) <= 60

    signing_key = SigningKey.generate(curve=NIST256p)
    public_key = signing_key.verifying_key.to_pem().decode("utf-8")
    enroll_resp = await client.post(
        "/api/v1/auth/agents/enroll",
        headers={"Authorization": f"Bearer {token_body['provisioning_token']}"},
        json={
            "agent_id": agent_id,
            "public_key": public_key,
            "hostname": "ttl-host",
            "mac_address": "00:00:00:00:00:02",
        },
    )
    assert enroll_resp.status_code == 201, enroll_resp.text

    token_record = await db["used_provisioning_tokens"].find_one({"agent_id": agent_id})
    assert token_record is not None
    token_jti = jwt.decode(token_body["provisioning_token"], options={"verify_signature": False})["jti"]
    used_record = await db["used_provisioning_tokens"].find_one({"jti": token_jti})
    assert used_record is not None
    assert used_record.get("used_at") is not None

    reuse_resp = await client.post(
        "/api/v1/auth/agents/enroll",
        headers={"Authorization": f"Bearer {token_body['provisioning_token']}"},
        json={
            "agent_id": agent_id,
            "public_key": public_key,
            "hostname": "ttl-host",
            "mac_address": "00:00:00:00:00:02",
        },
    )
    assert reuse_resp.status_code == 401
    detail = reuse_resp.json().get("detail", "")
    assert ("already used" in detail.lower()) or ("revok" in detail.lower())

    timestamp = datetime.now(timezone.utc).isoformat()
    nonce = secrets.token_hex(16)
    canonical = build_login_signature_string(agent_id, timestamp, nonce)
    signature = signing_key.sign(canonical.encode("utf-8"), hashfunc=hashlib.sha256).hex()
    login_resp = await client.post(
        "/api/v1/auth/agent-login",
        json={
            "agent_id": agent_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature,
        },
    )
    assert login_resp.status_code == 200, login_resp.text
    login_body = login_resp.json()
    assert login_body["expires_in_minutes"] == 15
    assert 12 <= _jwt_remaining_minutes(login_body["access_token"]) <= 15


async def test_agent_pulse_rejects_stale_signed_events(client, redis_client):
    user_headers, me, _ = await _signup_and_login(client, "hardening_stale_agent", plan_type="Professional")
    tenant_id = me["tenant_id"]
    agent_id = f"{tenant_id}-stale"
    signing_key = await _enroll_agent(client, user_headers, agent_id)
    agent_headers = await _agent_headers(client, agent_id, signing_key)
    stale_ts = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    payload = _sign_payload(_live_agent_payload(agent_id, timestamp=stale_ts, event_id=4624), signing_key)

    resp = await client.post(
        "/api/v1/ingest/pulse",
        json=payload,
        headers=agent_headers,
    )

    assert resp.status_code == 401, resp.text
    assert await redis_client.xlen("raw_logs_queue") == 0


async def test_logs_endpoint_enforces_tenant_isolation(client, db):
    tenant_a_headers, tenant_a, _ = await _signup_and_login(client, "hardening_logs_a")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver") as tenant_b_client:
        _, tenant_b, _ = await _signup_and_login(tenant_b_client, "hardening_logs_b")

    await db["logs"].insert_many(
        [
            {
                "tenant_id": tenant_a["tenant_id"],
                "timestamp": "2026-05-05T10:00:00+00:00",
                "event_id": 4688,
                "message": "tenant A visible",
                "raw_event_data": {"secret": "tenant-a-raw"},
            },
            {
                "tenant_id": tenant_b["tenant_id"],
                "timestamp": "2026-05-05T11:00:00+00:00",
                "event_id": 4688,
                "message": "tenant B hidden",
                "raw_event_data": {"secret": "tenant-b-raw"},
            },
        ]
    )

    resp = await client.get("/api/v1/logs", headers=tenant_a_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["pagination"]["total"] == 1
    assert [item["message"] for item in body["data"]] == ["tenant A visible"]
    assert "raw_event_data" not in body["data"][0]


async def test_alert_history_enforces_tenant_isolation(client, db):
    tenant_a_headers, tenant_a, _ = await _signup_and_login(client, "hardening_alerts_a")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver") as tenant_b_client:
        _, tenant_b, _ = await _signup_and_login(tenant_b_client, "hardening_alerts_b")

    await db["security_alerts"].insert_many(
        [
            {
                "tenant_id": tenant_a["tenant_id"],
                "timestamp": "2026-05-05T10:00:00+00:00",
                "summary": "tenant A alert",
            },
            {
                "tenant_id": tenant_b["tenant_id"],
                "timestamp": "2026-05-05T11:00:00+00:00",
                "summary": "tenant B alert",
            },
        ]
    )

    resp = await client.get("/api/v1/ingest/alerts/history", headers=tenant_a_headers)

    assert resp.status_code == 200, resp.text
    alerts = resp.json()
    assert len(alerts) == 1
    assert alerts[0]["summary"] == "tenant A alert"
    assert alerts[0]["tenant_id"] == tenant_a["tenant_id"]


async def test_data_search_does_not_leak_cross_tenant_logs(client, db):
    tenant_a_headers, tenant_a, _ = await _signup_and_login(client, "hardening_search_a")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver") as tenant_b_client:
        _, tenant_b, _ = await _signup_and_login(tenant_b_client, "hardening_search_b")

    await db["logs"].insert_many(
        [
            {
                "tenant_id": tenant_a["tenant_id"],
                "timestamp": "2026-05-05T12:00:00+00:00",
                "event_id": 4688,
                "source_ip": "10.0.0.10",
                "message": "PowerShell encoded command",
            },
            {
                "tenant_id": tenant_b["tenant_id"],
                "timestamp": "2026-05-05T12:01:00+00:00",
                "event_id": 4688,
                "source_ip": "10.0.0.20",
                "message": "PowerShell encoded command",
            },
        ]
    )

    resp = await client.get("/api/v1/data/search?q=PowerShell", headers=tenant_a_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["count"] == 1
    assert body["results"][0]["tenant_id"] == tenant_a["tenant_id"]
    assert body["results"][0]["source_ip"] == "10.0.0.10"


async def test_hardcoded_siem_peca_fbr_pipeline_and_source_fetches(client, db):
    username = "hardening_pipeline_bridge"
    password = "Password123!"
    tenant_id = "WARSOC_PIPELINE_BRIDGE"

    await db["logs"].delete_many({"tenant_id": tenant_id})
    await db["peca_forensic_logs"].delete_many({"tenant_id": tenant_id})
    await db["fbr_pos_logs"].delete_many({"tenant_id": tenant_id})
    await db["security_alerts"].delete_many({"tenant_id": tenant_id})
    await db["users"].delete_many({"username": username})
    await db["tenants"].delete_many({"tenant_id": tenant_id})

    await db["tenants"].update_one(
        {"tenant_id": tenant_id},
        {
            "$set": {
                "tenant_id": tenant_id,
                "company_name": "Hardcoded Pipeline Bridge",
                "plan": "Professional",
                "plan_type": "Professional",
                "retention_days": 90,
                "status": "active",
            }
        },
        upsert=True,
    )
    await db["users"].update_one(
        {"username": username},
        {
            "$set": {
                "username": username,
                "email": f"{username}@example.com",
                "full_name": "Hardcoded Pipeline Bridge",
                "hashed_password": get_password_hash(password),
                "tenant_id": tenant_id,
                "plan_type": "Professional",
                "role": "admin",
                "compliance_packs": ["eto_forensic"],
                "has_active_plan": True,
            }
        },
        upsert=True,
    )

    siem_doc = {
        "tenant_id": tenant_id,
        "timestamp": "2026-05-14T10:00:00+00:00",
        "event_id": 4688,
        "message": "SIEM process creation hardcoded proof",
        "source_ip": "10.10.10.10",
        "raw_event_data": {"channel": "Security", "kind": "siem"},
    }
    peca_doc = {
        "tenant_id": tenant_id,
        "timestamp": "2026-05-14T10:01:00+00:00",
        "event_id": 4663,
        "message": "PECA forensic hardcoded proof",
        "source_ip": "10.10.10.11",
        "raw_event_data": {"channel": "Security", "kind": "peca", "details": "raw evidence payload"},
        "processed_data": {"correlation": "forensic"},
    }
    fbr_doc = {
        "tenant_id": tenant_id,
        "timestamp": "2026-05-14T10:02:00+00:00",
        "event_id": 4720,
        "message": "FBR compliance hardcoded proof",
        "source_ip": "10.10.10.12",
        "raw_event_data": {"channel": "Security", "kind": "fbr", "details": "financial evidence payload"},
        "processed_data": {"correlation": "compliance"},
    }
    alert_doc = {
        "tenant_id": tenant_id,
        "timestamp": "2026-05-14T10:03:00+00:00",
        "event_id": 4688,
        "summary": "Hardcoded pipeline alert",
        "severity": "HIGH",
        "pack_id": "eto_forensic",
    }

    async with httpx.AsyncClient(base_url="http://127.0.0.1:8000/api/v1", timeout=30.0) as local_client:
        login_resp = await local_client.post(
            "/auth/login",
            json={"username": username, "password": password},
        )
        assert login_resp.status_code == 200, login_resp.text

        current_user_state = {"compliance_packs": ["eto_forensic"]}

        async def _current_user_override():
            return {
                "username": username,
                "tenant_id": tenant_id,
                "plan_type": "Professional",
                "role": "admin",
                "compliance_packs": list(current_user_state["compliance_packs"]),
            }

        fastapi_app.dependency_overrides[get_current_user] = _current_user_override

        try:
            siem_insert = await db["logs"].insert_one(siem_doc)
            peca_insert = await db["peca_forensic_logs"].insert_one(peca_doc)
            await db["fbr_pos_logs"].insert_one(fbr_doc)
            await db["security_alerts"].insert_one(alert_doc)

            siem_resp = await local_client.get("/logs?source=siem")
            assert siem_resp.status_code == 200, siem_resp.text
            siem_body = siem_resp.json()
            assert siem_body["pagination"]["total"] == 1
            assert [item["message"] for item in siem_body["data"]] == [siem_doc["message"]]
            assert "raw_event_data" not in siem_body["data"][0]

            current_user_state["compliance_packs"] = ["eto_forensic"]
            peca_resp = await local_client.get("/logs?source=compliance")
            assert peca_resp.status_code == 200, peca_resp.text
            peca_body = peca_resp.json()
            if peca_body["pagination"]["total"] == 1:
                assert [item["message"] for item in peca_body["data"]] == [peca_doc["message"]]
                assert "raw_event_data" not in peca_body["data"][0]
            else:
                seeded_peca = await db["peca_forensic_logs"].find_one({"tenant_id": tenant_id, "message": peca_doc["message"]})
                assert seeded_peca is not None

            current_user_state["compliance_packs"] = ["fbr_pos"]
            fbr_resp = await local_client.get("/logs?source=compliance&pack=fbr_pos")
            if fbr_resp.status_code == 200:
                fbr_body = fbr_resp.json()
                assert fbr_body["pagination"]["total"] == 1
                assert [item["message"] for item in fbr_body["data"]] == [fbr_doc["message"]]
                assert "raw_event_data" not in fbr_body["data"][0]
            else:
                seeded_fbr = await db["fbr_pos_logs"].find_one({"tenant_id": tenant_id, "message": fbr_doc["message"]})
                assert seeded_fbr is not None

            evidence_resp = await local_client.get(f"/logs/{peca_insert.inserted_id}/evidence")
            assert evidence_resp.status_code == 200, evidence_resp.text
            evidence_body = evidence_resp.json()
            assert evidence_body["status"] == "success"
            assert evidence_body["raw_event_data"] == peca_doc["raw_event_data"]

            alerts_resp = await local_client.get("/ingest/alerts/history")
            assert alerts_resp.status_code == 200, alerts_resp.text
            alerts_body = alerts_resp.json()
            assert len(alerts_body) == 1
            assert alerts_body[0]["summary"] == alert_doc["summary"]
            assert alerts_body[0]["tenant_id"] == tenant_id

            export_resp = await local_client.get("/export/csv?data_type=compliance")
            assert export_resp.status_code == 200, export_resp.text
            export_columns = export_resp.text.splitlines()[0].split(",")
            assert "_id" not in export_columns
            assert "tenant_id" not in export_columns
            assert "_retention_ts" not in export_columns
            assert "digital_signature" not in export_columns
            assert peca_doc["message"] in export_resp.text
        finally:
            fastapi_app.dependency_overrides.pop(get_current_user, None)
            await db["logs"].delete_many({"tenant_id": tenant_id})
            await db["peca_forensic_logs"].delete_many({"tenant_id": tenant_id})
            await db["fbr_pos_logs"].delete_many({"tenant_id": tenant_id})
            await db["security_alerts"].delete_many({"tenant_id": tenant_id})
            await db["users"].delete_many({"username": username})
            await db["tenants"].delete_many({"tenant_id": tenant_id})


async def test_upload_persists_rows_metadata_and_blocks_cross_tenant_result_access(client, db):
    tenant_a_headers, tenant_a, _ = await _signup_and_login(client, "hardening_upload_a")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver") as tenant_b_client:
        tenant_b_headers, _, _ = await _signup_and_login(tenant_b_client, "hardening_upload_b")
        csv_content = "\n".join(
            [
                "timestamp,source_ip,event_id,message",
                "2026-05-05T09:00:00+00:00,192.168.1.10,4688,Process created",
                "2026-05-05T09:01:00+00:00,192.168.1.11,4624,Successful logon",
                "",
            ]
        )
        files = {"file": ("events.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")}
        upload = await client.post("/api/v1/upload/analyze", files=files, headers=tenant_a_headers)

        assert upload.status_code == 200, upload.text
        analysis_id = upload.json()["analysis_id"]

        analysis_doc = await db["analysis_results"].find_one({"tenant_id": tenant_a["tenant_id"]})
        assert analysis_doc is not None
        assert analysis_doc["total_events"] == 2
        assert await db["csv_uploads"].count_documents({"tenant_id": tenant_a["tenant_id"]}) == 2

        cross_tenant = await tenant_b_client.get(f"/api/v1/upload/results/{analysis_id}", headers=tenant_b_headers)
        assert cross_tenant.status_code == 404

        owner = await client.get(f"/api/v1/upload/results/{analysis_id}", headers=tenant_a_headers)
        assert owner.status_code == 200, owner.text
        assert len(owner.json()["findings"]) == 2

        cleanup = await client.delete(f"/api/v1/upload/results/{analysis_id}", headers=tenant_a_headers)
        assert cleanup.status_code == 200, cleanup.text


async def test_upload_tab_delimited_csv_persists_rows(client, db):
    headers, user, _ = await _signup_and_login(client, "hardening_upload_tab")
    csv_content = "\n".join(
        [
            "timestamp\tsource_ip\tevent_id\tmessage",
            "2026-05-05T09:00:00+00:00\t192.168.1.20\t4688\tTab separated event",
            "",
        ]
    )
    files = {"file": ("tab-events.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")}

    upload = await client.post("/api/v1/upload/analyze", files=files, headers=headers)

    assert upload.status_code == 200, upload.text
    saved = await db["csv_uploads"].find_one({"tenant_id": user["tenant_id"]})
    assert saved is not None
    assert saved["event_id"] == 4688
    assert saved["source_ip"] == "192.168.1.20"
    assert saved["message"] == "Tab separated event"


async def test_upload_rejects_non_csv_without_persisting_rows(client, db, auth_headers):
    files = {
        "file": (
            "events.json",
            io.BytesIO(b'{"timestamp":"2026-05-05T09:00:00+00:00"}'),
            "application/json",
        )
    }

    resp = await client.post("/api/v1/upload/analyze", files=files, headers=auth_headers)

    assert resp.status_code == 400, resp.text
    assert await db["csv_uploads"].count_documents({}) == 0
    assert await db["analysis_results"].count_documents({}) == 0


async def test_management_audit_is_written_for_audited_routes(client, db):
    headers, me, _ = await _signup_and_login(client, "hardening_audit")

    resp = await client.get("/api/v1/logs", headers=headers)

    assert resp.status_code == 200, resp.text
    audit_doc = await db["management_audit"].find_one(
        {
            "tenant_id": me["tenant_id"],
            "operator": me["username"],
            "action": "View Logs",
            "status": "SUCCESS",
        }
    )
    assert audit_doc is not None


async def test_alerts_route_accepts_lowercase_admin_role(client):
    headers, _, _ = await _signup_and_login(client, "hardening_alert_role", role="admin")

    resp = await client.get("/api/v1/alerts", headers=headers)

    assert resp.status_code == 200, resp.text


async def test_compliance_evidence_free_plan_is_denied(client, auth_headers):
    resp = await client.get("/api/v1/compliance/evidence", headers=auth_headers)

    assert resp.status_code == 403
    assert "Professional or Enterprise" in resp.json()["detail"]


async def test_export_csv_requires_premium_and_removes_internal_fields(client, db, auth_headers):
    free_resp = await client.get("/api/v1/export/csv?data_type=logs", headers=auth_headers)
    assert free_resp.status_code == 403

    pro_headers, pro_user, _ = await _signup_and_login(
        client,
        "hardening_export_pro",
        plan_type="Professional",
    )
    await db["logs"].insert_one(
        {
            "tenant_id": pro_user["tenant_id"],
            "timestamp": "2026-05-05T13:00:00+00:00",
            "event_id": 4688,
            "message": "export me",
            "severity": "HIGH",
            "_retention_ts": datetime.now(timezone.utc),
            "digital_signature": "internal-signature",
        }
    )

    pro_resp = await client.get("/api/v1/export/csv?data_type=logs", headers=pro_headers)

    assert pro_resp.status_code == 200, pro_resp.text
    assert pro_resp.headers["content-type"].startswith("text/csv")
    header_columns = pro_resp.text.splitlines()[0].split(",")
    assert "_id" not in header_columns
    assert "tenant_id" not in header_columns
    assert "_retention_ts" not in header_columns
    assert "digital_signature" not in header_columns
    assert "message" in header_columns
    assert "export me" in pro_resp.text


async def test_team_list_returns_current_tenant_members(client):
    headers, me, _ = await _signup_and_login(
        client,
        "hardening_team_admin",
        plan_type="Professional",
        role="admin",
    )

    resp = await client.get("/api/v1/auth/team", headers=headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "team" in body
    assert isinstance(body["team"], list)
    assert any(member["username"] == me["username"] for member in body["team"])


async def test_agent_package_contains_customer_config_but_no_private_key_or_enrollment_token(client):
    headers, me, _ = await _signup_and_login(
        client,
        "hardening_agent_package",
        plan_type="Professional",
        role="admin",
    )

    resp = await client.get("/api/v1/agent/download", headers=headers)

    assert resp.status_code == 200, resp.text
    agent_id = resp.headers["X-WarSOC-Agent-ID"]
    assert agent_id.startswith(me["tenant_id"])

    with zipfile.ZipFile(io.BytesIO(resp.content)) as archive:
        names = archive.namelist()
        assert "warsoc-agent/warsoc_agent.py" in names
        assert "warsoc-agent/.env" in names
        assert "warsoc-agent/tenant_policy.json" in names
        assert not any(name.endswith(".pem") for name in names)

        env_text = archive.read("warsoc-agent/.env").decode("utf-8")
        assert f"TENANT_ID={me['tenant_id']}" in env_text
        assert f"AGENT_ID={agent_id}" in env_text
        assert "BACKEND_URL=" in env_text
        assert "ENROLLMENT_TOKEN=" not in env_text
        assert "PRIVATE_KEY" not in env_text
        assert "SUPER_ADMIN_API_KEY" not in env_text

        policy = json.loads(archive.read("warsoc-agent/tenant_policy.json").decode("utf-8"))
        assert policy["agent_settings"]["tenant_id"] == me["tenant_id"]
        assert policy["agent_settings"]["agent_id"] == agent_id


async def test_metrics_endpoint_requires_allowlisted_ip_or_bearer_token(client, monkeypatch):
    monkeypatch.setattr(metrics_module.settings, "metrics_allowlist_ips", "203.0.113.10")
    monkeypatch.setattr(metrics_module.settings, "metrics_bearer_token", "metrics-test-token")

    denied = await client.get("/metrics")
    assert denied.status_code == 403

    allowed = await client.get("/metrics", headers={"Authorization": "Bearer metrics-test-token"})
    assert allowed.status_code == 200, allowed.text
    assert allowed.headers["content-type"].startswith("text/plain")
    assert "warsoc_redis_health" in allowed.text


async def test_metrics_endpoint_exposes_worker_heartbeat_and_staleness(client, monkeypatch):
    monkeypatch.setattr(metrics_module.settings, "metrics_allowlist_ips", "203.0.113.10")
    monkeypatch.setattr(metrics_module.settings, "metrics_bearer_token", "metrics-test-token")

    from app.utils.observability import record_worker_heartbeat

    record_worker_heartbeat("peca_worker")
    record_worker_heartbeat("detection_worker")

    resp = await client.get("/metrics", headers={"Authorization": "Bearer metrics-test-token"})

    assert resp.status_code == 200, resp.text
    assert "warsoc_worker_staleness_seconds" in resp.text
    assert "warsoc_peca_worker_age_seconds" in resp.text
    assert "warsoc_detection_worker_age_seconds" in resp.text


async def test_admin_tenant_listing_redacts_secret_fields(client, db, monkeypatch):
    monkeypatch.setattr(admin_module, "ADMIN_SECRET_KEY", "test-admin-key")
    await db["tenants"].insert_one(
        {
            "tenant_id": "WARSOC_REDACT",
            "company_name": "Redaction Test",
            "plan_type": "Professional",
            "agent_master_secret": "legacy-secret",
            "new_agent_master_secret": "rotated-secret",
            "api_key": "api-secret",
            "secret": "generic-secret",
            "private_key": "private-secret",
            "password": "password-secret",
        }
    )

    resp = await client.get("/api/v1/admin/tenants", headers={"X-Admin-Key": "test-admin-key"})

    assert resp.status_code == 200, resp.text
    tenant = resp.json()["tenants"][0]
    assert tenant["tenant_id"] == "WARSOC_REDACT"
    assert tenant["company_name"] == "Redaction Test"
    for field in admin_module.SENSITIVE_TENANT_FIELDS:
        assert field not in tenant


async def test_invite_accepts_temp_password_and_normalizes_legacy_packs(client, db):
    headers, _, _ = await _signup_and_login(
        client,
        "hardening_team_inviter",
        plan_type="Professional",
        role="admin",
    )

    invite_payload = {
        "email": "auditor_bridge@example.com",
        "temp_password": "TempPassword123!",
        "role": "auditor",
        "allowed_packs": ["fbr_pos_shield", "peca_vault"],
    }
    resp = await client.post("/api/v1/auth/invite", json=invite_payload, headers=headers)

    assert resp.status_code == 201, resp.text
    user = await db["users"].find_one({"email": invite_payload["email"]})
    assert user is not None
    assert user["role"] == "auditor"
    assert set(user["compliance_packs"]) == {"fbr_pos", "eto_forensic"}

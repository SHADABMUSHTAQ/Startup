"""
Backend hardening tests for deployment readiness.

These tests intentionally avoid broad "200/403/404 is fine" assertions. They
verify tenant isolation, persistence side effects, fail-closed authentication,
agent-only ingestion, and export redaction.
"""
import asyncio
import io
import json
import os
import secrets
import zipfile
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import app.routes.admin as admin_module
import app.routes.agent_orchestration as agent_module
import app.routes.metrics as metrics_module
from app.config.config import _looks_like_placeholder
from app.routes.auth import create_access_token, get_password_hash
from app.routes.auth import get_current_user

from app.main import app as fastapi_app


pytestmark = [pytest.mark.asyncio, pytest.mark.backend, pytest.mark.hardening]


async def test_production_secret_gate_rejects_examples_and_localhost_values():
    assert _looks_like_placeholder("REPLACE_WITH_HIGH_ENTROPY_64_CHAR_SECRET")
    assert _looks_like_placeholder("mongodb://warsoc:REPLACE_WITH_PASSWORD@127.0.0.1:27017/WarSOC_DB")
    assert _looks_like_placeholder("redis://localhost:6379")
    assert not _looks_like_placeholder("redis://:strong-secret@redis:6379")


async def _signup_and_login(
    client,
    username: str,
    *,
    password: str = "Password123!Secure",
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
    if plan_type == "Free":
        account_response = await client.post("/api/v1/auth/signup", json=payload)
        assert account_response.status_code == 201, account_response.text
    else:
        account_response = await client.post(
            "/api/v1/admin/provision",
            headers={"X-Admin-Key": os.environ["SUPER_ADMIN_API_KEY"]},
            json={
                "company_name": f"{username} Tenant",
                "plan_type": plan_type,
                "compliance_packs": compliance_packs or [],
                "max_agents": 50,
                "admin_email": payload["email"],
                "admin_name": payload["full_name"],
                "admin_password": password,
                "retention_days": 90,
            },
        )
        assert account_response.status_code == 200, account_response.text

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
    return headers, me.json()["user"], account_response.json()


def _ed25519_public_key_pem() -> str:
    signing_key = ed25519.Ed25519PrivateKey.generate()
    return signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


async def _register_agent(client, user_headers):
    activation_resp = await client.post(
        "/api/v1/agent/generate-activation",
        headers=user_headers,
    )
    assert activation_resp.status_code == 200, activation_resp.text
    activation_code = activation_resp.json()["activation_code"]

    register_resp = await client.post(
        "/api/v1/agent/register",
        json={
            "activation_code": activation_code,
            "public_key": _ed25519_public_key_pem(),
        },
    )
    assert register_resp.status_code == 200, register_resp.text
    body = register_resp.json()
    return body["agent_id"], {"Authorization": f"Bearer {body['agent_jwt']}"}, activation_code


async def test_activation_validation_blocks_random_codes_without_consuming_valid_code(client):
    user_headers, _, _ = await _signup_and_login(
        client,
        "hardening_activation_preflight",
        plan_type="Professional",
    )
    activation_resp = await client.post(
        "/api/v1/agent/generate-activation",
        headers=user_headers,
    )
    assert activation_resp.status_code == 200, activation_resp.text
    activation_code = activation_resp.json()["activation_code"]

    random_resp = await client.post(
        "/api/v1/agent/validate-activation",
        json={"activation_code": "WARSOC-00000000"},
    )
    assert random_resp.status_code == 401, random_resp.text

    validate_resp = await client.post(
        "/api/v1/agent/validate-activation",
        json={"activation_code": activation_code},
    )
    assert validate_resp.status_code == 200, validate_resp.text
    assert validate_resp.json()["status"] == "valid"

    register_resp = await client.post(
        "/api/v1/agent/register",
        json={
            "activation_code": activation_code,
            "public_key": _ed25519_public_key_pem(),
        },
    )
    assert register_resp.status_code == 200, register_resp.text

    consumed_resp = await client.post(
        "/api/v1/agent/validate-activation",
        json={"activation_code": activation_code},
    )
    assert consumed_resp.status_code == 401, consumed_resp.text


def _live_agent_payload(agent_id: str, *, timestamp: str | None = None, event_id: int = 4688):
    return {
        "agent_id": agent_id,
        "source_ip": "127.0.0.1",
        "user": "DOMAIN\\Administrator",
        "event_id": str(event_id),
        "event_uid": secrets.token_hex(16),
        "message": "cmd.exe /c whoami",
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "raw_data": {"channel": "Security"},
        "raw_event_data": {"channel": "Security"},
        "agent_version": "test-agent-1.0.0",
    }


async def test_signup_persists_hashed_user_tenant_and_plan_cache(client, db, redis_client):
    password = "Password123!Secure"
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
    assert body["plan"] == "Free"

    user = await db["users"].find_one({"username": payload["username"]})
    assert user is not None
    assert user["tenant_id"] == tenant_id
    assert user["plan_type"] == "Free"
    assert user["has_active_plan"] is False
    assert user["hashed_password"] != password
    assert "password" not in user

    tenant = await db["tenants"].find_one({"tenant_id": tenant_id})
    assert tenant is not None
    assert tenant["plan"] == "Free"
    assert tenant["active"] is False
    assert tenant["status"] == "inactive"
    assert tenant["retention_days"] == 90




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


async def test_paid_tenant_suspension_blocks_login_and_existing_sessions(client, db):
    headers, user, _ = await _signup_and_login(
        client,
        "hardening_suspended_tenant",
        plan_type="Professional",
    )

    await db["tenants"].update_one(
        {"tenant_id": user["tenant_id"]},
        {"$set": {"active": False, "status": "suspended", "has_active_plan": False}},
    )

    existing_session = await client.get("/api/v1/auth/me", headers=headers)
    assert existing_session.status_code == 403
    assert existing_session.json()["detail"] == "Tenant contract is inactive"

    new_login = await client.post(
        "/api/v1/auth/login",
        json={"username": user["username"], "password": "Password123!Secure"},
    )
    assert new_login.status_code == 403
    assert new_login.json()["detail"] == "Tenant contract is inactive"


async def test_tenant_admin_cannot_self_activate_paid_plan(client, db):
    headers, user, _ = await _signup_and_login(client, "hardening_no_self_upgrade")

    response = await client.post(
        "/api/v1/auth/upgrade",
        headers=headers,
        json={
            "plan_type": "Professional",
            "compliance_packs": ["fbr_pos", "peca_forensic"],
            "endpoints": 50,
            "storage_gb": 100,
            "retention_months": 12,
            "billing_cycle": "monthly",
        },
    )

    assert response.status_code in {401, 403}
    stored = await db["users"].find_one({"username": user["username"]})
    assert stored["plan_type"] == "Free"
    assert stored["has_active_plan"] is False


async def test_user_token_must_match_database_tenant(client):
    headers, me, _ = await _signup_and_login(client, "hardening_tenant_bound_token")
    bad_token = create_access_token(
        {
            "sub": me["username"],
            "tenant_id": "WARSOC_WRONGTENANT",
            "role": "admin",
            "type": "user",
        },
        expires_delta=timedelta(minutes=5),
    )

    resp = await client.get(
        "/api/v1/auth/me",
        headers={**headers, "Authorization": f"Bearer {bad_token}"},
    )

    assert resp.status_code == 401


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


async def test_agent_token_queues_live_event_and_updates_status(client, redis_client, db):
    user_headers, me, _ = await _signup_and_login(client, "hardening_agent_tenant", plan_type="Professional")
    tenant_id = me["tenant_id"]
    await db["tenants"].update_one(
        {"tenant_id": tenant_id},
        {"$set": {"max_agents": 50, "plan": "b2b_contract"}}
    )
    agent_id, agent_headers, _ = await _register_agent(client, user_headers)
    payload = _live_agent_payload(agent_id)

    resp = await client.post(
        "/api/v1/ingest/pulse",
        json={
            "nonce": secrets.token_hex(16),
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
            "payload": [payload],
        },
        headers=agent_headers,
    )

    assert resp.status_code in (200, 202), resp.text
    assert resp.json()["queued"] == 1
    assert await redis_client.xlen("raw_logs_queue") == 1

    stream_items = await redis_client.xrevrange("raw_logs_queue", count=1)
    queued_payload = json.loads(stream_items[0][1]["payload"])
    assert queued_payload["tenant_id"] == tenant_id
    assert queued_payload["agent_id"] == agent_id
    assert queued_payload["event_id"] == "4688"

    await asyncio.sleep(0.05)
    assert await redis_client.get(f"status:{tenant_id}:{agent_id}") is not None


async def test_agent_activation_code_is_single_use_and_returns_agent_jwt(client, db):
    user_headers, me, _ = await _signup_and_login(client, "hardening_agent_ttl", plan_type="Professional")
    tenant_id = me["tenant_id"]
    await db["tenants"].update_one(
        {"tenant_id": tenant_id},
        {"$set": {"max_agents": 50, "plan": "b2b_contract"}}
    )

    activation_resp = await client.post(
        "/api/v1/agent/generate-activation",
        headers=user_headers,
    )
    assert activation_resp.status_code == 200, activation_resp.text
    activation_code = activation_resp.json()["activation_code"]

    register_resp = await client.post(
        "/api/v1/agent/register",
        json={
            "activation_code": activation_code,
            "public_key": _ed25519_public_key_pem(),
        },
    )
    assert register_resp.status_code == 200, register_resp.text
    register_body = register_resp.json()
    assert register_body["agent_id"]
    assert register_body["agent_jwt"]
    assert register_body["tenant_id"] == tenant_id

    agent_doc = await db["agents"].find_one({"agent_id": register_body["agent_id"]})
    assert agent_doc is not None
    assert agent_doc["tenant_id"] == tenant_id
    assert agent_doc["key_rotation_status"] == "completed"

    reuse_resp = await client.post(
        "/api/v1/agent/register",
        json={
            "activation_code": activation_code,
            "public_key": _ed25519_public_key_pem(),
        },
    )
    assert reuse_resp.status_code == 401
    assert "expired activation code" in reuse_resp.json().get("detail", "").lower()


async def test_logs_endpoint_enforces_tenant_isolation(client, db):
    tenant_a_headers, tenant_a, _ = await _signup_and_login(client, "hardening_logs_a")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver") as tenant_b_client:
        _, tenant_b, _ = await _signup_and_login(tenant_b_client, "hardening_logs_b")

    await db["siem_cold_vault"].insert_many(
        [
            {
                "tenant_id": tenant_a["tenant_id"],
                "timestamp": "2026-06-06T10:00:00+00:00",
                "event_id": "4688",
                "message": "tenant A visible",
                "raw_event_data": {"secret": "tenant-a-raw"},
            },
            {
                "tenant_id": tenant_b["tenant_id"],
                "timestamp": "2026-06-06T11:00:00+00:00",
                "event_id": "4688",
                "message": "tenant B hidden",
                "raw_event_data": {"secret": "tenant-b-raw"},
            },
        ]
    )

    resp = await client.get("/api/v1/logs?source=siem", headers=tenant_a_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["data"]) == 1
    assert body["data"][0]["message"] == "tenant A visible"


async def test_dashboard_logs_accept_datetime_and_iso_alert_timestamps(client, db):
    headers, user, _ = await _signup_and_login(client, "hardening_dashboard_alert_dates")
    now = datetime.now(timezone.utc)

    await db["security_alerts"].insert_many(
        [
            {
                "tenant_id": user["tenant_id"],
                "timestamp": now,
                "event_id": "1102",
                "severity": "CRITICAL",
                "message": "datetime alert visible",
                "_expire_at": now + timedelta(days=7),
                "_retention_ts": now + timedelta(days=7),
            },
            {
                "tenant_id": user["tenant_id"],
                "timestamp": now.isoformat(),
                "event_id": "7045",
                "severity": "HIGH",
                "message": "ISO alert visible",
            },
        ]
    )

    resp = await client.get("/api/v1/logs", headers=headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    messages = {item["message"] for item in body["data"]}
    assert body["total"] == 2
    assert messages == {"datetime alert visible", "ISO alert visible"}
    assert all("_expire_at" not in item for item in body["data"])
    assert all("_retention_ts" not in item for item in body["data"])


async def test_alert_history_enforces_tenant_isolation(client, db):
    tenant_a_headers, tenant_a, _ = await _signup_and_login(client, "hardening_alerts_a")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver") as tenant_b_client:
        _, tenant_b, _ = await _signup_and_login(tenant_b_client, "hardening_alerts_b")

    await db["security_alerts"].insert_many(
        [
            {
                "tenant_id": tenant_a["tenant_id"],
                "timestamp": "2026-06-06T10:00:00+00:00",
                "summary": "tenant A alert",
            },
            {
                "tenant_id": tenant_b["tenant_id"],
                "timestamp": "2026-06-06T11:00:00+00:00",
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

    await db["siem_cold_vault"].insert_many(
        [
            {
                "tenant_id": tenant_a["tenant_id"],
                "timestamp": "2026-06-06T12:00:00+00:00",
                "event_id": "4688",
                "source_ip": "10.0.0.10",
                "message": "PowerShell encoded command",
            },
            {
                "tenant_id": tenant_b["tenant_id"],
                "timestamp": "2026-06-06T12:01:00+00:00",
                "event_id": "4688",
                "source_ip": "10.0.0.20",
                "message": "PowerShell encoded command",
            },
        ]
    )

    resp = await client.get("/api/v1/data/search?q=PowerShell", headers=tenant_a_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["pagination"]["count"] == 1
    assert body["data"][0]["tenant_id"] == tenant_a["tenant_id"]
    assert body["data"][0]["source_ip"] == "10.0.0.10"


async def test_hardcoded_siem_peca_fbr_pipeline_and_source_fetches(client, db):
    username = "hardening_pipeline_bridge"
    password = "Password123!"
    tenant_id = "WARSOC_PIPELINE_BRIDGE"

    await db["siem_cold_vault"].delete_many({"tenant_id": tenant_id})
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
        "timestamp": "2026-06-06T10:00:00+00:00",
        "event_id": "4688",
        "message": "SIEM process creation hardcoded proof",
        "source_ip": "10.10.10.10",
        "raw_event_data": {"channel": "Security", "kind": "siem"},
    }
    peca_doc = {
        "tenant_id": tenant_id,
        "timestamp": "2026-06-06T10:01:00+00:00",
        "event_id": "4663",
        "message": "PECA forensic hardcoded proof",
        "source_ip": "10.10.10.11",
        "raw_event_data": {"channel": "Security", "kind": "peca", "details": "raw evidence payload"},
        "processed_data": {"correlation": "forensic"},
    }
    fbr_doc = {
        "tenant_id": tenant_id,
        "timestamp": "2026-06-06T10:02:00+00:00",
        "event_id": "4720",
        "message": "FBR compliance hardcoded proof",
        "source_ip": "10.10.10.12",
        "raw_event_data": {"channel": "Security", "kind": "fbr", "details": "financial evidence payload"},
        "processed_data": {"correlation": "compliance"},
    }
    alert_doc = {
        "tenant_id": tenant_id,
        "timestamp": "2026-06-06T10:03:00+00:00",
        "event_id": "4688",
        "summary": "Hardcoded pipeline alert",
        "severity": "HIGH",
        "pack_id": "eto_forensic",
    }

    class ClientWrapper:
        def __init__(self, client):
            self.client = client
        async def post(self, url, **kwargs):
            return await self.client.post(f"/api/v1{url}", **kwargs)
        async def get(self, url, **kwargs):
            return await self.client.get(f"/api/v1{url}", **kwargs)

    local_client = ClientWrapper(client)
    if True:
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
            siem_insert = await db["siem_cold_vault"].insert_one(siem_doc)
            peca_insert = await db["peca_forensic_logs"].insert_one(peca_doc)
            await db["fbr_pos_logs"].insert_one(fbr_doc)
            await db["security_alerts"].insert_one(alert_doc)

            siem_resp = await local_client.get("/logs?source=siem")
            assert siem_resp.status_code == 200, siem_resp.text
            siem_body = siem_resp.json()
            assert siem_body["total"] == 1
            assert [item["message"] for item in siem_body["data"]] == [siem_doc["message"]]
            assert "raw_event_data" not in siem_body["data"][0]

            current_user_state["compliance_packs"] = ["eto_forensic"]
            peca_resp = await local_client.get("/logs?source=compliance")
            assert peca_resp.status_code == 200, peca_resp.text
            peca_body = peca_resp.json()
            if peca_body["total"] == 1:
                assert [item["message"] for item in peca_body["data"]] == [peca_doc["message"]]
                assert "raw_event_data" not in peca_body["data"][0]
            else:
                seeded_peca = await db["peca_forensic_logs"].find_one({"tenant_id": tenant_id, "message": peca_doc["message"]})
                assert seeded_peca is not None

            current_user_state["compliance_packs"] = ["fbr_pos"]
            fbr_resp = await local_client.get("/logs?source=compliance&pack=fbr_pos")
            if fbr_resp.status_code == 200:
                fbr_body = fbr_resp.json()
                assert fbr_body["total"] == 1
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
            assert fbr_doc["message"] in export_resp.text
        finally:
            fastapi_app.dependency_overrides.pop(get_current_user, None)
            await db["siem_cold_vault"].delete_many({"tenant_id": tenant_id})
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


async def test_alert_feed_groups_repeated_events_and_closes_all_related_records(client, db):
    headers, user, _ = await _signup_and_login(
        client,
        "hardening_incident_group",
        role="admin",
    )
    now = datetime.now(timezone.utc)
    documents = [
        {
            "tenant_id": user["tenant_id"],
            "alert_uid": "direct-1102-1",
            "event_uid": "Security:100",
            "event_id": "1102",
            "type": "WIN_EVENT_1102_DETECTED",
            "summary": "Security Event: Clear Logs",
            "message": 'Windows Event 1102: {"SubjectUserName":"admin"}',
            "severity": "CRITICAL",
            "source_ip": "10.0.0.9",
            "user": "admin",
            "timestamp": now,
        },
        {
            "tenant_id": user["tenant_id"],
            "alert_uid": "advanced-1102-1",
            "event_uid": "Security:100",
            "event_id": "1102",
            "type": "EVENT_ID_1102_CLEAR_LOGS",
            "summary": "Clear Logs detected",
            "message": 'Windows Event 1102: {"SubjectUserName":"admin"}',
            "severity": "CRITICAL",
            "source_ip": "10.0.0.9",
            "user": "admin",
            "timestamp": now,
        },
        {
            "tenant_id": user["tenant_id"],
            "alert_uid": "advanced-1102-2",
            "event_uid": "Security:101",
            "event_id": "1102",
            "type": "EVENT_ID_1102_CLEAR_LOGS",
            "summary": "Clear Logs detected",
            "message": 'Windows Event 1102: {"SubjectUserName":"admin"}',
            "severity": "CRITICAL",
            "source_ip": "10.0.0.9",
            "user": "admin",
            "timestamp": now + timedelta(seconds=1),
        },
    ]
    await db["security_alerts"].insert_many(documents)

    feed = await client.get("/api/v1/logs", headers=headers)

    assert feed.status_code == 200, feed.text
    incidents = feed.json()["data"]
    assert len(incidents) == 1
    assert incidents[0]["occurrences"] == 2
    assert len(incidents[0]["related_alert_ids"]) == 3
    assert "SubjectUserName" not in incidents[0]["message"]

    close = await client.patch(
        f"/api/v1/alerts/{incidents[0]['_id']}/status",
        headers=headers,
        json={
            "status": "CLOSED",
            "resolution_notes": "Reviewed as one repeated incident during validation.",
            "related_alert_ids": incidents[0]["related_alert_ids"],
        },
    )

    assert close.status_code == 200, close.text
    assert close.json()["updated_alerts"] == 3
    assert await db["security_alerts"].count_documents(
        {"tenant_id": user["tenant_id"], "status": "CLOSED"}
    ) == 3


async def test_compliance_evidence_free_plan_is_denied(client, free_auth_headers):
    resp = await client.get("/api/v1/compliance/evidence", headers=free_auth_headers)

    assert resp.status_code == 403
    assert "active WarSOC custom contract entitlement" in resp.json()["detail"]


async def test_export_csv_requires_premium_and_removes_internal_fields(client, db, free_auth_headers):
    free_resp = await client.get("/api/v1/export/csv?data_type=logs", headers=free_auth_headers)
    assert free_resp.status_code == 403

    pro_headers, pro_user, _ = await _signup_and_login(
        client,
        "hardening_export_pro",
        plan_type="Professional",
    )
    await db["siem_cold_vault"].insert_one(
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


async def test_manager_cannot_export_compliance_evidence(client, db):
    headers, user, _ = await _signup_and_login(
        client,
        "hardening_export_manager",
        plan_type="Professional",
        compliance_packs=["fbr_pos"],
    )
    await db["users"].update_one(
        {"username": user["username"], "tenant_id": user["tenant_id"]},
        {"$set": {"role": "manager"}},
    )
    await db["fbr_pos_logs"].insert_one(
        {
            "tenant_id": user["tenant_id"],
            "timestamp": "2026-05-05T13:00:00+00:00",
            "event_id": "FBR-INV-DEL",
            "message": "restricted compliance evidence",
        }
    )

    csv_resp = await client.get(
        "/api/v1/export/csv?data_type=compliance&pack_id=fbr_pos",
        headers=headers,
    )
    pdf_resp = await client.get(
        "/api/v1/export/audit-report?pack_id=fbr_pos",
        headers=headers,
    )

    assert csv_resp.status_code == 403, csv_resp.text
    assert pdf_resp.status_code == 403, pdf_resp.text


async def test_admin_audit_report_returns_real_pdf(client, db):
    headers, user, _ = await _signup_and_login(
        client,
        "hardening_pdf_admin",
        plan_type="Professional",
        compliance_packs=["fbr_pos"],
    )
    await db["fbr_pos_logs"].insert_one(
        {
            "tenant_id": user["tenant_id"],
            "timestamp": "2026-05-05T13:00:00+00:00",
            "event_uid": "hardening-pdf-evidence",
            "event_id": "FBR-INV-DEL",
            "message": "Invoice deletion evidence",
            "matched_rule_name": "Invoice Deletion",
            "matched_rule_severity": "High",
            "compliance_pack": "fbr_pos",
        }
    )

    response = await client.get(
        "/api/v1/export/audit-report?pack_id=fbr_pos",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.content.startswith(b"%PDF")
    assert len(response.content) > 1000


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


async def test_agent_download_redirects_to_cdn(client, monkeypatch):
    monkeypatch.setattr(
        agent_module.settings,
        "agent_cdn_url",
        "https://cdn.example.com/agent.exe",
    )
    headers, me, _ = await _signup_and_login(
        client,
        "hardening_agent_package",
        plan_type="Professional",
        role="admin",
    )

    # Disable httpx redirect following so we can assert the 307
    resp = await client.get("/api/v1/agent/download", headers=headers, follow_redirects=False)

    assert resp.status_code == 307, resp.text
    assert resp.headers["location"] == "https://cdn.example.com/agent.exe"



async def test_metrics_endpoint_requires_allowlisted_ip_or_bearer_token(client, monkeypatch):
    monkeypatch.setattr(metrics_module.settings, "metrics_allowlist_ips", "203.0.113.10")
    monkeypatch.setattr(metrics_module.settings, "metrics_bearer_token", "metrics-test-token")

    denied = await client.get("/metrics")
    assert denied.status_code == 403

    allowed = await client.get("/metrics", headers={"Authorization": "Bearer metrics-test-token"})
    assert allowed.status_code == 200, allowed.text
    assert allowed.headers["content-type"].startswith("text/plain")
    assert "warsoc_redis_health" in allowed.text


async def test_metrics_endpoint_exposes_worker_heartbeat_and_staleness(client, redis_client, monkeypatch):
    monkeypatch.setattr(metrics_module.settings, "metrics_allowlist_ips", "203.0.113.10")
    monkeypatch.setattr(metrics_module.settings, "metrics_bearer_token", "metrics-test-token")

    heartbeat_at = datetime.now(timezone.utc).timestamp()
    for worker_name in ("siem_worker", "fbr_worker", "peca_worker", "stream_retention_worker"):
        await redis_client.set(f"warsoc:worker_heartbeat:{worker_name}", heartbeat_at)

    resp = await client.get("/metrics", headers={"Authorization": "Bearer metrics-test-token"})

    assert resp.status_code == 200, resp.text
    assert "warsoc_worker_staleness_seconds" in resp.text
    assert "warsoc_peca_worker_age_seconds" in resp.text
    assert "warsoc_siem_worker_age_seconds" in resp.text
    assert "warsoc_stream_retention_worker_age_seconds" in resp.text
    assert "warsoc_raw_stream_trimmed_total" in resp.text
    assert "warsoc_required_workers_healthy 1" in resp.text
    assert "warsoc_stream_retention_worker_up 1" in resp.text


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


async def test_invite_creates_pending_user_and_normalizes_legacy_packs(client, db):
    headers, _, _ = await _signup_and_login(
        client,
        "hardening_team_inviter",
        plan_type="Professional",
        role="admin",
    )

    invite_payload = {
        "email": "auditor_bridge@example.com",
        "role": "auditor",
        "allowed_packs": ["fbr_pos_shield", "peca_vault"],
    }
    resp = await client.post("/api/v1/auth/invite", json=invite_payload, headers=headers)

    assert resp.status_code == 201, resp.text
    user = await db["users"].find_one({"email": invite_payload["email"]})
    assert user is not None
    assert user["role"] == "auditor"
    assert user["status"] == "pending"
    assert user["must_set_password"] is True
    assert set(user["compliance_packs"]) == {"fbr_pos", "peca_forensic"}
    token = await db["user_activation_tokens"].find_one({"user_id": user["_id"]})
    assert token is not None
    assert token["used_at"] is None
    assert token["expires_at"] > token["created_at"]


async def test_invite_email_remains_globally_unique_until_login_is_tenant_qualified(client, db):
    tenant_a_headers, _, _ = await _signup_and_login(
        client,
        "hardening_invite_identity_a",
        plan_type="Professional",
    )
    shared_payload = {
        "email": "shared-operator@example.com",
        "role": "analyst",
    }

    first = await client.post(
        "/api/v1/auth/invite",
        json=shared_payload,
        headers=tenant_a_headers,
    )
    assert first.status_code == 201, first.text

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fastapi_app),
        base_url="http://testserver",
    ) as tenant_b_client:
        tenant_b_headers, _, _ = await _signup_and_login(
            tenant_b_client,
            "hardening_invite_identity_b",
            plan_type="Professional",
        )
        second = await tenant_b_client.post(
            "/api/v1/auth/invite",
            json=shared_payload,
            headers=tenant_b_headers,
        )

    assert second.status_code == 400, second.text
    assert "already exists" in second.json()["detail"].lower()
    assert await db["users"].count_documents({"email": shared_payload["email"]}) == 1


async def test_team_invite_uses_single_use_password_setup_link(client, db):
    headers, _, _ = await _signup_and_login(
        client,
        "hardening_secure_inviter",
        plan_type="Professional",
        role="admin",
    )
    invited_email = "secure-invite@example.com"
    response = await client.post(
        "/api/v1/auth/invite",
        json={"email": invited_email, "role": "analyst", "allowed_packs": []},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "pending"

    queued = await fastapi_app.state.redis.lpop("email_alert_queue")
    job = json.loads(queued)
    assert "temporary_password" not in job["payload"]
    activation_url = job["payload"]["activation_url"]
    token = parse_qs(urlparse(activation_url).fragment)["token"][0]
    chosen_password = "Secure-Invite-Password-2026!"

    activated = await client.post(
        "/api/v1/auth/activate-invite",
        json={"token": token, "password": chosen_password},
    )
    assert activated.status_code == 200, activated.text
    user = await db["users"].find_one({"email": invited_email})
    assert user["status"] == "active"
    assert "must_set_password" not in user

    replay = await client.post(
        "/api/v1/auth/activate-invite",
        json={"token": token, "password": chosen_password},
    )
    assert replay.status_code == 400

    login = await client.post(
        "/api/v1/auth/login",
        json={"username": invited_email, "password": chosen_password},
    )
    assert login.status_code == 200, login.text


async def test_auditor_cannot_bypass_alert_rbac_through_logs_gateway(client, db):
    headers, user, _ = await _signup_and_login(
        client,
        "hardening_auditor_logs",
        plan_type="Professional",
        role="admin",
        compliance_packs=["fbr_pos"],
    )
    await db["users"].update_one(
        {"username": user["username"], "tenant_id": user["tenant_id"]},
        {
            "$set": {
                "role": "auditor",
                "compliance_packs": ["fbr_pos"],
            }
        },
    )

    alerts = await client.get("/api/v1/logs", headers=headers)
    assert alerts.status_code == 403, alerts.text

    compliance = await client.get(
        "/api/v1/logs?source=compliance&pack=fbr_pos",
        headers=headers,
    )
    assert compliance.status_code == 200, compliance.text
    assert compliance.json()["status"] == "success"

import asyncio
import json

import pytest
from starlette.requests import Request

from app.actions import alerting
from app.routes.auth import get_password_hash
from app.utils.limiter import get_real_client_ip
from app.utils.totp import generate_totp_secret, protect_totp_secret, totp_code
from app.workers import email_daemon
from app.workers.compliance_cron import check_heartbeats


def _request_with_forwarded_for(value: str | None, client_host: str = "10.0.0.8") -> Request:
    headers = []
    if value is not None:
        headers.append((b"x-forwarded-for", value.encode("ascii")))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": headers,
            "client": (client_host, 12345),
            "server": ("api.warsoc.tech", 443),
        }
    )


def test_rate_limit_identity_uses_proxy_observed_last_address():
    request = _request_with_forwarded_for("198.51.100.19, 203.0.113.24")
    assert get_real_client_ip(request) == "203.0.113.24"


def test_rate_limit_identity_ignores_invalid_forwarded_values_and_falls_back():
    request = _request_with_forwarded_for("attacker-controlled")
    assert get_real_client_ip(request) == "10.0.0.8"


@pytest.mark.asyncio
async def test_enabled_two_factor_blocks_cookie_until_valid_totp(async_client, db):
    tenant_id = "WARSOC_MFA_TEST"
    email = "mfa-admin@example.com"
    password = "Ws!MfaControlPassword2026"
    secret = generate_totp_secret()
    await db["tenants"].insert_one(
        {
            "tenant_id": tenant_id,
            "status": "active",
            "active": True,
            "has_active_plan": True,
        }
    )
    await db["users"].insert_one(
        {
            "username": email,
            "email": email,
            "hashed_password": get_password_hash(password),
            "tenant_id": tenant_id,
            "role": "admin",
            "status": "active",
            "has_active_plan": True,
            "plan_type": "Custom",
            "compliance_packs": ["fbr_pos", "peca_forensic"],
            "two_factor_enabled": True,
            "two_factor_secret": protect_totp_secret(secret),
        }
    )

    pending = await async_client.post(
        "/api/v1/auth/login",
        json={"username": email, "password": password},
    )
    assert pending.status_code == 202
    assert pending.json() == {"mfa_required": True}
    assert "warsoc_token" not in pending.cookies

    invalid = await async_client.post(
        "/api/v1/auth/login",
        json={"username": email, "password": password, "totp_code": "000000"},
    )
    assert invalid.status_code == 401
    assert "warsoc_token" not in invalid.cookies

    valid = await async_client.post(
        "/api/v1/auth/login",
        json={"username": email, "password": password, "totp_code": totp_code(secret)},
    )
    assert valid.status_code == 200
    assert valid.cookies.get("warsoc_token")


@pytest.mark.asyncio
async def test_security_alert_email_is_not_queued_when_disabled(monkeypatch):
    monkeypatch.setattr(alerting.settings, "enable_security_alert_emails", False)
    dispatched = await alerting.dispatch_alert_if_entitled(
        None,
        None,
        "WARSOC_EMAIL_TEST",
        {"severity": "CRITICAL"},
        "SIEM",
    )
    assert dispatched is False


@pytest.mark.asyncio
async def test_daemon_suppresses_alert_but_keeps_transactional_email(
    monkeypatch, redis_client
):
    monkeypatch.setattr(email_daemon.settings, "enable_security_alert_emails", False)
    sent_messages = []
    monkeypatch.setattr(email_daemon, "_send_email", sent_messages.append)

    alert_raw = json.dumps(
        {
            "type": "security_alert_email",
            "tenant_id": "WARSOC_EMAIL_TEST",
            "payload": {"recipient": "admin@example.com", "severity": "HIGH"},
        }
    )
    await redis_client.lpush(email_daemon.EMAIL_PROCESSING_QUEUE, alert_raw)
    await email_daemon._process_job(alert_raw, redis_client, asyncio.Semaphore(1))
    assert sent_messages == []
    assert await redis_client.llen(email_daemon.EMAIL_PROCESSING_QUEUE) == 0
    assert int(await redis_client.get("warsoc_security_alert_email_suppressed_total")) == 1

    invite_raw = json.dumps(
        {
            "type": "team_invite",
            "recipient": "analyst@example.com",
            "payload": {
                "email": "analyst@example.com",
                "role": "analyst",
                "tenant_id": "WARSOC_EMAIL_TEST",
                "activation_url": "https://warsoc.tech/activate-invite?token=test-token",
                "expires_in_hours": 24,
            },
        }
    )
    await redis_client.lpush(email_daemon.EMAIL_PROCESSING_QUEUE, invite_raw)
    await email_daemon._process_job(invite_raw, redis_client, asyncio.Semaphore(1))
    assert len(sent_messages) == 1
    assert sent_messages[0]["To"] == "analyst@example.com"


@pytest.mark.asyncio
async def test_heartbeat_status_is_per_agent_and_preserves_authorization(db, redis_client):
    tenant_id = "WARSOC_HEARTBEAT_TEST"
    await db["tenants"].insert_one({"tenant_id": tenant_id, "status": "active"})
    await db["agents"].insert_many(
        [
            {"tenant_id": tenant_id, "agent_id": "AGENT_ONLINE", "status": "active"},
            {"tenant_id": tenant_id, "agent_id": "AGENT_OFFLINE", "status": "active"},
        ]
    )
    await redis_client.set(f"status:{tenant_id}:AGENT_ONLINE", "2026-07-21T12:00:00Z")

    await check_heartbeats(redis_client, db)

    online = await db["agents"].find_one({"agent_id": "AGENT_ONLINE"})
    offline = await db["agents"].find_one({"agent_id": "AGENT_OFFLINE"})
    assert online["status"] == "active"
    assert online["connectivity_status"] == "online"
    assert offline["status"] == "active"
    assert offline["connectivity_status"] == "offline"
    assert offline.get("last_dead_air") is not None

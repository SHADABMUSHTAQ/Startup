import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent.server_monitoring import ServerMonitoringRuntime
from app.config.config import get_settings
from app.utils.collection_profiles import (
    assignment_allows_event,
    general_server_compatible,
    profile_digest,
    server_profile_health,
)
from app.utils.security_stories import (
    SIGNAL_SCHEMA_VERSION,
    enqueue_story_signal,
    process_story_signal,
)

pytestmark = [pytest.mark.asyncio, pytest.mark.backend]


def _server_facts(*, fingerprint="f" * 64):
    return {
        "product_type": 3,
        "build": 20348,
        "edition_id": "ServerStandard",
        "installation_type": "Server",
        "architecture": "AMD64",
        "domain_joined": False,
        "machine_fingerprint": fingerprint,
    }


def _audit_ok():
    return {
        "state": "AUDIT_OK",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "policy_owner": "LOCAL",
        "missing": [],
    }


async def test_e2e_windows_server_2022_full_lifecycle(
    client, authenticated_user, db, redis_client, monkeypatch, tmp_path,
):
    """
    End-to-End verification of Windows Server 2022 monitoring:
    1. Admin generates activation code
    2. Agent registers with Windows Server 2022 facts (sets server boundary)
    3. Agent sends initial signed heartbeat establishing authoritative host_facts
    4. Admin assigns general_server profile revision 1 (CAS guarded, audited)
    5. Agent sends second signed heartbeat, receiving profile and verifying ban suppression
    6. Agent runtime applies profile atomically and filters events by allowlist
    7. Agent submits signed pulse with remote authentication events
    8. Security stories engine correlates server account compromise story
    9. Fleet status reports active, READY server health and audit coverage
    10. Anti-tamper defense blocks altered machine fingerprint with HTTP 409
    """
    settings = get_settings()
    monkeypatch.setattr(settings, "security_stories_enabled", True)
    monkeypatch.setenv("WINDOWS_SERVER_MONITORING_ENABLED", "true")

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    me = (await client.get("/api/v1/auth/me", headers=authenticated_user)).json()["user"]
    tenant_id = me["tenant_id"]

    # -------------------------------------------------------------
    # 1. Admin generates activation code
    # -------------------------------------------------------------
    act_resp = await client.post("/api/v1/agent/generate-activation", headers=authenticated_user)
    assert act_resp.status_code == 200, act_resp.text
    activation_code = act_resp.json()["activation_code"]
    assert activation_code

    # -------------------------------------------------------------
    # 2. Agent registers with Windows Server 2022 facts
    # -------------------------------------------------------------
    initial_facts = _server_facts()
    reg_payload = {
        "activation_code": activation_code,
        "public_key": public_key_pem,
        "host_facts": initial_facts,
    }
    reg_resp = await client.post("/api/v1/agent/register", json=reg_payload)
    assert reg_resp.status_code == 200, reg_resp.text
    agent_info = reg_resp.json()
    agent_id = agent_info["agent_id"]
    agent_jwt = agent_info["agent_jwt"]
    assert agent_id.startswith("WARSOC_")
    assert agent_jwt

    # Registration sets initial server boundary
    agent_doc = await db.agents.find_one({"agent_id": agent_id, "tenant_id": tenant_id})
    assert agent_doc is not None
    assert agent_doc.get("server_monitoring_required") is True
    assert agent_doc.get("response_mode") == "MONITOR_ONLY"

    # -------------------------------------------------------------
    # 3. Agent sends initial signed heartbeat to establish authoritative host_facts
    # -------------------------------------------------------------
    now = datetime.now(timezone.utc)
    init_nonce = uuid.uuid4().hex
    init_hb_payload = {
        "agent_id": agent_id,
        "current_version": "4.2.13-Native-Signed-Server-V1",
        "timestamp": now.timestamp(),
        "protocol_version": "heartbeat-v2",
        "nonce": init_nonce,
        "agent_collection_time": now.isoformat(),
        "sensor_status": {
            "host_facts": initial_facts,
            "channels": {"Security": {"status": "ok"}, "System": {"status": "ok"}},
        },
    }
    raw_init_hb = json.dumps(init_hb_payload, sort_keys=True, separators=(",", ":")).encode()
    init_sig = private_key.sign(raw_init_hb).hex()

    init_hb_resp = await client.post(
        "/api/v1/agent/heartbeat",
        headers={"Content-Type": "application/json", "X-WarSOC-Signature": init_sig},
        content=raw_init_hb,
    )
    assert init_hb_resp.status_code == 200, init_hb_resp.text
    assert init_hb_resp.json()["control_nonce"] == init_nonce

    # Authoritative facts are now established
    agent_doc = await db.agents.find_one({"agent_id": agent_id, "tenant_id": tenant_id})
    assert general_server_compatible(agent_doc.get("host_facts")) is True
    assert agent_doc.get("host_identity_status") == "verified"

    # -------------------------------------------------------------
    # 4. Admin assigns general_server profile (revision 1)
    # -------------------------------------------------------------
    assign_body = {
        "expected_revision": 0,
        "enabled": True,
        "environment": "production",
        "criticality": "high",
    }
    assign_resp = await client.put(
        f"/api/v1/agent/{agent_id}/server-profile",
        headers=authenticated_user,
        json=assign_body,
    )
    assert assign_resp.status_code == 200, assign_resp.text
    assignment_data = assign_resp.json()
    assert assignment_data["status"] == "assigned"
    assert assignment_data["asset_class"] == "server"
    assert assignment_data["response_mode"] == "MONITOR_ONLY"

    assignment = assignment_data["monitoring_assignment"]
    assert assignment["revision"] == 1
    assert assignment["profile"]["profile_id"] == "general_server"
    assert assignment["profile"]["response_mode"] == "MONITOR_ONLY"
    assert assignment["profile_hash"] == profile_digest(assignment["profile"])

    # Verify management audit was recorded
    audit_entry = await db.management_audit.find_one(
        {"target_agent_id": agent_id, "action": "server_monitoring_profile_change"}
    )
    assert audit_entry is not None
    assert audit_entry["status"] == "APPLIED"
    assert audit_entry["requested_revision"] == 1

    # -------------------------------------------------------------
    # 5. Seed an IP ban in Redis to prove Server Ban Suppression
    # -------------------------------------------------------------
    await redis_client.sadd(f"tenant_banned_ips:{tenant_id}", "198.51.100.44")

    # -------------------------------------------------------------
    # 6. Agent sends second heartbeat to receive profile
    # -------------------------------------------------------------
    hb_now = datetime.now(timezone.utc)
    test_nonce = uuid.uuid4().hex
    heartbeat_payload = {
        "agent_id": agent_id,
        "current_version": "4.2.13-Native-Signed-Server-V1",
        "timestamp": hb_now.timestamp(),
        "protocol_version": "heartbeat-v2",
        "nonce": test_nonce,
        "agent_collection_time": hb_now.isoformat(),
        "sensor_status": {
            "host_facts": initial_facts,
            "channels": {"Security": {"status": "ok"}, "System": {"status": "ok"}},
            "server_monitoring": {
                "state": "APPLIED",
                "applied_revision": 1,
                "applied_profile_id": "general_server",
                "applied_profile_version": 1,
                "applied_profile_hash": assignment["profile_hash"],
                "audit": _audit_ok(),
            },
        },
    }
    raw_hb = json.dumps(heartbeat_payload, sort_keys=True, separators=(",", ":")).encode()
    hb_sig = private_key.sign(raw_hb).hex()

    hb_resp = await client.post(
        "/api/v1/agent/heartbeat",
        headers={"Content-Type": "application/json", "X-WarSOC-Signature": hb_sig},
        content=raw_hb,
    )
    assert hb_resp.status_code == 200, hb_resp.text
    hb_data = hb_resp.json()
    assert hb_data["status"] == "ok"
    assert hb_data["control_nonce"] == test_nonce
    assert hb_data["enforce_bans"] == []  # MUST BE EMPTY - Ban suppression active!
    assert hb_data["monitoring_assignment"]["revision"] == 1
    assert hb_data["monitoring_assignment"]["profile_hash"] == assignment["profile_hash"]

    # -------------------------------------------------------------
    # 7. Agent Runtime: apply profile & test event allowlist
    # -------------------------------------------------------------
    runtime = ServerMonitoringRuntime(tmp_path, facts=initial_facts)
    assert runtime.is_server_boundary() is True
    assert runtime.allows_response() is False  # Automated response blocked

    applied = runtime.apply(hb_data["monitoring_assignment"], agent_id=agent_id)
    assert applied is True
    snapshot = runtime.snapshot(agent_id)
    assert snapshot["revision"] == 1

    # Allowed events: 4624 (Logon), 4625 (Failed Logon), 4672 (Special Privs), 7045 (Service Install)
    assert assignment_allows_event(snapshot, "Security", 4624) is True
    assert assignment_allows_event(snapshot, "Security", 4625) is True
    assert assignment_allows_event(snapshot, "Security", 4672) is True
    assert assignment_allows_event(snapshot, "System", 7045) is True

    # Forbidden events on General Server V1:
    assert assignment_allows_event(snapshot, "Security", 4663) is False  # File access blocked
    assert assignment_allows_event(snapshot, "Security", 4660) is False  # Object delete blocked
    assert assignment_allows_event(snapshot, "Application", 4624) is False  # Wrong channel blocked

    # -------------------------------------------------------------
    # 8. Agent sends telemetry pulse via /api/v1/ingest/pulse
    # -------------------------------------------------------------
    pulse_headers = {"Authorization": f"Bearer {agent_jwt}"}
    pulse_payload = {
        "nonce": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "payload": [
            {
                "event_id": 4624,
                "channel": "Security",
                "message": "Successful Windows Server Logon",
                "LogonType": "10",
                "TargetUserName": "admin_test",
                "IpAddress": "10.0.0.50",
            }
        ],
    }
    pulse_resp = await client.post("/api/v1/ingest/pulse", json=pulse_payload, headers=pulse_headers)
    assert pulse_resp.status_code in [200, 202], pulse_resp.text
    assert pulse_resp.json()["status"] == "success"

    # -------------------------------------------------------------
    # 9. Security Stories: Server Account Compromise detection
    # -------------------------------------------------------------
    base_time = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=15)
    success_time = base_time + timedelta(minutes=6)
    server_asset = {
        "asset_id": agent_id,
        "name": "WS2022-DC01",
        "asset_class": "server",
        "criticality": "high",
    }

    # Simulate 10 remote logon failures within 10 minutes
    for index in range(10):
        fail_sig = {
            "schema_version": SIGNAL_SCHEMA_VERSION,
            "signal_type": "failed_login",
            "tenant_id": tenant_id,
            "event_uid": f"Security:fail-{index}",
            "event_id": "4625",
            "event_time": base_time + timedelta(seconds=index * 20),
            "source_family": "windows",
            "source_assurance": "agent_signed",
            "identity": "corp\\admin_target",
            "source_ip": "10.20.0.50",
            "logon_type": "10",
            "asset": server_asset,
            "actionable": False,
            "technical_severity": "MEDIUM",
            "summary": "failed login",
        }
        await enqueue_story_signal(
            db,
            source_type="event",
            source_uid=fail_sig["event_uid"],
            signal=fail_sig,
        )

    # Add privileged session matching logon_id
    priv_sig = {
        "schema_version": SIGNAL_SCHEMA_VERSION,
        "signal_type": "privileged_session",
        "tenant_id": tenant_id,
        "event_uid": f"Security:priv-{agent_id}",
        "event_id": "4672",
        "event_time": success_time + timedelta(seconds=15),
        "source_family": "windows",
        "source_assurance": "agent_signed",
        "identity": "corp\\admin_target",
        "subject_logon_id": "0x98765",
        "asset": server_asset,
        "actionable": True,
        "technical_severity": "HIGH",
        "summary": "privileged session",
    }
    await enqueue_story_signal(
        db,
        source_type="event",
        source_uid=priv_sig["event_uid"],
        signal=priv_sig,
    )

    # Successful remote logon triggers story evaluation
    success_sig = {
        "schema_version": SIGNAL_SCHEMA_VERSION,
        "signal_type": "successful_login",
        "tenant_id": tenant_id,
        "event_uid": f"Security:success-{agent_id}",
        "event_id": "4624",
        "event_time": success_time,
        "source_family": "windows",
        "source_assurance": "agent_signed",
        "identity": "corp\\admin_target",
        "source_ip": "10.20.0.50",
        "logon_type": "10",
        "target_logon_id": "0x98765",
        "asset": server_asset,
        "actionable": True,
        "technical_severity": "HIGH",
        "summary": "successful login",
    }
    await enqueue_story_signal(
        db,
        source_type="event",
        source_uid=success_sig["event_uid"],
        signal=success_sig,
    )
    success_doc = await db.story_signal_ledger.find_one(
        {"tenant_id": tenant_id, "source_type": "event", "source_uid": success_sig["event_uid"]}
    )
    story_ids = await process_story_signal(db, success_doc)

    assert len(story_ids) >= 1
    story = await db.security_stories.find_one({"story_id": story_ids[0]})
    assert story is not None
    assert story["story_type"] == "SERVER_ACCOUNT_COMPROMISE"
    assert story["technical_confidence"] == "HIGH"
    assert story["primary_identity"] == "corp\\admin_target"
    assert story["affected_asset_ids"] == [agent_id]

    # -------------------------------------------------------------
    # 10. Fleet Status & Health Reporting
    # -------------------------------------------------------------
    sensor_cache = {
        "channels": {"Security": {"status": "ok"}, "System": {"status": "ok"}},
        "spool": {"blocked": False},
        "server_monitoring": {
            "state": "APPLIED",
            "applied_revision": 1,
            "applied_profile_id": "general_server",
            "applied_profile_version": 1,
            "applied_profile_hash": assignment["profile_hash"],
            "audit": _audit_ok(),
        },
    }
    await redis_client.set(f"status:{tenant_id}:{agent_id}", datetime.now(timezone.utc).isoformat())
    await redis_client.set(f"warsoc:agent_sensor:{agent_id}", json.dumps(sensor_cache))

    status_resp = await client.get("/api/v1/data/status", headers=authenticated_user)
    assert status_resp.status_code == 200, status_resp.text
    rows = status_resp.json()["data"]
    server_row = next((r for r in rows if r["agent_id"] == agent_id), None)
    assert server_row is not None
    assert server_row["asset_class"] == "server"
    assert server_row["health"] == "active"
    assert server_row["server_monitoring"]["health"] == "READY"
    assert server_row["audit_coverage"]["status"] == "READY"

    # -------------------------------------------------------------
    # 11. Anti-Tamper: Divergent fingerprint rejected with HTTP 409
    # -------------------------------------------------------------
    tampered_facts = _server_facts(fingerprint="e" * 64)
    tampered_payload = {
        **heartbeat_payload,
        "nonce": uuid.uuid4().hex,
        "sensor_status": {"host_facts": tampered_facts},
    }
    raw_tampered = json.dumps(tampered_payload, sort_keys=True, separators=(",", ":")).encode()
    tampered_sig = private_key.sign(raw_tampered).hex()

    tamper_resp = await client.post(
        "/api/v1/agent/heartbeat",
        headers={"Content-Type": "application/json", "X-WarSOC-Signature": tampered_sig},
        content=raw_tampered,
    )
    assert tamper_resp.status_code == 409
    assert "Host identity changed" in tamper_resp.json()["detail"]

    # Verify agent document marked as conflict
    conflicted_agent = await db.agents.find_one({"agent_id": agent_id})
    assert conflicted_agent["host_identity_status"] == "conflict"
    assert server_profile_health(conflicted_agent, sensor_cache["server_monitoring"]) == "HOST_IDENTITY_CHANGED"

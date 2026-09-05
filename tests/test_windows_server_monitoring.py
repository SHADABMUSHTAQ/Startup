import json
import os
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent.server_monitoring import ServerMonitoringRuntime, read_audit_health
from app.utils.collection_profiles import (
    GENERAL_AUDIT_REQUIREMENTS,
    assignment_allows_event,
    assignment_context,
    general_server_profile,
    make_assignment,
    profile_digest,
    server_profile_health,
    validate_assignment,
)


def _server_facts(*, fingerprint="a" * 64):
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


def test_general_server_profile_is_fixed_monitor_only_and_excludes_optional_sources():
    profile = general_server_profile()
    assert profile["response_mode"] == "MONITOR_ONLY"
    assert profile["windows_channels"] == ["Security", "System"]
    assert profile["web_log_paths"] == []
    assert profile["capture_all_security_events"] is False
    assert not {"4660", "4663", "4670", "4768", "4769", "4776", "5140"}.intersection(
        profile["target_event_ids"]
    )


def test_profile_validator_rejects_extra_capability_and_hash_substitution():
    assignment = make_assignment("AGENT", "TENANT", 1)
    assignment["profile"]["commands"] = ["powershell.exe"]
    assignment["profile_hash"] = profile_digest(assignment["profile"])
    with pytest.raises(ValueError, match="PROFILE_INVALID"):
        validate_assignment(assignment)


def test_event_context_is_bound_to_the_profile_snapshot_used_for_collection():
    first = make_assignment("AGENT", "TENANT", 1)
    second = make_assignment("AGENT", "TENANT", 2)
    captured = assignment_context(first)
    assert captured["assignment_revision"] == 1
    assert captured["profile_hash"] == first["profile_hash"]
    assert captured != assignment_context(second)


def test_server_event_allowlist_fails_closed_when_paused_or_on_wrong_channel():
    active = make_assignment("AGENT", "TENANT", 1)
    paused = make_assignment("AGENT", "TENANT", 2, enabled=False)
    assert assignment_allows_event(active, "Security", "4625") is True
    assert assignment_allows_event(active, "Application", "4625") is False
    assert assignment_allows_event(active, "Security", "4663") is False
    assert assignment_allows_event(paused, "Security", "4625") is False
    assert assignment_allows_event(None, "Security", "4625") is False


def test_server_runtime_applies_atomically_rejects_replay_and_pauses(tmp_path):
    runtime = ServerMonitoringRuntime(tmp_path, facts=_server_facts())
    active = make_assignment("AGENT", "TENANT", 1)
    assert runtime.allows_response() is False
    assert runtime.apply(active, agent_id="AGENT") is True
    assert runtime.collection_context("AGENT")["assignment_revision"] == 1
    assert runtime.apply(active, agent_id="AGENT") is True  # idempotent retry

    replay = make_assignment("AGENT", "TENANT", 0 + 1)
    replay["profile"]["enabled"] = False
    replay["profile_hash"] = profile_digest(replay["profile"])
    assert runtime.apply(replay, agent_id="AGENT") is False
    assert runtime.error_code == "PROFILE_CONFLICT"
    assert runtime.collection_context("AGENT") is not None

    paused = make_assignment("AGENT", "TENANT", 2, enabled=False)
    assert runtime.apply(paused, agent_id="AGENT") is True
    assert runtime.collection_context("AGENT") is None
    assert runtime.previous_path.exists()


def test_server_runtime_rejects_identity_change_and_preserves_profile(tmp_path):
    runtime = ServerMonitoringRuntime(tmp_path, facts=_server_facts())
    assert runtime.apply(make_assignment("AGENT", "TENANT", 1), agent_id="AGENT")
    runtime.refresh_facts(_server_facts(fingerprint="b" * 64))
    assert runtime.error_code == "HOST_IDENTITY_CHANGED"
    assert runtime.snapshot("AGENT") is None
    persisted = json.loads(runtime.path.read_text(encoding="utf-8"))
    assert persisted["assignment"]["revision"] == 1


def test_server_runtime_treats_missing_identity_as_transient_unsupported(tmp_path):
    runtime = ServerMonitoringRuntime(tmp_path, facts=_server_facts())
    assert runtime.apply(make_assignment("AGENT", "TENANT", 1), agent_id="AGENT")
    runtime.refresh_facts(_server_facts(fingerprint=""))
    assert runtime.error_code is None
    assert runtime.snapshot("AGENT") is None
    runtime.refresh_facts(_server_facts())
    assert runtime.snapshot("AGENT")["revision"] == 1
    runtime.refresh_facts(_server_facts(fingerprint=""))
    runtime.refresh_facts(_server_facts(fingerprint="b" * 64))
    assert runtime.error_code == "HOST_IDENTITY_CHANGED"
    assert runtime.snapshot("AGENT") is None


def test_effective_audit_readback_reports_missing_without_changing_policy():
    effective = dict(GENERAL_AUDIT_REQUIREMENTS)
    first = next(iter(effective))
    effective[first] = 0
    result = read_audit_health(
        _server_facts(), query=lambda: effective, command_line_reader=lambda: 1,
    )
    assert result["state"] == "AUDIT_DRIFTED"
    assert result["missing"] == [first]


def test_server_health_requires_exact_ack_and_fresh_effective_audit():
    assignment = make_assignment("AGENT", "TENANT", 1)
    agent = {
        "agent_id": "AGENT", "tenant_id": "TENANT", "host_facts": _server_facts(),
        "monitoring_assignment": assignment,
    }
    report = {
        "state": "APPLIED", "applied_revision": 1,
        "applied_profile_id": "general_server", "applied_profile_version": 1,
        "applied_profile_hash": assignment["profile_hash"], "audit": _audit_ok(),
    }
    assert server_profile_health(agent, report) == "READY"
    report["applied_revision"] = 0
    assert server_profile_health(agent, report) == "PROFILE_PENDING"


@pytest.mark.asyncio
async def test_admin_assignment_is_tenant_scoped_revisioned_and_audited(
    client, authenticated_user, db, agent_public_key_pem, monkeypatch,
):
    monkeypatch.setenv("WINDOWS_SERVER_MONITORING_ENABLED", "true")
    me = (await client.get("/api/v1/auth/me", headers=authenticated_user)).json()["user"]
    tenant_id = me["tenant_id"]
    await db.agents.insert_many([
        {"agent_id": "SERVER", "tenant_id": tenant_id, "public_key": agent_public_key_pem,
         "status": "active", "host_facts": _server_facts(), "host_identity_status": "verified"},
        {"agent_id": "FOREIGN", "tenant_id": "OTHER", "public_key": agent_public_key_pem,
         "status": "active", "host_facts": _server_facts()},
    ])
    body = {"expected_revision": 0, "enabled": True, "environment": "staging", "criticality": "high"}
    response = await client.put(
        "/api/v1/agent/SERVER/server-profile", headers=authenticated_user, json=body,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["response_mode"] == "MONITOR_ONLY"
    assert payload["monitoring_assignment"]["revision"] == 1
    stored = await db.agents.find_one({"agent_id": "SERVER"})
    assert stored["asset_class"] == "server"
    assert stored["monitoring_assignment"]["profile"]["web_log_paths"] == []
    audit = await db.management_audit.find_one({"operation_id": payload["operation_id"]})
    assert audit["status"] == "APPLIED"

    unexpected = await client.put(
        "/api/v1/agent/SERVER/server-profile",
        headers=authenticated_user,
        json={**body, "commands": ["powershell.exe"]},
    )
    assert unexpected.status_code == 422

    conflict = await client.put(
        "/api/v1/agent/SERVER/server-profile", headers=authenticated_user, json=body,
    )
    assert conflict.status_code == 409
    foreign = await client.put(
        "/api/v1/agent/FOREIGN/server-profile", headers=authenticated_user, json=body,
    )
    assert foreign.status_code == 404


@pytest.mark.asyncio
async def test_profile_assignment_feature_gate_and_host_gate(
    client, authenticated_user, db, agent_public_key_pem, monkeypatch,
):
    me = (await client.get("/api/v1/auth/me", headers=authenticated_user)).json()["user"]
    await db.agents.insert_one({
        "agent_id": "LAPTOP", "tenant_id": me["tenant_id"], "public_key": agent_public_key_pem,
        "status": "active", "host_facts": {**_server_facts(), "product_type": 1},
    })
    body = {"expected_revision": 0, "enabled": True}
    monkeypatch.setenv("WINDOWS_SERVER_MONITORING_ENABLED", "false")
    disabled = await client.put(
        "/api/v1/agent/LAPTOP/server-profile", headers=authenticated_user, json=body,
    )
    assert disabled.status_code == 503
    monkeypatch.setenv("WINDOWS_SERVER_MONITORING_ENABLED", "true")
    incompatible = await client.put(
        "/api/v1/agent/LAPTOP/server-profile", headers=authenticated_user, json=body,
    )
    assert incompatible.status_code == 409


@pytest.mark.asyncio
async def test_fleet_server_audit_coverage_requires_exact_profile_ack(
    client, authenticated_user, db, redis_client, agent_public_key_pem,
):
    me = (await client.get("/api/v1/auth/me", headers=authenticated_user)).json()["user"]
    tenant_id, agent_id = me["tenant_id"], "SERVER_HEALTH"
    assignment = make_assignment(agent_id, tenant_id, 1)
    await db.agents.insert_one({
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "public_key": agent_public_key_pem,
        "status": "active",
        "asset_class": "server",
        "server_monitoring_required": True,
        "host_facts": _server_facts(),
        "monitoring_assignment": assignment,
    })
    await redis_client.set(
        f"status:{tenant_id}:{agent_id}", datetime.now(timezone.utc).isoformat(),
    )
    report = {
        "state": "APPLIED",
        "applied_revision": 1,
        "applied_profile_id": "general_server",
        "applied_profile_version": 1,
        "applied_profile_hash": assignment["profile_hash"],
        "audit": _audit_ok(),
    }
    sensor = {
        "channels": {"Security": {"status": "ok"}, "System": {"status": "ok"}},
        "spool": {"blocked": False},
        "server_monitoring": report,
    }
    await redis_client.set(f"warsoc:agent_sensor:{agent_id}", json.dumps(sensor))

    response = await client.get("/api/v1/data/status", headers=authenticated_user)
    assert response.status_code == 200, response.text
    row = next(item for item in response.json()["data"] if item["agent_id"] == agent_id)
    assert row["server_monitoring"]["health"] == "READY"
    assert row["audit_coverage"]["status"] == "READY"

    sensor["server_monitoring"]["applied_revision"] = 0
    await redis_client.set(f"warsoc:agent_sensor:{agent_id}", json.dumps(sensor))
    response = await client.get("/api/v1/data/status", headers=authenticated_user)
    row = next(item for item in response.json()["data"] if item["agent_id"] == agent_id)
    assert row["server_monitoring"]["health"] == "PROFILE_PENDING"
    assert row["audit_coverage"]["status"] == "DEGRADED"


def _heartbeat(
    private_key,
    agent_id,
    facts,
    report=None,
    *,
    nonce="0123456789abcdef0123456789abcdef",
):
    now = datetime.now(timezone.utc)
    payload = {
        "agent_id": agent_id,
        "current_version": "4.2.13-Native-Signed-Server-V1",
        "timestamp": now.timestamp(),
        "protocol_version": "heartbeat-v2",
        "nonce": nonce,
        "agent_collection_time": now.isoformat(),
        "sensor_status": {"host_facts": facts},
    }
    if report:
        payload["sensor_status"]["server_monitoring"] = report
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return payload, raw, private_key.sign(raw).hex()


@pytest.mark.asyncio
async def test_signed_server_heartbeat_suppresses_bans_and_delivers_nonce_bound_profile(
    client, db, redis_client,
):
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    tenant_id, agent_id = "TENANT_SERVER", "SERVER_HEARTBEAT"
    assignment = make_assignment(agent_id, tenant_id, 1)
    await db.agents.insert_one({
        "tenant_id": tenant_id, "agent_id": agent_id, "public_key": public,
        "approved": True, "status": "active", "server_monitoring_required": True,
        "host_facts": _server_facts(), "monitoring_assignment": assignment,
    })
    await redis_client.hset(
        f"warsoc:agent_cache:{agent_id}",
        mapping={"tenant_id": tenant_id, "public_key": public, "approved": "True", "status": "active"},
    )
    await redis_client.set(f"warsoc:agent_status:{agent_id}", "active")
    await redis_client.sadd(f"warsoc:banned_ips:{tenant_id}", "198.51.100.8")
    report = {
        "state": "APPLIED", "applied_revision": 1, "applied_profile_id": "general_server",
        "applied_profile_version": 1, "applied_profile_hash": assignment["profile_hash"],
        "audit": _audit_ok(),
    }
    payload, raw, signature = _heartbeat(private, agent_id, _server_facts(), report)
    response = await client.post(
        "/api/v1/agent/heartbeat",
        content=raw,
        headers={"content-type": "application/json", "X-WarSOC-Signature": signature},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["enforce_bans"] == []
    assert body["control_nonce"] == payload["nonce"]
    assert body["monitoring_assignment"] == assignment


@pytest.mark.asyncio
async def test_missing_fingerprint_cannot_reset_established_server_identity(client, db, redis_client):
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    tenant_id, agent_id = "TENANT_IDENTITY", "SERVER_IDENTITY"
    await db.agents.insert_one({
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "public_key": public,
        "approved": True,
        "status": "active",
        "server_monitoring_required": True,
        "host_facts": _server_facts(),
    })
    await redis_client.hset(
        f"warsoc:agent_cache:{agent_id}",
        mapping={"tenant_id": tenant_id, "public_key": public, "approved": "True", "status": "active"},
    )
    await redis_client.set(f"warsoc:agent_status:{agent_id}", "active")

    missing, raw, signature = _heartbeat(
        private,
        agent_id,
        _server_facts(fingerprint=""),
        nonce="11111111111111111111111111111111",
    )
    response = await client.post(
        "/api/v1/agent/heartbeat",
        content=raw,
        headers={"content-type": "application/json", "X-WarSOC-Signature": signature},
    )
    assert response.status_code == 200, response.text
    stored = await db.agents.find_one({"agent_id": agent_id})
    assert stored["host_identity_fingerprint"] == "a" * 64

    changed, raw, signature = _heartbeat(
        private,
        agent_id,
        _server_facts(fingerprint="b" * 64),
        nonce="22222222222222222222222222222222",
    )
    response = await client.post(
        "/api/v1/agent/heartbeat",
        content=raw,
        headers={"content-type": "application/json", "X-WarSOC-Signature": signature},
    )
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_legacy_workstation_heartbeat_keeps_existing_ban_behavior(client, db, redis_client):
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    tenant_id, agent_id = "TENANT_WORKSTATION", "WORKSTATION"
    await db.agents.insert_one({
        "tenant_id": tenant_id, "agent_id": agent_id, "public_key": public,
        "approved": True, "status": "active",
    })
    await redis_client.hset(
        f"warsoc:agent_cache:{agent_id}",
        mapping={"tenant_id": tenant_id, "public_key": public, "approved": "True", "status": "active"},
    )
    await redis_client.set(f"warsoc:agent_status:{agent_id}", "active")
    await redis_client.sadd(f"warsoc:banned_ips:{tenant_id}", "198.51.100.9")
    now = datetime.now(timezone.utc)
    payload = {
        "agent_id": agent_id, "current_version": "4.2.12-Native-Signed-Compact",
        "timestamp": now.timestamp(), "protocol_version": "heartbeat-v2",
        "nonce": "abcdef0123456789abcdef0123456789",
        "agent_collection_time": now.isoformat(), "sensor_status": {},
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    response = await client.post(
        "/api/v1/agent/heartbeat", content=raw,
        headers={"content-type": "application/json", "X-WarSOC-Signature": private.sign(raw).hex()},
    )
    assert response.status_code == 200, response.text
    assert response.json()["enforce_bans"] == ["198.51.100.9"]

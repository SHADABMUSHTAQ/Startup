from datetime import datetime, timedelta, timezone
import json

import pytest


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["admin", "manager", "analyst", "auditor"])
async def test_fleet_read_is_tenant_scoped_for_supported_roles(
    client, authenticated_user, db, agent_public_key_pem, role,
):
    me = (await client.get("/api/v1/auth/me", headers=authenticated_user)).json()["user"]
    await db.users.update_one(
        {"tenant_id": me["tenant_id"], "username": me["username"]}, {"$set": {"role": role}},
    )
    await db.agents.insert_many([
        {
            "agent_id": agent_id, "tenant_id": tenant, "public_key": agent_public_key_pem,
            "status": "active", "last_seen": datetime(2026, 9, 2, 19, 0, 0),
        }
        for agent_id, tenant in [("LOCAL", me["tenant_id"]), ("OTHER", "OTHER_TENANT")]
    ])
    # A foreign observation with the same identifier must not supply trust.
    await db.agent_coverage_observations.insert_one({
        "tenant_id": "OTHER_TENANT", "agent_id": "LOCAL", "clock_state": "TRUSTED",
        "protocol_version": "heartbeat-v2", "server_received_time": datetime.now(timezone.utc),
    })
    response = await client.get("/api/v1/data/status", headers=authenticated_user)
    assert response.status_code == 200, response.text
    rows = response.json()["data"]
    assert [row["agent_id"] for row in rows] == ["LOCAL"]
    assert rows[0]["time_trust"]["status"] == "UNKNOWN"
    assert rows[0]["spool_health"]["status"] == "UNKNOWN"
    assert rows[0]["last_seen"] == "2026-09-02T19:00:00+00:00"
    assert "public_key" not in rows[0]
    if role == "auditor":
        search = await client.get("/api/v1/data/search", headers=authenticated_user)
        assert search.status_code == 403  # Fleet read does not grant raw-log access.


@pytest.mark.asyncio
@pytest.mark.parametrize("offset,protocol,state,expected", [
    (0, "heartbeat-v2", "TRUSTED", "TRUSTED"),
    (-601, "heartbeat-v2", "TRUSTED", "STALE"),
    (300, "heartbeat-v2", "TRUSTED", "STALE"),
    (0, "heartbeat-v1", "TRUSTED", "LEGACY"),
    (0, "heartbeat-v2", "UNTRUSTED", "UNTRUSTED"),
])
async def test_endpoint_time_trust_uses_latest_observation_and_freshness(
    client, authenticated_user, db, agent_public_key_pem, offset, protocol, state, expected,
):
    tenant_id = (await client.get("/api/v1/auth/me", headers=authenticated_user)).json()["user"]["tenant_id"]
    await db.agents.insert_one({
        "tenant_id": tenant_id, "agent_id": "CLOCK", "public_key": agent_public_key_pem, "status": "active",
    })
    await db.agent_coverage_observations.insert_many([
        {
            "tenant_id": tenant_id, "agent_id": "CLOCK", "clock_state": value,
            "protocol_version": protocol,
            "server_received_time": datetime.now(timezone.utc) + timedelta(seconds=age),
        }
        for age, value in [(offset - 100, "DEGRADED"), (offset, state)]
    ])
    response = await client.get("/api/v1/data/status", headers=authenticated_user)
    assert response.status_code == 200, response.text
    assert response.json()["data"][0]["time_trust"]["status"] == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("sensor", [[], {"channels": {"Security": "bad"}}, {"spool": "bad"}])
async def test_malformed_or_missing_sensor_data_never_looks_healthy(
    client, authenticated_user, db, redis_client, agent_public_key_pem, sensor,
):
    tenant_id = (await client.get("/api/v1/auth/me", headers=authenticated_user)).json()["user"]["tenant_id"]
    await db.agents.insert_one({
        "tenant_id": tenant_id, "agent_id": "SENSOR", "public_key": agent_public_key_pem, "status": "active",
    })
    await redis_client.set(f"status:{tenant_id}:SENSOR", datetime.now(timezone.utc).isoformat())
    await redis_client.set("warsoc:agent_sensor:SENSOR", json.dumps(sensor))
    response = await client.get("/api/v1/data/status", headers=authenticated_user)
    assert response.status_code == 200, response.text
    row = response.json()["data"][0]
    assert row["spool_health"]["status"] == "UNKNOWN"
    assert row["audit_coverage"]["status"] != "READY"


@pytest.mark.asyncio
async def test_fleet_rejects_unauthenticated_read(client):
    assert (await client.get("/api/v1/data/status")).status_code == 401

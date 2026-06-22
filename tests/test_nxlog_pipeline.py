import pytest
from httpx import AsyncClient
import uuid
import time
from datetime import datetime, timezone

@pytest.mark.asyncio
async def test_nxlog_end_to_end_pipeline(async_client: AsyncClient, db, redis_client, auth_headers):
    # 1. Generate Activation Code (Mocking the UI Dashboard action)
    act_resp = await async_client.post(
        "/api/v1/agent/generate-activation",
        headers=auth_headers
    )
    assert act_resp.status_code == 200
    act_code = act_resp.json()["activation_code"]
    
    # 2. Phase 1: Activate Agent (Mocking activate_agent.ps1)
    reg_payload = {
        "activation_code": act_code,
        "public_key": "NXLOG_TLS_NATIVE"
    }
    reg_resp = await async_client.post("/api/v1/agent/register", json=reg_payload)
    assert reg_resp.status_code == 200
    
    agent_data = reg_resp.json()
    agent_jwt = agent_data["agent_jwt"]
    agent_id = agent_data["agent_id"]
    
    assert agent_jwt is not None
    
    headers = {
        "Authorization": f"Bearer {agent_jwt}"
    }

    # 3. Phase 4: Test The Replay Blockade (Timestamp too old)
    old_ts = int(time.time()) - 400 # 6.6 minutes ago
    bad_payload = {
        "nonce": str(uuid.uuid4()),
        "timestamp": old_ts,
        "payload": [{"event_id": 4688, "message": "Test old log"}]
    }
    
    pulse_resp_bad = await async_client.post("/api/v1/ingest/pulse", json=bad_payload, headers=headers)
    assert pulse_resp_bad.status_code == 400
    assert "Payload timestamp out of acceptable 5-minute window" in pulse_resp_bad.json()["detail"]
    
    # 4. Phase 4: Test Successful NXLog Ingestion
    valid_nonce = str(uuid.uuid4())
    good_payload = {
        "nonce": valid_nonce,
        "timestamp": int(time.time()),
        "payload": [{"event_id": 4663, "message": "NXLog File Deletion Test"}]
    }
    
    pulse_resp_good = await async_client.post("/api/v1/ingest/pulse", json=good_payload, headers=headers)
    assert pulse_resp_good.status_code in [200, 202]
    assert pulse_resp_good.json()["status"] == "success"
    
    # 5. Phase 4: Test The Nonce Cache (Replay Attack)
    # We send the exact same payload again within the 5-minute window
    pulse_resp_replay = await async_client.post("/api/v1/ingest/pulse", json=good_payload, headers=headers)
    assert pulse_resp_replay.status_code == 409
    assert "Replay attack detected" in pulse_resp_replay.json()["detail"]

    print("\n[+] End-to-End NXLog Pipeline Tests Passed: Registration -> JWT Injection -> Replay Prevention -> Successful Ingestion")

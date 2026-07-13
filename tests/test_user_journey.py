import pytest
import asyncio
import time
import uuid
from httpx import AsyncClient
from tests.helpers import ed25519_keypair_pem, provision_and_login_admin

@pytest.mark.asyncio
async def test_user_and_agent_ingest_journey(async_client: AsyncClient, db, redis_client):
    print("\n\n" + "="*60)
    print("[START] WARSOC END-TO-END JOURNEY TEST")
    print("="*60)

    # ---------------------------------------------------------
    # Phase 1: User Sign Up & Login (The Pharmacy Owner POV)
    # ---------------------------------------------------------
    session = await provision_and_login_admin(async_client, "pharmacy_admin")
    print("[+] Admin POV: Provisioned and logged into a paid tenant successfully.")
    user_token = session["token"]
    csrf_token = session["csrf_token"]
    user_headers = {"x-csrf-token": csrf_token}
    async_client.cookies.set("warsoc_token", user_token)
    print("[+] User POV: Logged in. Received HttpOnly Cookie and CSRF Token.")

    # 1C. Verify Profile & Tenant
    resp = await async_client.get("/api/v1/auth/me", headers=user_headers)
    assert resp.status_code == 200
    user_profile = resp.json()
    tenant_id = user_profile["user"]["tenant_id"]
    print(f"[+] User POV: Verified profile. Assigned Tenant ID: {tenant_id}")


    # ---------------------------------------------------------
    # Phase 2: Agent Enrollment (The Deployment Script POV)
    # ---------------------------------------------------------
    
    # 2A. User generates activation code from dashboard
    resp = await async_client.post("/api/v1/agent/generate-activation", headers=user_headers)
    assert resp.status_code == 200
    act_code = resp.json()["activation_code"]
    print(f"[+] Admin POV: Generated 10-minute activation code: {act_code}")

    # 2B. The `activate_agent.ps1` script redeems the code for a permanent JWT
    _, public_key_pem = ed25519_keypair_pem()
    reg_payload = {
        "activation_code": act_code,
        "public_key": public_key_pem
    }
    resp = await async_client.post("/api/v1/agent/register", json=reg_payload)
    assert resp.status_code == 200, f"Agent register failed: {resp.text}"
    agent_data = resp.json()
    agent_jwt = agent_data["agent_jwt"]
    agent_id = agent_data["agent_id"]
    print(f"[+] Installer POV: Redeemed code. Acquired permanent JWT for Agent: {agent_id}")


    # ---------------------------------------------------------
    # Phase 3: Native Windows Telemetry Ingestion
    # ---------------------------------------------------------
    agent_headers = {"Authorization": f"Bearer {agent_jwt}"}
    
    mock_logs = [
        {
            "event_id": 4688,
            "message": "New process created: powershell.exe -enc ZABlAG0AbwA=",
            "raw_event_data": {"channel": "Security", "NewProcessName": "powershell.exe"},
        },
        {
            "event_id": 1102,
            "message": "The audit log was cleared",
            "raw_event_data": {"channel": "Security"},
        },
    ]
    
    pulse_payload = {
        "nonce": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "payload": mock_logs
    }
    
    resp = await async_client.post("/api/v1/ingest/pulse", json=pulse_payload, headers=agent_headers)
    assert resp.status_code in [200, 202], f"Pulse failed: {resp.text}"
    print("[+] Agent POV: Streamed native Windows Events 4688 and 1102 through replay protection.")

    # ---------------------------------------------------------
    # Phase 4: Durable Queue Handoff
    # ---------------------------------------------------------
    
    # Check that logs landed in the queue
    q_len = await redis_client.xlen("raw_logs_queue")
    assert q_len > 0
    print("[+] Backend POV: Native events are durably queued for SIEM and PECA workers.")

    print("="*60)
    print("[OK] ROUTE JOURNEY SUCCESSFUL: Provisioning -> Login -> Activation -> Native Ingest Queue")
    print("="*60 + "\n")

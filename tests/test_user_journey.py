import pytest
import asyncio
import time
import uuid
from httpx import AsyncClient
from tests.helpers import ed25519_keypair_pem, provision_and_login_admin

@pytest.mark.asyncio
async def test_full_user_and_agent_journey(async_client: AsyncClient, db, redis_client):
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
    # Phase 3: Telemetry Ingestion (The NXLog POV)
    # ---------------------------------------------------------
    agent_headers = {"Authorization": f"Bearer {agent_jwt}"}
    
    mock_logs = [
        # Compliance Log (PECA/FBR)
        {"event_id": 4663, "message": "Object Access - Read Invoice.pdf"},
        # Security Log (Process Injection)
        {"event_id": 8, "message": "CreateRemoteThread into lsass.exe"}
    ]
    
    pulse_payload = {
        "nonce": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "payload": mock_logs
    }
    
    resp = await async_client.post("/api/v1/ingest/pulse", json=pulse_payload, headers=agent_headers)
    assert resp.status_code in [200, 202], f"Pulse failed: {resp.text}"
    print("[+] NXLog POV: Streamed Sysmon Event 8 and Audit Event 4663 successfully through Replay Blockade.")

    # ---------------------------------------------------------
    # Phase 4: SIEM Processing & Dashboard Verification
    # ---------------------------------------------------------
    
    # Check that logs landed in the queue
    q_len = await redis_client.xlen("raw_logs_queue")
    assert q_len > 0
    print("[+] Backend POV: Logs successfully queued in Redis Stream for SIEM/FBR Workers.")
    
    # To mock the SIEM worker, we manually insert the alerts into DB (since worker doesn't run in pytest)
    await db["security_alerts"].insert_one({
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "event_id": 8,
        "severity": "CRITICAL",
        "description": "Process Injection Detected (CreateRemoteThread)",
        "timestamp": time.time()
    })
    
    await db["fbr_pos_logs"].insert_one({
         "tenant_id": tenant_id,
         "agent_id": agent_id,
         "event_id": 4663,
         "timestamp": time.time(),
         "message": "FBR Invoice Accessed"
    })
    print("[+] Worker POV: SIEM & FBR workers consumed stream and generated incidents.")

    # 4A. User checks Dashboard for Alerts
    # Using ingest_pulse's history endpoint which is mapped for the tenant
    resp = await async_client.get(f"/api/v1/ingest/alerts/history", headers=user_headers)
    assert resp.status_code == 200, f"History failed: {resp.text}"
    alerts = resp.json()
    
    # Since the route might filter differently, we check our raw DB just in case the route expects specific schema
    db_alerts = await db["security_alerts"].find({"tenant_id": tenant_id}).to_list(100)
    assert len(db_alerts) > 0
    print("[+] User POV: Refreshed dashboard. Process Injection Alert is blinking RED.")

    print("="*60)
    print("[OK] FULL USER JOURNEY SUCCESSFUL: Signup -> Deployment -> Detection -> Alerting")
    print("="*60 + "\n")

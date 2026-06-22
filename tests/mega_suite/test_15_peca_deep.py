import pytest
import asyncio
import httpx
from app.main import app as fastapi_app
import uuid
import time
import json
import os
from ecdsa import SigningKey, SECP256k1
import hashlib
from app.database import get_db, db_manager

API_BASE_URL = "http://127.0.0.1:8000/api/v1"

def _now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()

def _http_event(event_id, event_uid, tenant_id, agent_id, message, source_ip, private_key_pem, user=None):
    from ecdsa import SigningKey, SECP256k1
    import hashlib
    sk = SigningKey.from_pem(private_key_pem)
    
    payload = {
        "event_id": event_id,
        "event_uid": event_uid,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "timestamp": _now_iso(),
        "source_ip": source_ip,
        "message": message,
        "raw_data": message
    }
    if user:
        payload["user"] = user
    
    payload_str = json.dumps(payload, sort_keys=True)
    signature = sk.sign_deterministic(payload_str.encode("utf-8"), hashfunc=hashlib.sha256).hex()
    
    payload["agent_signature"] = signature
    return payload

@pytest.mark.asyncio
async def test_peca_deep_dive():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver/api/v1", timeout=30.0) as client:
        # 1. Setup Tenant and Agent
        username = f"peca_tester_{uuid.uuid4().hex[:8]}"
        password = "SuperSecretPassword123!"
        
        signup_resp = await client.post("/auth/signup", json={
            "email": f"{username}@example.com",
            "username": username,
            "password": password,
            "full_name": "PECA Tester",
            "company_name": "PECA Deep Dive Corp"
        })
        assert signup_resp.status_code == 201
        
        login_resp = await client.post("/auth/login", json={
            "username": username,
            "password": password
        })
        assert login_resp.status_code == 200
        
        user_token = login_resp.cookies.get("warsoc_token")
        csrf_token = login_resp.cookies.get("csrf_token")
        client.cookies.set("warsoc_token", user_token)
        client.cookies.set("csrf_token", csrf_token)
        client.headers.update({"x-csrf-token": csrf_token})
        
        tenant_id = signup_resp.json()["tenant_id"]

        # Register Agent
        sk = SigningKey.generate(curve=SECP256k1)
        private_key_pem = sk.to_pem().decode('utf-8')
        public_key_pem = sk.get_verifying_key().to_pem().decode('utf-8')
        
        activation_resp = await client.post("/agent/generate-activation")
        assert activation_resp.status_code == 200
        activation_code = activation_resp.json()["activation_code"]
        
        reg_resp = await client.post("/agent/register", json={
            "activation_code": activation_code,
            "public_key": public_key_pem,
            "features": "SIEM,FBR,PECA"
        })
        assert reg_resp.status_code == 200
        
        agent_data = reg_resp.json()
        agent_id = agent_data["agent_id"]
        agent_jwt = agent_data["agent_jwt"]

        agent_client = httpx.AsyncClient(base_url=API_BASE_URL, headers={"Authorization": f"Bearer {agent_jwt}"})
        
        db = db_manager.db
        
        # Inject tenant features to Redis since the test doesn't go through billing flow
        from app.config.config import get_settings
        settings = get_settings()
        import redis.asyncio as aioredis
        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
        await redis_client.set(f"tenant_features:{tenant_id}", "siem,fbr_pos,peca_forensic")
        
        # Manually create consumer groups starting from 0 to prevent the worker from missing injected events
        # due to test DB flush causing NOGROUP Auto-Heal (which creates at id="$")
        try:
            await redis_client.xgroup_create("raw_logs_queue", "fbr_group", id="0", mkstream=True)
        except Exception as e:
            pass
        try:
            await redis_client.xgroup_create("raw_logs_queue", "siem_group", id="0", mkstream=True)
        except Exception:
            pass
        try:
            await redis_client.xgroup_create("raw_logs_queue", "peca_group", id="0", mkstream=True)
        except Exception:
            pass
            
        await redis_client.close()

        # Clear old logs for this tenant
        await db.peca_forensic_logs.delete_many({"tenant_id": tenant_id})

        # --- SCENARIO 1: Failed Logon Detection (4625) ---
        print("[*] Testing Failed Logon (4625)...")
        logon_event = _http_event(
            event_id=4625,
            event_uid=f"peca-logon-{uuid.uuid4()}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            message="Failed login attempt for Administrator",
            source_ip="10.0.0.100",
            private_key_pem=private_key_pem
        )

        # --- SCENARIO 2: Audit Log Deletion (1102) ---
        print("[*] Testing Audit Log Deletion (1102)...")
        audit_event = _http_event(
            event_id=1102,
            event_uid=f"peca-audit-{uuid.uuid4()}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            message="The audit log was cleared.",
            source_ip="10.0.0.100",
            private_key_pem=private_key_pem
        )

        # --- SCENARIO 3: Suspicious Process Creation (4688) ---
        print("[*] Testing Process Creation (4688)...")
        proc_event = _http_event(
            event_id=4688,
            event_uid=f"peca-proc-{uuid.uuid4()}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            message="A new process has been created.",
            source_ip="10.0.0.50",
            private_key_pem=private_key_pem
        )

        # --- SCENARIO 4: Non-PECA Event (Control) ---
        print("[*] Testing Non-PECA Event...")
        non_peca_event = _http_event(
            event_id="FBR-INV-DEL",
            event_uid=f"non-peca-{uuid.uuid4()}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            message="Invoice Deleted",
            source_ip="10.0.0.200",
            private_key_pem=private_key_pem
        )

        resp = await agent_client.post("/ingest/pulse", json=[logon_event, audit_event, proc_event, non_peca_event])
        assert resp.status_code == 200

        print("[*] Waiting for PECA Worker to process...")
        await asyncio.sleep(10)

        # Verification
        peca_logs_cursor = db.peca_forensic_logs.find({"tenant_id": tenant_id})
        peca_logs = await peca_logs_cursor.to_list(length=100)
        
        # Verify events were stored
        stored_event_ids = [str(log.get("event_id")) for log in peca_logs]
        
        assert "4625" in stored_event_ids, "4625 was not stored in peca_forensic_logs!"
        assert "1102" in stored_event_ids, "1102 was not stored in peca_forensic_logs!"
        assert "4688" in stored_event_ids, "4688 was not stored in peca_forensic_logs!"
        
        # Verify non-PECA event was NOT stored
        assert "FBR-INV-DEL" not in stored_event_ids, "FBR-INV-DEL should NOT be stored in peca_forensic_logs!"
        
        # Verify compliance metadata
        for log in peca_logs:
            assert log.get("compliance_pack") == "peca_forensic", f"Missing compliance_pack tag on {log.get('event_id')}"
            assert "matched_rule_id" in log, f"Missing matched_rule_id on {log.get('event_id')}"

        print("[*] PECA Deep Dive: SUCCESS!")

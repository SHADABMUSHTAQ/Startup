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
async def test_fbr_deep_dive():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver/api/v1", timeout=30.0) as client:
        # 1. Setup Tenant and Agent
        username = f"fbr_tester_{uuid.uuid4().hex[:8]}"
        password = "SuperSecretPassword123!"
        
        signup_resp = await client.post("/auth/signup", json={
            "email": f"{username}@example.com",
            "username": username,
            "password": password,
            "full_name": "FBR Tester",
            "company_name": "FBR Deep Dive Corp"
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

        # Clear old alerts/logs for this tenant
        await db.security_alerts.delete_many({"tenant_id": tenant_id})
        await db.fbr_pos_logs.delete_many({"tenant_id": tenant_id})

        # --- SCENARIO 1: FBR Invoice Deletion ---
        print("[*] Testing FBR Invoice Deletion...")
        del_event = _http_event(
            event_id="FBR-INV-DEL",
            event_uid=f"fbr-del-{uuid.uuid4()}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            message="Invoice #1024 deleted from POS database",
            source_ip="10.0.0.100",
            private_key_pem=private_key_pem
        )

        # --- SCENARIO 2: FBR Invoice Modification ---
        print("[*] Testing FBR Invoice Modification...")
        mod_event = _http_event(
            event_id="FBR-INV-MOD",
            event_uid=f"fbr-mod-{uuid.uuid4()}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            message="Invoice #1025 total altered by cashier",
            source_ip="10.0.0.100",
            private_key_pem=private_key_pem
        )

        # --- SCENARIO 3: Windows Object Delete (Cross-Framework) ---
        print("[*] Testing Windows Object Delete (4660)...")
        win_del_event = _http_event(
            event_id=4660,
            event_uid=f"win-del-{uuid.uuid4()}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            message="An object was deleted",
            source_ip="10.0.0.50",
            private_key_pem=private_key_pem
        )

        # --- SCENARIO 4: Non-FBR Event (Control) ---
        print("[*] Testing Non-FBR Event...")
        non_fbr_event = _http_event(
            event_id=4625,
            event_uid=f"non-fbr-{uuid.uuid4()}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            message="Failed login attempt",
            source_ip="10.0.0.200",
            private_key_pem=private_key_pem
        )

        resp = await agent_client.post("/ingest/pulse", json=[del_event, mod_event, win_del_event, non_fbr_event])
        assert resp.status_code == 200

        print("[*] Waiting for FBR Worker to process...")
        await asyncio.sleep(10)

        # Verification
        fbr_logs_cursor = db.fbr_pos_logs.find({"tenant_id": tenant_id})
        fbr_logs = await fbr_logs_cursor.to_list(length=100)
        
        # Verify events were stored
        stored_event_ids = [str(log.get("event_id")) for log in fbr_logs]
        
        assert "FBR-INV-DEL" in stored_event_ids, "FBR-INV-DEL was not stored in fbr_pos_logs!"
        assert "FBR-INV-MOD" in stored_event_ids, "FBR-INV-MOD was not stored in fbr_pos_logs!"
        assert "4660" in stored_event_ids, "4660 was not stored in fbr_pos_logs!"
        
        # Verify non-FBR event was NOT stored
        assert "4625" not in stored_event_ids, "4625 should NOT be stored in fbr_pos_logs!"
        
        # Verify compliance metadata
        for log in fbr_logs:
            assert log.get("compliance_pack") == "fbr_pos", f"Missing compliance_pack tag on {log.get('event_id')}"
            assert "matched_rule_id" in log, f"Missing matched_rule_id on {log.get('event_id')}"

        print("[*] FBR Deep Dive: SUCCESS!")

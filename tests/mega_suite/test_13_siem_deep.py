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
async def test_siem_deep_dive():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver/api/v1", timeout=30.0) as client:
        # 1. Setup Tenant and Agent
        username = f"siem_tester_{uuid.uuid4().hex[:8]}"
        password = "SuperSecretPassword123!"
        
        signup_resp = await client.post("/auth/signup", json={
            "email": f"{username}@example.com",
            "username": username,
            "password": password,
            "full_name": "SIEM Tester",
            "company_name": "SIEM Deep Dive Corp"
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

        # Clear old alerts for this tenant
        await db.security_alerts.delete_many({"tenant_id": tenant_id})

        # --- SCENARIO 1: SQL Injection (Regex Engine) ---
        print("[*] Testing SQL Injection...")
        sql_event = _http_event(
            event_id=1,  # Arbitrary HTTP request map (or Windows-Sec if mapped)
            event_uid=f"sqli-{uuid.uuid4()}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            message="GET /api/v1/users?id=1' OR 1=1 -- HTTP/1.1",
            source_ip=f"8.8.8.{int(time.time()) % 255}",
            private_key_pem=private_key_pem
        )
        resp = await agent_client.post("/ingest/pulse", json=[sql_event])
        assert resp.status_code == 200, f"SQL injection ingest failed: {resp.text}"
        
        # --- SCENARIO 2: Ransomware Shadow Copy Delete ---
        print("[*] Testing Ransomware Detection...")
        ransom_event = _http_event(
            event_id=4688,  # Process Create
            event_uid=f"ransom-{uuid.uuid4()}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            message="wmic shadowcopy delete",
            source_ip="10.0.0.5",
            private_key_pem=private_key_pem
        )
        resp = await agent_client.post("/ingest/pulse", json=[ransom_event])
        assert resp.status_code == 200

        # --- SCENARIO 3: False Positive Control ---
        print("[*] Testing False Positive Suppression...")
        fp_event = _http_event(
            event_id=4625,  # Failed Login
            event_uid=f"fp-{uuid.uuid4()}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            message="failed password for system healthcheck process",
            source_ip="192.168.1.50",
            private_key_pem=private_key_pem
        )
        resp = await agent_client.post("/ingest/pulse", json=[fp_event])
        assert resp.status_code == 200

        # --- SCENARIO 4: Brute Force Stateful Rule ---
        print("[*] Testing Brute Force Stateful Threshold...")
        # threshold is 10 in 60s for high_velocity_brute_force, or brute_force_threshold = 3 for general.
        # Let's send 4 failed logins from same IP for same user
        bf_events = []
        for i in range(4):
            bf_events.append(_http_event(
                event_id=4625,
                event_uid=f"bf-{uuid.uuid4()}",
                tenant_id=tenant_id,
                agent_id=agent_id,
                message="failed password for root",
                source_ip="1.2.3.4",
                private_key_pem=private_key_pem
            ))
        resp = await agent_client.post("/ingest/pulse", json=bf_events)
        assert resp.status_code == 200

        # --- SCENARIO 5: Password Spraying Stateful Rule ---
        print("[*] Testing Password Spraying...")
        # Password spraying threshold: 10 different users from same IP
        spray_events = []
        for i in range(11):
            spray_events.append(_http_event(
                event_id=4625,
                event_uid=f"spray-{uuid.uuid4()}",
                tenant_id=tenant_id,
                agent_id=agent_id,
                message=f"failed password for user{i}",
                source_ip="5.5.5.5",
                private_key_pem=private_key_pem,
                user=f"spray_target_{i}"
            ))
        resp = await agent_client.post("/ingest/pulse", json=spray_events)
        assert resp.status_code == 200

        print("[*] Waiting for SIEM Worker to process...")
        await asyncio.sleep(10)

        # Verification
        alerts_cursor = db.security_alerts.find({"tenant_id": tenant_id})
        alerts = await alerts_cursor.to_list(length=100)
        
        # Check SQL Injection
        sql_alert = next((a for a in alerts if a.get("type") == "SQL_INJECTION"), None)
        assert sql_alert is not None, f"SQL Injection was not detected! Alerts: {[a.get('type') for a in alerts]}"
        assert sql_alert["severity"] == "HIGH"
        
        # Check Ransomware
        ransom_alert = next((a for a in alerts if a.get("type") == "SIGMA_RANSOMWARE_SHADOW_DELETE"), None)
        assert ransom_alert is not None, "Ransomware shadow delete was not detected!"
        assert ransom_alert["severity"] == "CRITICAL"
        
        # Check False Positive
        # The FP event has "healthcheck" which is in `suppress_if_message_contains`
        fp_alerts = [a for a in alerts if "healthcheck" in a.get("summary", "")]
        assert len(fp_alerts) == 0, "False Positive was incorrectly alerted!"
        
        # Check Stateful Brute Force (BRUTE_FORCE_PATTERN or high_velocity)
        bf_alerts = [a for a in alerts if "brute force" in a.get("summary", "").lower() or a.get("type") == "BRUTE_FORCE_PATTERN"]
        assert len(bf_alerts) > 0, "Brute force pattern not detected!"
        
        # Check Password Spraying
        spray_alerts = [a for a in alerts if a.get("type") == "Password spraying attack detected" or "spraying" in a.get("summary", "").lower()]
        assert len(spray_alerts) > 0, "Password spraying pattern not detected!"

        print("[*] SIEM Deep Dive: SUCCESS!")

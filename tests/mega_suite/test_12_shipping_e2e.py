import asyncio
import os
import time
import uuid
import httpx
from app.main import app as fastapi_app
import websockets
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pymongo import MongoClient

API_BASE_URL = os.getenv("E2E_API_BASE_URL", "http://127.0.0.1:8000/api/v1")
WS_BASE_URL = os.getenv("E2E_WS_BASE_URL", "ws://127.0.0.1:8000/api/v1")
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "WarSOC_DB")

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

def _ed25519_public_key_pem() -> str:
    signing_key = ed25519.Ed25519PrivateKey.generate()
    return signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _http_event(event_id: int, event_uid: str, tenant_id: str, agent_id: str, message: str, source_ip: str) -> dict:
    return {
        "event_uid": event_uid,
        "event_id": event_id,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "source_ip": source_ip,
        "user": "SYSTEM",
        "message": message,
        "timestamp": _now_iso(),
        "raw_data": {"event_id": event_id, "source_ip": source_ip},
        "raw_event_data": {"event_id": event_id, "source_ip": source_ip},
        "processed_data": {},
        "agent_version": "shipping-e2e-agent",
    }


@pytest.mark.asyncio
async def test_shipping_e2e(mongo_client, settings):
    """
    Final Shipping End-to-End Test.
    Covers: User Signup -> Upgrade -> Login -> Agent Reg -> Agent Login -> Mass Ingest -> WebSocket -> Export -> Limits
    """
    # 1. Setup Data
    username = f"e2e_user_{uuid.uuid4().hex[:8]}"
    password = "SuperSecretPassword123!"
    email = f"{username}@example.com"

    # 2. Signup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver/api/v1", timeout=30.0) as client:
        print(f"[*] Signing up user {username}...")
        signup_resp = await client.post("/auth/signup", json={
            "username": username,
            "email": email,
            "full_name": "E2E Tester",
            "password": password,
            "plan_type": "Free"
        })
        assert signup_resp.status_code == 201, f"Signup failed: {signup_resp.text}"
        
        # 3. DB Manual Upgrade (Simulate Sales Provisioning)
        print("[*] Simulating Admin Upgrading tenant to FULL_SUITE...")
        db = mongo_client[os.getenv("MONGO_DB_NAME", "WarSOC_DB")]
        
        user_doc = await db.users.find_one({"username": username})
        tenant_id = user_doc["tenant_id"]
        
        await db.users.update_one(
            {"username": username}, 
            {"$set": {
                "plan_type": "FULL_SUITE", 
                "compliance_packs": ["fbr_pos", "peca_forensic"]
            }}
        )

        # 4. Login User
        print("[*] Logging in user to get JWT...")
        login_resp = await client.post("/auth/login", json={
            "username": username,
            "password": password
        })
        assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
        
        # Extract token and CSRF
        user_token = login_resp.cookies.get("warsoc_token")
        csrf_token = login_resp.cookies.get("csrf_token")
        
        # Set them globally on client
        client.cookies.set("warsoc_token", user_token)
        client.cookies.set("csrf_token", csrf_token)
        client.headers.update({"x-csrf-token": csrf_token})
        
        # Verify rate limits and login audit trail
        user_after_login = await db.users.find_one({"username": username})
        assert "last_login_at" in user_after_login, "last_login_at not recorded!"
        assert "last_login_ip" in user_after_login, "last_login_ip not recorded!"
        
        # 5. Agent Registration
        print("[*] Generating Agent Keys and Registering Agent...")
        public_key_pem = _ed25519_public_key_pem()

        # First, user generates an activation code
        activation_resp = await client.post("/agent/generate-activation")
        assert activation_resp.status_code == 200, f"Activation generation failed: {activation_resp.text}"
        activation_code = activation_resp.json()["activation_code"]
        
        reg_resp = await client.post("/agent/register", json={
            "activation_code": activation_code,
            "public_key": public_key_pem,
            "features": "SIEM,FBR,PECA"
        })
        assert reg_resp.status_code == 200, f"Agent Registration Failed: {reg_resp.text}"
        
        agent_data = reg_resp.json()
        agent_id = agent_data["agent_id"]
        
        agent_doc = await db.agents.find_one({"agent_id": agent_id})
        assert agent_doc["key_rotation_status"] == "completed", "Key rotation status not tracked correctly!"

        # 6. Agent JWT is issued by the activation/register flow.
        agent_jwt = reg_resp.json().get("agent_jwt")
        assert agent_jwt is not None, "Agent JWT not returned from registration!"
        
        # 7. Start WebSocket Listener
        print("[*] Requesting WebSocket Ticket...")
        ticket_resp = await client.post("/ws/ticket")
        assert ticket_resp.status_code == 200, f"Failed to get WS ticket: {ticket_resp.text}"
        ws_ticket = ticket_resp.json()["ticket"]

        print("[*] Starting WebSocket Listener...")
        received_alerts = []
        async def listen_ws():
            ws_host = API_BASE_URL.replace("http://", "ws://").replace("/api/v1", "")
            ws_url = f"{ws_host}/ws/alerts?ticket={ws_ticket}"
            try:
                async with websockets.connect(ws_url) as websocket:
                    # We don't need to send auth message anymore since the ticket handles it
                    print("[WS] Connected successfully via ticket.")
                    
                    while True:
                        msg = await asyncio.wait_for(websocket.recv(), timeout=30.0)
                        data = json.loads(msg)
                        received_alerts.append(data)
            except asyncio.TimeoutError:
                print("[WS] Listener timed out waiting for messages.")
            except websockets.exceptions.ConnectionClosed as e:
                print(f"[WS] Connection closed: {e}")
            except Exception as e:
                print(f"[WS] Exception: {e}")

        ws_task = asyncio.create_task(listen_ws())
        
        # 8. Mass Ingestion
        print("[*] Sending 150 Events (Mix of SIEM, FBR, PECA)...")
        events = []
        for i in range(150):
            if i % 3 == 0:
                event_id = 7045
                msg = f"Ransomware Encryption Pattern Detected {i}"
            elif i % 3 == 1:
                event_id = 200  # PECA
                msg = f"Evidence Extraction {i}"
            else:
                event_id = 100  # FBR
                msg = f"POS Transaction Blocked {i}"
                
            events.append(_http_event(
                event_id=event_id,
                event_uid=f"e2e-event-{i}",
                tenant_id=tenant_id,
                agent_id=agent_id,
                message=msg,
                source_ip="10.20.30.40"
            ))
        
        # Send in batches of 500
        agent_client = httpx.AsyncClient(base_url=API_BASE_URL, headers={"Authorization": f"Bearer {agent_jwt}"})
        batch_size = 500
        for i in range(0, 150, batch_size):
            batch = events[i:i+batch_size]
            envelope = {
                "nonce": uuid.uuid4().hex,
                "timestamp": int(time.time()),
                "payload": batch,
            }
            resp = await agent_client.post("/ingest/pulse", json=envelope, timeout=30.0)
            assert resp.status_code in (200, 202), f"Ingest failed: {resp.text}"
            
        print("[*] Ingestion complete. Waiting for workers to process and WebSocket to stream...")
        await asyncio.sleep(15) # Give workers time to process
        
        # We don't want to wait forever for WS, so we cancel it
        ws_task.cancel()
        
        print(f"[*] Received {len(received_alerts)} real-time alerts via WebSocket.")
        assert len(received_alerts) > 0, "No real-time alerts received over WebSocket!"
        
        # 9. Verify Compliance Evidence Pagination & O(N) Mitigation
        print("[*] Testing Pagination O(N) Limit...")
        evidence_resp = await client.get("/compliance/evidence?skip=15000&limit=50", timeout=10.0)
        assert evidence_resp.status_code == 200, f"Evidence fetch failed: {evidence_resp.text}"
        ev_data = evidence_resp.json()
        assert ev_data["pagination"]["skip"] == 10000, f"Skip was not capped! Skip = {ev_data['pagination']['skip']}"
        assert ev_data.get("info") is not None, "O(N) info warning message was not returned!"
        
        # 10. Verify Export PDF/CSV Endpoint (maxTimeMS Check)
        print("[*] Testing Export Endpoint...")
        export_resp = await client.get("/compliance/export?type=fbr&limit=100", timeout=15.0)
        assert export_resp.status_code == 200, f"Export failed: {export_resp.text}"
        assert export_resp.headers["content-type"] == "text/csv; charset=utf-8"
        
        print("[*] SUCCESS: All E2E constraints, limits, and workflows passed successfully!")

if __name__ == "__main__":
    asyncio.run(test_shipping_e2e())

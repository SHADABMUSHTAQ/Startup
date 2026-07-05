import os
import time
import uuid
import httpx
from app.main import app as fastapi_app
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

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
    In-process shipping contract.
    Covers manual provisioning, login, agent registration, authenticated mass
    ingestion, WebSocket ticket issuance, export, and pagination limits.
    """
    # 1. Setup Data
    username = f"e2e_user_{uuid.uuid4().hex[:8]}"
    password = "SuperSecretPassword123!"
    email = f"{username}@example.com"

    # 2. Manual B2B provisioning
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver/api/v1", timeout=30.0) as client:
        print(f"[*] Provisioning tenant admin {username}...")
        admin_key = os.getenv("SUPER_ADMIN_API_KEY")
        assert admin_key, "SUPER_ADMIN_API_KEY must be configured for the shipping contract"
        provision_resp = await client.post(
            "/admin/provision",
            headers={"X-Admin-Key": admin_key},
            json={
                "company_name": "WarSOC Shipping Contract",
                "plan_type": "FULL_SUITE",
                "compliance_packs": ["fbr_pos", "peca_forensic"],
                "max_agents": 50,
                "admin_email": email,
                "admin_name": "E2E Tester",
                "admin_password": password,
            },
        )
        assert provision_resp.status_code == 200, f"Provisioning failed: {provision_resp.text}"
        tenant_id = provision_resp.json()["tenant_id"]
        db = mongo_client[settings.mongodb_db_name]

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
        
        # 7. Verify a short-lived WebSocket ticket is issued and persisted.
        print("[*] Requesting WebSocket Ticket...")
        ticket_resp = await client.post("/ws/ticket")
        assert ticket_resp.status_code == 200, f"Failed to get WS ticket: {ticket_resp.text}"
        ws_ticket = ticket_resp.json()["ticket"]
        redis_client = fastapi_app.state.redis
        ticket_key = f"warsoc:ws_ticket:{ws_ticket}"
        assert await redis_client.get(ticket_key), "WebSocket ticket was not persisted"
        assert 0 < await redis_client.ttl(ticket_key) <= 30
        
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
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=fastapi_app),
            base_url="http://testserver/api/v1",
            headers={"Authorization": f"Bearer {agent_jwt}"},
        ) as agent_client:
            envelope = {
                "nonce": uuid.uuid4().hex,
                "timestamp": int(time.time()),
                "payload": events,
            }
            resp = await agent_client.post("/ingest/pulse", json=envelope, timeout=30.0)
        assert resp.status_code in (200, 202), f"Ingest failed: {resp.text}"
        assert await redis_client.xlen("raw_logs_queue") == 150

        # Seed one post-worker evidence row so the export/pagination API contract
        # is verified without depending on an external worker process.
        await db.fbr_pos_logs.insert_one(
            {
                "tenant_id": tenant_id,
                "event_uid": f"shipping-export-{uuid.uuid4().hex}",
                "event_id": "FBR-INV-DEL",
                "timestamp": _now_iso(),
                "compliance_pack": "fbr_pos",
                "matched_rule_id": "FBR-INV-DEL",
                "matched_rule_name": "Invoice Deletion",
                "matched_rule_severity": "High",
            }
        )
        
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

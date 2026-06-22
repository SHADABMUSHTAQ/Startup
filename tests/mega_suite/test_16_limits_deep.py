import pytest
import httpx
from app.main import app as fastapi_app
import uuid
from ecdsa import SigningKey, SECP256k1
import asyncio

API_BASE_URL = "http://127.0.0.1:8000/api/v1"

def _http_event(event_id, event_uid, tenant_id, agent_id, message, source_ip, private_key_pem):
    """Helper to generate a valid HTTP event matching the Pydantic schema."""
    import time
    from datetime import datetime, timezone
    
    timestamp = datetime.now(timezone.utc).isoformat()
    raw_event = {"raw_id": event_uid, "msg": message, "syslog_ts": timestamp}

    import json
    canonical_data = json.dumps(raw_event, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sk = SigningKey.from_pem(private_key_pem)
    signature = sk.sign(canonical_data).hex()

    return {
        "event_id": event_id,
        "event_uid": event_uid,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "message": message,
        "raw_event": raw_event,
        "agent_signature": signature
    }

@pytest.mark.asyncio
async def test_limits_deep_dive():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver/api/v1", timeout=30.0) as client:
        # 1. Setup Tenant and Agent
        username = f"limits_tester_{uuid.uuid4().hex[:8]}"
        password = "SuperSecretPassword123!"

        signup_resp = await client.post("/auth/signup", json={
            "email": f"{username}@example.com",
            "username": username,
            "password": password,
            "full_name": "Limits Tester",
            "company_name": "Limits Corp"
        })
        assert signup_resp.status_code == 201

        login_resp = await client.post("/auth/login", json={
            "username": username,
            "password": password
        })
        assert login_resp.status_code == 200

        csrf_token = login_resp.cookies.get("csrf_token")
        client.cookies.set("csrf_token", csrf_token)
        client.headers.update({"x-csrf-token": csrf_token})
        user_token = login_resp.cookies.get("warsoc_token")
        client.cookies.set("warsoc_token", user_token)

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
            "features": "SIEM"
        })
        assert reg_resp.status_code == 200

        agent_data = reg_resp.json()
        agent_id = agent_data["agent_id"]
        agent_jwt = agent_data["agent_jwt"]

        agent_client = httpx.AsyncClient(
            base_url=API_BASE_URL, 
            headers={"Authorization": f"Bearer {agent_jwt}"},
            limits=httpx.Limits(max_connections=400, max_keepalive_connections=400)
        )

        # Inject tenant features to Redis
        from app.config.config import get_settings
        settings = get_settings()
        import redis.asyncio as aioredis
        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
        await redis_client.set(f"tenant_features:{tenant_id}", "siem,fbr_pos,peca_forensic")
        await redis_client.close()

        print("[*] Testing Rate Limiting (Burst)...")
        # Send 350 requests simultaneously to trigger the 300/second limiter
        valid_event = _http_event("4624", uuid.uuid4().hex, tenant_id, agent_id, "Burst Test", "10.0.0.1", private_key_pem)
        
        async def make_request():
            return await agent_client.post("/ingest/pulse", json=[valid_event])

        # To avoid actual network timeout, we chunk the requests
        results = await asyncio.gather(*[make_request() for _ in range(350)])
        
        status_codes = [r.status_code for r in results]
        assert 429 in status_codes, f"Rate limiting did not trigger on burst traffic! Statuses: {set(status_codes)}"
        print(f"[+] Rate Limit triggered! Received 429 Too Many Requests.")
        
        # Test Payload Size
        print("[*] Testing Payload Size Limit (>5MB)...")
        huge_message = "A" * (6 * 1024 * 1024) # 6 MB string
        huge_event = _http_event("4624", uuid.uuid4().hex, tenant_id, agent_id, huge_message, "10.0.0.2", private_key_pem)
        
        resp_huge = await agent_client.post("/ingest/pulse", json=[huge_event])
        print(f"[+] Payload Size Limit result: {resp_huge.status_code}")
        assert resp_huge.status_code in (413, 400), f"Expected 413 or 400 Payload Too Large, got {resp_huge.status_code}"

        print("[*] Testing Schema Validation (Invalid Schema)...")
        # The ingest route uses manual parsing, so we test a Pydantic route like /agent/register for 422
        bad_schema_payload = {
            "activation_code": {"nested": "bad"}, # Should be a string
            "public_key": "some_key"
        }
        resp_schema = await client.post("/agent/register", json=bad_schema_payload)
        assert resp_schema.status_code == 422, f"Expected 422 Unprocessable Entity, got {resp_schema.status_code}"
        print(f"[+] Schema validation triggered! Received 422.")

        print("[*] API Armor Deep Dive: SUCCESS!")

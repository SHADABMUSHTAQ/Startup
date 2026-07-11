import pytest
import httpx
from app.main import app as fastapi_app
import uuid
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import asyncio
from fastapi import Request
from tests.helpers import provision_and_login_admin

def _http_event(event_id, event_uid, tenant_id, agent_id, message, source_ip):
    """Helper to generate a valid HTTP event matching the Pydantic schema."""
    import time
    from datetime import datetime, timezone
    
    timestamp = datetime.now(timezone.utc).isoformat()
    raw_event = {"raw_id": event_uid, "msg": message, "syslog_ts": timestamp}

    return {
        "event_id": event_id,
        "event_uid": event_uid,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "message": message,
        "raw_event": raw_event,
    }

@pytest.mark.asyncio
async def test_limits_deep_dive():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver/api/v1", timeout=30.0) as client:
        # 1. Setup Tenant and Agent
        session = await provision_and_login_admin(client, "limits_tester", api_prefix="")
        csrf_token = session["csrf_token"]
        user_token = session["token"]
        tenant_id = session["tenant_id"]

        # Register Agent
        signing_key = ed25519.Ed25519PrivateKey.generate()
        public_key_pem = signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

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
            transport=httpx.ASGITransport(app=fastapi_app),
            base_url="http://testserver/api/v1",
            headers={"Authorization": f"Bearer {agent_jwt}"},
            timeout=30.0
        )

        # Inject tenant features to Redis
        from app.config.config import get_settings
        settings = get_settings()
        import redis.asyncio as aioredis
        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
        await redis_client.set(f"tenant_features:{tenant_id}", "siem,fbr_pos,peca_forensic")
        await redis_client.aclose()

        print("[*] Testing Rate Limiting (Burst)...")
        # Exercise the production Redis limiter with a lower test threshold so
        # scheduler speed cannot move requests into a later one-second bucket.
        from app.utils.rate_limiter import redis_ingest_rate_limit

        async def test_ingest_limiter(request: Request):
            return await redis_ingest_rate_limit(
                request,
                limit_per_second=10,
                window_seconds=60,
            )

        fastapi_app.dependency_overrides[redis_ingest_rate_limit] = test_ingest_limiter
        valid_event = _http_event(
            "4624",
            uuid.uuid4().hex,
            tenant_id,
            agent_id,
            "Burst Test",
            "10.0.0.1",
        )
        
        async def make_request():
            return await agent_client.post(
                "/ingest/pulse",
                json={
                    "nonce": uuid.uuid4().hex,
                    "timestamp": int(time.time()),
                    "payload": [valid_event],
                },
            )

        try:
            results = await asyncio.gather(*[make_request() for _ in range(25)])
            status_codes = [r.status_code for r in results]
            assert 503 not in status_codes, "Redis failed before rate limiting could respond"
            assert 429 in status_codes, (
                "Rate limiting did not trigger on burst traffic! "
                f"Statuses: {set(status_codes)}"
            )
            print("[+] Rate limit triggered with HTTP 429.")
        finally:
            fastapi_app.dependency_overrides.pop(redis_ingest_rate_limit, None)

        await asyncio.sleep(2)
        
        # Test Payload Size
        print("[*] Testing Payload Size Limit (>5MB)...")
        huge_message = "A" * (6 * 1024 * 1024) # 6 MB string
        huge_event = _http_event(
            "4624",
            uuid.uuid4().hex,
            tenant_id,
            agent_id,
            huge_message,
            "10.0.0.2",
        )
        
        resp_huge = await agent_client.post(
            "/ingest/pulse",
            json={
                "nonce": uuid.uuid4().hex,
                "timestamp": int(time.time()),
                "payload": [huge_event],
            },
        )
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
        await agent_client.aclose()

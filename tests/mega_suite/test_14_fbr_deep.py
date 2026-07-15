import pytest
import asyncio
from contextlib import suppress
import httpx
from app.main import app as fastapi_app
import uuid
import time
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from app.database import db_manager
from app.workers.fbr_worker import fbr_worker
from tests.helpers import ed25519_keypair_pem, provision_and_login_admin

def _now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()

def _http_event(event_id, event_uid, tenant_id, agent_id, message, source_ip, private_key_pem, user=None):
    sk = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
    
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
    signature = sk.sign(payload_str.encode("utf-8")).hex()
    
    payload["agent_signature"] = signature
    return payload

@pytest.mark.asyncio
async def test_fbr_deep_dive():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver/api/v1", timeout=30.0) as client:
        # 1. Setup Tenant and Agent
        session = await provision_and_login_admin(client, "fbr_tester", api_prefix="")
        user_token = session["token"]
        csrf_token = session["csrf_token"]
        tenant_id = session["tenant_id"]

        # Register Agent
        private_key_pem, public_key_pem = ed25519_keypair_pem()
        
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
            await redis_client.xgroup_create("raw_logs_queue", "eto_group", id="0", mkstream=True)
        except Exception:
            pass
            
        await redis_client.aclose()

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

        # --- SCENARIO 3: POS Database File Modification ---
        print("[*] Testing FBR Database File Modification...")
        fim_event = _http_event(
            event_id="FIM-DB-MOD",
            event_uid=f"fbr-fim-{uuid.uuid4()}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            message="POS database file C:\\POS\\sales.mdf modified",
            source_ip="10.0.0.100",
            private_key_pem=private_key_pem
        )

        # --- SCENARIO 4: Windows Object Delete (Cross-Framework) ---
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

        # --- SCENARIO 5: Non-FBR Event (Control) ---
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

        worker_task = asyncio.create_task(fbr_worker())
        try:
            envelope = {
                "nonce": uuid.uuid4().hex,
                "timestamp": int(time.time()),
                "payload": [del_event, mod_event, fim_event, win_del_event, non_fbr_event],
            }
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=fastapi_app),
                base_url="http://testserver/api/v1",
                headers={"Authorization": f"Bearer {agent_jwt}"},
                timeout=30.0,
            ) as agent_client:
                resp = await agent_client.post("/ingest/pulse", json=envelope)
            assert resp.status_code in (200, 202), resp.text

            print("[*] Waiting for FBR Worker to process...")
            deadline = asyncio.get_running_loop().time() + 20
            while asyncio.get_running_loop().time() < deadline:
                if await db.fbr_pos_logs.count_documents({"tenant_id": tenant_id}) >= 2:
                    break
                await asyncio.sleep(0.25)
        finally:
            worker_task.cancel()
            with suppress(asyncio.CancelledError):
                await worker_task

        # Verification
        fbr_logs_cursor = db.fbr_pos_logs.find({"tenant_id": tenant_id})
        fbr_logs = await fbr_logs_cursor.to_list(length=100)
        
        # Verify events were stored
        stored_event_ids = [str(log.get("event_id")) for log in fbr_logs]
        
        assert "FBR-INV-DEL" in stored_event_ids, "FBR-INV-DEL was not stored in fbr_pos_logs!"
        assert "FBR-INV-MOD" in stored_event_ids, "FBR-INV-MOD was not stored in fbr_pos_logs!"
        assert "FIM-DB-MOD" not in stored_event_ids, "FIM-DB-MOD should be rejected if externally supplied!"
        assert "4660" not in stored_event_ids, "4660 unmatched FIM should be dropped!"
        assert "4625" not in stored_event_ids, "4625 should NOT be stored in fbr_pos_logs!"
        
        for log in fbr_logs:
            assert log.get("compliance_pack") == "fbr_pos", f"Missing compliance_pack tag on {log.get('event_id')}"
            assert "matched_rule_id" in log, f"Missing matched_rule_id on {log.get('event_id')}"

        print("[*] FBR Deep Dive: SUCCESS!")

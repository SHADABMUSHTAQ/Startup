import pytest
import asyncio
from contextlib import suppress
import httpx
from app.main import app as fastapi_app
import uuid
import time
import json
from cryptography.hazmat.primitives import serialization
from app.database import db_manager
from app.workers.peca_worker import peca_worker
from app.utils.agent_crypto import build_event_signature_string, build_payload_hash, build_signable_event_payload
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
        "user": user or "SYSTEM",
        "message": message,
        "raw_data": message
    }
    payload_hash = build_payload_hash(build_signable_event_payload(payload))
    signature_input = build_event_signature_string(agent_id, payload["timestamp"], event_uid, payload_hash)
    payload["payload_hash"] = payload_hash
    payload["signature_version"] = "ed25519-v1"
    payload["signature_algorithm"] = "Ed25519"
    payload["agent_signature"] = sk.sign(signature_input.encode("utf-8")).hex()
    return payload

@pytest.mark.asyncio
async def test_peca_deep_dive():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver/api/v1", timeout=30.0) as client:
        # 1. Setup Tenant and Agent
        session = await provision_and_login_admin(client, "peca_tester", api_prefix="")
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

        # --- SCENARIO 4: Service Installation (7045) ---
        print("[*] Testing Service Installation (7045)...")
        service_event = _http_event(
            event_id=7045,
            event_uid=f"peca-service-{uuid.uuid4()}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            message="A service was installed in the system.",
            source_ip="10.0.0.50",
            private_key_pem=private_key_pem
        )

        # --- SCENARIO 5: Event Logging Service Shutdown (1100) ---
        print("[*] Testing Event Logging Service Shutdown (1100)...")
        logging_shutdown_event = _http_event(
            event_id=1100,
            event_uid=f"peca-log-shutdown-{uuid.uuid4()}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            message="The event logging service has shut down.",
            source_ip="10.0.0.50",
            private_key_pem=private_key_pem
        )

        # --- SCENARIO 6: Non-PECA Event (Control) ---
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

        worker_task = asyncio.create_task(peca_worker())
        try:
            envelope = {
                "nonce": uuid.uuid4().hex,
                "timestamp": int(time.time()),
                "payload": [
                    logon_event,
                    audit_event,
                    proc_event,
                    service_event,
                    logging_shutdown_event,
                    non_peca_event,
                ],
            }
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=fastapi_app),
                base_url="http://testserver/api/v1",
                headers={"Authorization": f"Bearer {agent_jwt}"},
                timeout=30.0,
            ) as agent_client:
                resp = await agent_client.post("/ingest/pulse", json=envelope)
            assert resp.status_code in (200, 202), resp.text

            print("[*] Waiting for PECA Worker to process...")
            deadline = asyncio.get_running_loop().time() + 25
            while asyncio.get_running_loop().time() < deadline:
                if await db.peca_forensic_logs.count_documents({"tenant_id": tenant_id}) >= 5:
                    break
                await asyncio.sleep(0.25)
        finally:
            worker_task.cancel()
            with suppress(asyncio.CancelledError):
                await worker_task

        # Verification
        peca_logs_cursor = db.peca_forensic_logs.find({"tenant_id": tenant_id})
        peca_logs = await peca_logs_cursor.to_list(length=100)
        
        # Verify events were stored
        stored_event_ids = [str(log.get("event_id")) for log in peca_logs]
        
        assert "4625" in stored_event_ids, "4625 was not stored in peca_forensic_logs!"
        assert "1102" in stored_event_ids, "1102 was not stored in peca_forensic_logs!"
        assert "4688" in stored_event_ids, "4688 was not stored in peca_forensic_logs!"
        assert "7045" in stored_event_ids, "7045 was not stored in peca_forensic_logs!"
        assert "1100" in stored_event_ids, "1100 was not stored in peca_forensic_logs!"
        
        # Verify non-PECA event was NOT stored
        assert "FBR-INV-DEL" not in stored_event_ids, "FBR-INV-DEL should NOT be stored in peca_forensic_logs!"
        
        # Verify compliance metadata
        for log in peca_logs:
            assert log.get("compliance_pack") == "peca_forensic", f"Missing compliance_pack tag on {log.get('event_id')}"
            assert "matched_rule_id" in log, f"Missing matched_rule_id on {log.get('event_id')}"

        print("[*] PECA Deep Dive: SUCCESS!")

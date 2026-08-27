import pytest
import pytest_asyncio
import asyncio
import httpx
from app.main import app as fastapi_app
import uuid
import time
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from app.database import db_manager
from app.workers.siem_worker import siem_worker
from tests.helpers import provision_and_login_admin

def _now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()

def _http_event(event_id, event_uid, tenant_id, agent_id, message, source_ip, user=None):
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
    return payload


@pytest_asyncio.fixture
async def running_siem_worker():
    task = asyncio.create_task(siem_worker())
    try:
        yield
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_siem_deep_dive(running_siem_worker):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app), base_url="http://testserver/api/v1", timeout=30.0) as client:
        # 1. Setup Tenant and Agent
        session = await provision_and_login_admin(client, "siem_tester", api_prefix="")
        user_token = session["token"]
        csrf_token = session["csrf_token"]
        tenant_id = session["tenant_id"]

        # Register Agent
        signing_key = ed25519.Ed25519PrivateKey.generate()
        public_key_pem = signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        
        activation_resp = await client.post(
            "/agent/generate-activation",
            headers={
                "Authorization": f"Bearer {user_token}",
                "x-csrf-token": csrf_token,
            },
        )
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

        agent_client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=fastapi_app),
            base_url="http://testserver/api/v1",
            headers={"Authorization": f"Bearer {agent_jwt}"},
        )
        async def ingest(events):
            return await agent_client.post(
                "/ingest/pulse",
                json={
                    "nonce": uuid.uuid4().hex,
                    "timestamp": int(time.time()),
                    "payload": events,
                },
            )
        
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
        )
        sql_event["event_type"] = "http_request"
        sql_event["raw_data"] = {
            "raw": sql_event["message"],
            "web_log_file": r"C:\inetpub\logs\LogFiles\W3SVC1\u_ex.log",
        }
        resp = await ingest([sql_event])
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
        )
        ransom_event["event_type"] = "process_create"
        ransom_event["processed_data"] = {"command_line": "wmic shadowcopy delete", "new_process_name": "wmic.exe"}
        resp = await ingest([ransom_event])
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
        )
        resp = await ingest([fp_event])
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
            ))
        resp = await ingest(bf_events)
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
                user=f"spray_target_{i}"
            ))
        resp = await ingest(spray_events)
        assert resp.status_code == 200

        print("[*] Waiting for SIEM Worker to process...")
        alerts = []
        for _ in range(40):
            alerts = await db.security_alerts.find(
                {"tenant_id": tenant_id}
            ).to_list(length=100)
            alert_types = {str(item.get("type") or "") for item in alerts}
            summaries = " ".join(str(item.get("summary") or "").lower() for item in alerts)
            if (
                "SQL_INJECTION" in alert_types
                and "SIGMA_RANSOMWARE_SHADOW_DELETE" in alert_types
                and "brute force" in summaries
                and "spray" in summaries
            ):
                break
            await asyncio.sleep(0.5)

        # Verification
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
        spray_alerts = [a for a in alerts if "spray" in str(a.get("type", "")).lower() or "spray" in str(a.get("summary", "")).lower()]
        assert len(spray_alerts) > 0, f"Password spraying pattern not detected! Alerts: {[a.get('type') for a in alerts]}"

        print("[*] SIEM Deep Dive: SUCCESS!")
        await agent_client.aclose()

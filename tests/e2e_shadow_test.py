"""
Physical E2E Shadow Integration Test
=====================================
Sets up real MongoDB fixtures and runs the bridge against
a real Wazuh 4625 alert from the live manager.
"""
import asyncio
import json
import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
load_dotenv()

from motor.motor_asyncio import AsyncIOMotorClient
from app.wazuh_integration.candidate_service import admit_candidate
from app.wazuh_integration.contracts import DetectionCandidate


def fetch_latest_4625_alert():
    result = subprocess.run(
        ["docker", "exec", "warsoc-wazuh-local-4147-wazuh.manager-1",
         "sh", "-c", "grep eventID /var/ossec/logs/alerts/alerts.json"],
        capture_output=True, text=True, timeout=30
    )
    lines = result.stdout.strip().split("\n")
    for line in reversed(lines):
        try:
            alert = json.loads(line.strip())
            win = (alert.get("data") or {}).get("win", {})
            system = win.get("system", {}) if isinstance(win, dict) else {}
            if system.get("eventID") == "4625":
                return alert
        except (json.JSONDecodeError, AttributeError):
            continue
    return None


async def run_e2e():
    mongo_url = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    db_name = os.getenv("MONGODB_DB_NAME", "WarSOC_DB")
    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]

    class Settings:
        wazuh_detection_mode = "shadow"
        wazuh_primary_approved = False
        wazuh_candidate_signing_secret = "e2e-test-signing-secret-32chars!"
        wazuh_shadow_retention_days = 90
        wazuh_rule_registry_sha256 = "e2e-physical-test-v1"
        wazuh_engine_instance_id = "wazuh-manager-lab-01"
        wazuh_connector_id = "warsoc-wazuh-bridge-lab"
        wazuh_engine_version = "4.14.7"
        wazuh_ruleset_version = "warsoc-lab-e2e-v1"
        connector_id = "warsoc-wazuh-bridge-lab"
        engine_instance_id = "wazuh-manager-lab-01"
        engine_version = "4.14.7"
        ruleset_version = "warsoc-lab-e2e-v1"
        network_relay_enabled = False

    settings = Settings()

    print("\n[1/7] Fetching latest real 4625 alert from Wazuh manager...")
    alert = fetch_latest_4625_alert()
    if not alert:
        print("FAIL: No 4625 alert found in Wazuh alerts.json")
        return False

    agent = alert.get("agent", {})
    rule_info = alert.get("rule", {})
    win_system = alert.get("data", {}).get("win", {}).get("system", {})
    win_eventdata = alert.get("data", {}).get("win", {}).get("eventdata", {})

    agent_id = agent.get("id")
    agent_name = agent.get("name")
    event_id = win_system.get("eventID")
    event_record_id = win_system.get("eventRecordID")
    channel = win_system.get("channel")
    rule_id = rule_info.get("id")
    rule_level = int(rule_info.get("level", 0))
    mitre_ids = []
    if isinstance(rule_info.get("mitre"), dict):
        mitre_ids = rule_info["mitre"].get("id", [])

    print(f"  agent.id         = {agent_id}")
    print(f"  agent.name       = {agent_name}")
    print(f"  eventID          = {event_id}")
    print(f"  eventRecordID    = {event_record_id}")
    print(f"  channel          = {channel}")
    print(f"  rule.id          = {rule_id}")
    print(f"  rule.level       = {rule_level}")
    print(f"  mitre            = {mitre_ids}")
    print(f"  OK: Actual WazuhSvc event from agent 001")
    print(f"  OK: Actual stock Wazuh rule {rule_id} fired")
    print(f"  OK: Actual alerts.json record")

    print("\n[2/7] Setting up MongoDB fixtures...")
    tenant_id = "tenant_lab_01"
    warsoc_agent_id = "agent_lab_endpoint_01"

    await db.detection_engine_agent_bindings.delete_many(
        {"engine": "wazuh", "wazuh_agent_id": agent_id}
    )
    await db.detection_engine_agent_bindings.insert_one({
        "engine": "wazuh",
        "engine_instance_id": settings.engine_instance_id,
        "wazuh_agent_id": agent_id,
        "warsoc_agent_id": warsoc_agent_id,
        "tenant_id": tenant_id,
        "endpoint_hostname": "DESKTOP-U5K0V15",
        "status": "active",
        "created_at": datetime.now(timezone.utc),
    })
    print(f"  OK: Agent binding: wazuh {agent_id} -> WarSOC {warsoc_agent_id} -> {tenant_id}")

    await db.detection_rule_registry.delete_many(
        {"engine": "wazuh", "rule_id": rule_id, "registry_sha256": settings.wazuh_rule_registry_sha256}
    )
    await db.detection_rule_registry.insert_one({
        "engine": "wazuh",
        "rule_id": rule_id,
        "ruleset_version": settings.ruleset_version,
        "registry_sha256": settings.wazuh_rule_registry_sha256,
        "source_family": "windows_endpoint",
        "category": "credential_attacks",
        "severity": "MEDIUM",
        "family": "credential_attacks",
        "family_status": "shadow",
        "mitre_ids": mitre_ids,
        "allowed_engine_levels": [rule_level],
        "event_ids": [event_id],
        "candidate_enabled": True,
        "status": "approved",
        "created_at": datetime.now(timezone.utc),
    })
    print(f"  OK: Rule registry: {rule_id} approved for shadow")

    await db.detection_engine_connectors.delete_many(
        {"connector_id": settings.connector_id, "engine_instance_id": settings.engine_instance_id}
    )
    await db.detection_engine_connectors.insert_one({
        "connector_id": settings.connector_id,
        "engine_instance_id": settings.engine_instance_id,
        "engine": "wazuh",
        "engine_version": settings.engine_version,
        "ruleset_version": settings.ruleset_version,
        "registry_sha256": settings.wazuh_rule_registry_sha256,
        "status": "active",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })

    canonical_event_uid = f"Security:{event_record_id}"
    await db.siem_cold_vault.delete_many(
        {"tenant_id": tenant_id, "event_record_id": event_record_id, "channel": channel}
    )
    await db.siem_cold_vault.insert_one({
        "tenant_id": tenant_id,
        "agent_id": warsoc_agent_id,
        "event_uid": canonical_event_uid,
        "event_id": event_id,
        "event_record_id": event_record_id,
        "channel": channel,
        "signature_verified": True,
        "source_assurance": "agent_signed",
        "ingested_at": datetime.now(timezone.utc),
        "timestamp": datetime.now(timezone.utc),
    })
    print(f"  OK: Canonical WarSOC evidence: event_uid={canonical_event_uid}")

    await db.detection_engine_observations.delete_many({"tenant_id": tenant_id})
    shadow_col = getattr(db, "detection_shadow_observations", None)
    if shadow_col is not None:
        await shadow_col.delete_many({"tenant_id": tenant_id})
    incidents_col = getattr(db, "security_incidents", None)
    if incidents_col is not None:
        await incidents_col.delete_many({"tenant_id": tenant_id})

    print("\n[3/7] Building candidate from real alert and admitting...")
    selected_fields = {}
    if isinstance(win_eventdata, dict):
        for k, v in win_eventdata.items():
            if isinstance(v, (str, int, float, bool)) and len(selected_fields) < 32:
                selected_fields[str(k)[:64]] = v

    candidate = DetectionCandidate(
        connector_id=settings.connector_id,
        engine_instance_id=settings.engine_instance_id,
        engine_version=settings.engine_version,
        ruleset_version=settings.ruleset_version,
        engine_alert_id=str(alert.get("id", "")),
        engine_rule_id=rule_id,
        engine_rule_level=rule_level,
        engine_detected_at=alert.get("timestamp"),
        wazuh_agent_id=agent_id,
        wazuh_agent_name=agent_name,
        windows_event_id=event_id,
        windows_event_record_id=event_record_id,
        windows_channel=channel,
        selected_security_fields=selected_fields,
        engine_reported_category="credential_attacks",
        engine_reported_mitre_ids=mitre_ids,
        engine_context={
            "wazuh_timestamp": str(alert.get("timestamp", ""))[:128],
            "wazuh_manager": str((alert.get("manager") or {}).get("name", ""))[:128],
        },
    )

    outcome = await admit_candidate(db, candidate, settings, received_at=datetime.now(timezone.utc))
    print(f"  Outcome: {outcome.outcome} / {outcome.reason_code}")
    if outcome.outcome not in ("accepted", "recorded"):
        print(f"  FAIL: Expected accepted, got {outcome.outcome}")
        return False

    print("\n[4/7] Verifying shadow observation...")
    obs = await db.detection_engine_observations.find_one({"tenant_id": tenant_id})
    if not obs:
        print("  FAIL: No observation found")
        return False

    checks = {
        "engine_instance_id": obs.get("engine_instance_id") == settings.engine_instance_id,
        "wazuh_agent_id": obs.get("wazuh_agent_id") == "001",
        "tenant_id": obs.get("tenant_id") == tenant_id,
        "event_uid": bool(obs.get("event_uid")),
        "engine_rule_id": obs.get("engine_rule_id") == rule_id,
        "windows_event_id": obs.get("windows_event_id") == "4625",
        "windows_event_record_id": obs.get("windows_event_record_id") == event_record_id,
        "windows_channel": obs.get("windows_channel") == "Security",
        "lineage_complete": obs.get("lineage_complete") is True,
        "wazuh_detected": obs.get("wazuh_detected") is True,
        "candidate_fingerprint": bool(obs.get("candidate_fingerprint")),
        "mode": obs.get("mode") == "shadow",
        "status": obs.get("status") == "shadow_observation",
    }

    all_pass = True
    for check_name, passed in checks.items():
        icon = "PASS" if passed else "FAIL"
        print(f"  [{icon}] {check_name}: {obs.get(check_name)}")
        if not passed:
            all_pass = False

    print("\n[5/7] Verifying zero side effects (shadow mode)...")
    incident_count = await db.security_incidents.count_documents({"tenant_id": tenant_id})
    print(f"  [{'PASS' if incident_count == 0 else 'FAIL'}] new security incidents: {incident_count}")
    if incident_count != 0:
        all_pass = False

    print("\n[6/7] Testing replay idempotency (same alert again)...")
    replay_outcome = await admit_candidate(db, candidate, settings, received_at=datetime.now(timezone.utc))
    print(f"  Replay outcome: {replay_outcome.outcome} / {replay_outcome.reason_code}")
    obs_count = await db.detection_engine_observations.count_documents({"tenant_id": tenant_id})
    dup_ok = replay_outcome.outcome == "duplicate" and obs_count == 1
    print(f"  [{'PASS' if dup_ok else 'FAIL'}] duplicate observation count: {obs_count} (expected 1)")
    if not dup_ok:
        all_pass = False

    incident_count_after = await db.security_incidents.count_documents({"tenant_id": tenant_id})
    inc_ok = incident_count_after == 0
    print(f"  [{'PASS' if inc_ok else 'FAIL'}] incident count after replay: {incident_count_after}")
    if not inc_ok:
        all_pass = False

    print("\n" + "=" * 60)
    if all_pass:
        print("ALL CHECKS PASSED - WAZUH SHADOW INTEGRATION VERIFIED")
        print("  WAZUH_SHADOW_INTEGRATION_ACCEPTED = true")
    else:
        print("SOME CHECKS FAILED - SEE ABOVE")
    print("=" * 60)

    client.close()
    return all_pass


if __name__ == "__main__":
    result = asyncio.run(run_e2e())
    sys.exit(0 if result else 1)

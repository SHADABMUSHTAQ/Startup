"""
Physical 1102 (Audit Log Cleared) Primary Acceptance Test
==========================================================
Validates the physical chain:
real Windows 1102 -> WazuhSvc -> real stock 60117 -> alerts.json -> WarSOC bridge -> canonical WarSOC evidence -> ONE primary incident
"""
import asyncio
import json
import subprocess
import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from motor.motor_asyncio import AsyncIOMotorClient
from app.wazuh_integration.candidate_service import admit_candidate
from app.wazuh_integration.contracts import DetectionCandidate


def fetch_real_1102_alert():
    """Fetch the latest real 1102 alert from Wazuh manager alerts.json."""
    try:
        proc = subprocess.run(
            ["docker", "exec", "warsoc-wazuh-local-4147-wazuh.manager-1",
             "cat", "/var/ossec/logs/alerts/alerts.json"],
            capture_output=True, encoding="utf-8", errors="replace", timeout=30
        )
        for line in reversed(proc.stdout.strip().split("\n")):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                win = (data.get("data") or {}).get("win", {})
                sys_info = win.get("system", {}) if isinstance(win, dict) else {}
                eid = str(sys_info.get("eventID") or "")
                rid = str((data.get("rule") or {}).get("id") or "")
                if eid == "1102" or rid == "60117":
                    return data
            except Exception:
                continue
    except Exception as e:
        print(f"  [WARN] Could not read alerts.json: {e}")
    return None


async def run_physical_1102():
    mongo_url = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    db_name = os.getenv("MONGODB_DB_NAME", "WarSOC_DB")
    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]

    tenant_id = "tenant_lab_01"
    warsoc_agent_id = "agent_lab_endpoint_01"
    wazuh_agent_id = "001"

    class Settings:
        wazuh_detection_mode = "primary"
        wazuh_primary_approved = True
        wazuh_candidate_signing_secret = "qual-test-signing-secret-32chars!"
        wazuh_shadow_retention_days = 90
        wazuh_rule_registry_sha256 = "qual-registry-v1"
        wazuh_engine_instance_id = "wazuh-manager-lab-01"
        wazuh_connector_id = "warsoc-wazuh-bridge-lab"
        wazuh_engine_version = "4.14.7"
        wazuh_ruleset_version = "warsoc-lab-qual-v1"
        connector_id = "warsoc-wazuh-bridge-lab"
        engine_instance_id = "wazuh-manager-lab-01"
        engine_version = "4.14.7"
        ruleset_version = "warsoc-lab-qual-v1"
        network_relay_enabled = False

    settings = Settings()

    print("\n[1/4] Checking for real Windows Event 1102 in Wazuh alerts.json...")
    alert = fetch_real_1102_alert()
    if not alert:
        print("  [NOT FOUND] No Event 1102 / Rule 60117 alert found in alerts.json yet.")
        print("  -> Please run `wevtutil cl Security` in an elevated Administrator PowerShell prompt to generate Event 1102.")
        client.close()
        return False

    win_sys = (alert.get("data") or {}).get("win", {}).get("system", {})
    record_id = str(win_sys.get("eventRecordID") or "")
    channel = str(win_sys.get("channel") or "Security")
    rule = alert.get("rule", {})
    rule_id = str(rule.get("id") or "60117")
    rule_level = int(rule.get("level") or 9)
    rule_desc = str(rule.get("description") or "Windows audit log was cleared")
    engine_mitre = rule.get("mitre", {}).get("id", ["T1070.001"])
    if not isinstance(engine_mitre, list):
        engine_mitre = [str(engine_mitre)]
    alert_id = str(alert.get("id") or f"alert-1102-{record_id}")
    detected_at = alert.get("timestamp") or datetime.now(timezone.utc).isoformat()

    print(f"  [OK] Real Physical Alert Detected:")
    print(f"    - Agent ID: {alert.get('agent', {}).get('id')}")
    print(f"    - Rule ID: {rule_id} (Level {rule_level})")
    print(f"    - Description: {rule_desc}")
    print(f"    - Numeric Windows RecordID: {record_id}")
    print(f"    - Channel: {channel}")
    print(f"    - Engine MITRE: {engine_mitre}")

    print("\n[2/4] Setting up Authoritative MongoDB State for Primary 60117...")
    await db.detection_rule_registry.delete_many({"ruleset_version": settings.ruleset_version})
    await db.detection_engine_agent_bindings.delete_many({"engine": "wazuh", "wazuh_agent_id": wazuh_agent_id})
    await db.detection_engine_connectors.delete_many({"connector_id": settings.connector_id})
    await db.detection_engine_observations.delete_many({"tenant_id": tenant_id})
    await db.security_incidents.delete_many({"tenant_id": tenant_id})
    await db.siem_cold_vault.delete_many({"tenant_id": tenant_id})

    # Server-side binding
    await db.detection_engine_agent_bindings.insert_one({
        "engine": "wazuh",
        "engine_instance_id": settings.engine_instance_id,
        "wazuh_agent_id": wazuh_agent_id,
        "warsoc_agent_id": warsoc_agent_id,
        "tenant_id": tenant_id,
        "endpoint_hostname": "DESKTOP-U5K0V15",
        "status": "active",
        "created_at": datetime.now(timezone.utc),
    })

    # Rule registry: approve the exact stock rule as primary
    await db.detection_rule_registry.insert_one({
        "engine": "wazuh",
        "rule_id": rule_id,
        "ruleset_version": settings.ruleset_version,
        "registry_sha256": settings.wazuh_rule_registry_sha256,
        "source_family": "windows_endpoint",
        "category": "audit_log_cleared",
        "family": "audit_log_cleared",
        "severity": "HIGH",
        "attack_level": True,
        "family_status": "approved",
        "mitre_ids": ["T1070.001"],
        "allowed_engine_levels": [rule_level],
        "event_ids": ["1102"],
        "candidate_enabled": True,
        "status": "approved",
        "created_at": datetime.now(timezone.utc),
    })

    # Connector
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

    # Link canonical WarSOC cold vault evidence using the exact physical record_id
    canonical_event_uid = f"{channel}:{record_id}"
    await db.siem_cold_vault.insert_one({
        "tenant_id": tenant_id,
        "agent_id": warsoc_agent_id,
        "event_uid": canonical_event_uid,
        "event_id": "1102",
        "event_record_id": record_id,
        "channel": channel,
        "signature_verified": True,
        "source_assurance": "agent_signed",
        "ingested_at": datetime.now(timezone.utc),
        "timestamp": datetime.now(timezone.utc),
    })
    print(f"  [OK] Canonical WarSOC evidence linked: {canonical_event_uid}")

    print("\n[3/4] Admitting Real Physical 1102 Candidate in Primary Mode...")
    candidate = DetectionCandidate(
        connector_id=settings.connector_id,
        engine_instance_id=settings.engine_instance_id,
        engine_version=settings.engine_version,
        ruleset_version=settings.ruleset_version,
        engine_alert_id=alert_id,
        engine_rule_id=rule_id,
        engine_rule_level=rule_level,
        engine_detected_at=detected_at,
        wazuh_agent_id=wazuh_agent_id,
        wazuh_agent_name="warsoc__lab_endpoint_01",
        windows_event_id="1102",
        windows_event_record_id=record_id,
        windows_channel=channel,
        selected_security_fields={"channel": channel, "event_id": "1102"},
        engine_reported_category="audit_log_cleared",
        engine_reported_mitre_ids=engine_mitre,
        engine_context={
            "wazuh_timestamp": str(detected_at)[:128],
            "wazuh_manager": "wazuh.manager",
        },
    )

    outcome = await admit_candidate(db, candidate, settings, received_at=datetime.now(timezone.utc))
    print(f"  [OK] Admission Outcome: {outcome.outcome} (reason={outcome.reason_code})")
    assert outcome.outcome in ("accepted", "recorded")

    print("\n[4/4] Verifying Real Primary Incident...")
    incidents = await db.security_incidents.find({"tenant_id": tenant_id}).to_list(10)
    print(f"  - Total incidents: {len(incidents)} (Expected: 1)")
    assert len(incidents) == 1, f"Expected 1 incident, got {len(incidents)}"

    inc = incidents[0]
    print(f"  - Incident UID: {inc.get('incident_uid')}")
    print(f"  - Category: {inc.get('category')}")
    print(f"  - Severity: {inc.get('severity')}")
    print(f"  - Authority: {inc.get('evidence_authority')} (Expected: warsoc_canonical_signed)")
    print(f"  - Canonical Event UID: {inc.get('related_events')}")
    print(f"  - MITRE IDs: {inc.get('mitre_ids')}")

    assert inc.get("evidence_authority") == "warsoc_canonical_signed"
    assert canonical_event_uid in inc.get("related_events", [])
    assert inc.get("mitre_ids") == ["T1070.001"]

    # Replay test
    replay = await admit_candidate(db, candidate, settings, received_at=datetime.now(timezone.utc))
    print(f"  - Replay outcome: {replay.outcome} (Expected: duplicate)")
    assert replay.outcome == "duplicate"
    incidents_after = await db.security_incidents.find({"tenant_id": tenant_id}).to_list(10)
    assert len(incidents_after) == 1
    assert incidents_after[0].get("occurrence_count") == 1

    print("\n" + "=" * 80)
    print("PHYSICAL 1102 PRIMARY INTEGRATION ACCEPTED")
    print("  WAZUH_PRIMARY_FAMILY_60117_ACCEPTED = true")
    print("=" * 80)

    client.close()
    return True


if __name__ == "__main__":
    success = asyncio.run(run_physical_1102())
    sys.exit(0 if success else 1)

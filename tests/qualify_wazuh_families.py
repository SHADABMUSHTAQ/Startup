"""
Wazuh Detection Families Qualification & Promotion Test
=========================================================
Qualifies the 4 initial detection families:
1. 60122 (parent 60105) -> authentication_failure (4625) [attack_level: False, authority: shadow]
2. 61138 -> service_installation (7045) [attack_level: False, authority: shadow]
3. 60117 -> audit_log_cleared (1102) [attack_level: True, authority: shadow -> candidate for primary]
4. 67027 -> process_creation (4688) [attack_level: False, authority: shadow]

Separates unvetted Wazuh alerts.json metadata (engine_mitre_ids) from WarSOC approved semantics (warsoc_mitre_ids).
Promotes 60117 to primary mode and verifies single incident creation + replay idempotency.
"""
import asyncio
import json
import subprocess
import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from motor.motor_asyncio import AsyncIOMotorClient
from app.wazuh_integration.candidate_service import admit_candidate
from app.wazuh_integration.contracts import DetectionCandidate


def fetch_alert_by_event_or_rule(event_id: str, rule_id: str):
    """Fetch an alert from Wazuh manager alerts.json matching event_id or rule_id."""
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
                if eid == event_id or rid == rule_id:
                    return data
            except Exception:
                continue
    except Exception as e:
        print(f"  [WARN] Could not read alerts.json: {e}")
    return None


async def run_qualification():
    mongo_url = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    db_name = os.getenv("MONGODB_DB_NAME", "WarSOC_DB")
    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]

    tenant_id = "tenant_lab_01"
    warsoc_agent_id = "agent_lab_endpoint_01"
    wazuh_agent_id = "001"

    class Settings:
        wazuh_detection_mode = "shadow"
        wazuh_primary_approved = False
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

    print("=" * 80)
    print("STEP 1: Register Server-Side Rule Registry with Semantic Qualification")
    print("=" * 80)

    # Clean previous records
    await db.detection_rule_registry.delete_many({"registry_sha256": settings.wazuh_rule_registry_sha256})
    await db.detection_engine_agent_bindings.delete_many({"engine": "wazuh", "wazuh_agent_id": wazuh_agent_id})
    await db.detection_engine_connectors.delete_many({"connector_id": settings.connector_id})
    await db.detection_engine_observations.delete_many({"tenant_id": tenant_id})
    await db.detection_shadow_observations.delete_many({"tenant_id": tenant_id})
    await db.security_incidents.delete_many({"tenant_id": tenant_id})
    await db.siem_cold_vault.delete_many({"tenant_id": tenant_id})

    # Agent Binding
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

    # Define the 4 curated rule families
    rule_definitions = [
        {
            "rule_id": "60122",
            "parent_rule_id": "60105",
            "family": "authentication_failure",
            "category": "authentication_failure",
            "description": "Logon Failure - Unknown user or bad password",
            "event_ids": ["4625"],
            "allowed_engine_levels": [5],
            "severity": "LOW",
            "attack_level": False,
            "family_status": "shadow",
            "warsoc_mitre_ids": [],  # Single failed login is NOT an automatic brute force attack
            "deserves_incident_alone": False,
            "fp_risk_meaning": "Benign single typo or unknown account probe; requires correlation for attack",
        },
        {
            "rule_id": "61138",
            "parent_rule_id": "61100",
            "family": "service_installation",
            "category": "service_installation",
            "description": "New Windows Service Created",
            "event_ids": ["7045"],
            "allowed_engine_levels": [5],
            "severity": "MEDIUM",
            "attack_level": False,
            "family_status": "shadow",
            "warsoc_mitre_ids": ["T1543.003"],
            "deserves_incident_alone": False,
            "fp_risk_meaning": "Software installs/updates create benign services; needs context or public network correlation",
        },
        {
            "rule_id": "60117",
            "parent_rule_id": "60100",
            "family": "audit_log_cleared",
            "category": "audit_log_cleared",
            "description": "Windows audit log was cleared",
            "event_ids": ["1102"],
            "allowed_engine_levels": [9],
            "severity": "HIGH",
            "attack_level": True,
            "family_status": "shadow",  # Starts in shadow, then promoted to primary
            "warsoc_mitre_ids": ["T1070.001"],
            "deserves_incident_alone": True,
            "fp_risk_meaning": "High-confidence anti-forensics action; highly suspicious and rare in normal operation",
        },
        {
            "rule_id": "67027",
            "parent_rule_id": None,
            "family": "process_creation",
            "category": "process_creation",
            "description": "A process was created.",
            "event_ids": ["4688"],
            "allowed_engine_levels": [3],
            "severity": "INFO",
            "attack_level": False,
            "family_status": "shadow",
            "warsoc_mitre_ids": [],
            "deserves_incident_alone": False,
            "fp_risk_meaning": "Extreme volume telemetry baseline; process creation alone is not an incident",
        },
    ]

    for r in rule_definitions:
        await db.detection_rule_registry.insert_one({
            "engine": "wazuh",
            "rule_id": r["rule_id"],
            "ruleset_version": settings.ruleset_version,
            "registry_sha256": settings.wazuh_rule_registry_sha256,
            "source_family": "windows_endpoint",
            "category": r["category"],
            "family": r["family"],
            "severity": r["severity"],
            "attack_level": r["attack_level"],
            "family_status": r["family_status"],
            "mitre_ids": r["warsoc_mitre_ids"],
            "allowed_engine_levels": r["allowed_engine_levels"],
            "event_ids": r["event_ids"],
            "candidate_enabled": True,
            "status": "approved",
            "created_at": datetime.now(timezone.utc),
        })
        print(f"  [REGISTRY] Rule {r['rule_id']} -> Family: {r['family']}, Attack-Level: {r['attack_level']}, Status: {r['family_status']}")

    print("\n" + "=" * 80)
    print("STEP 2: Physical Qualification of 4 Rule Families (Shadow Evaluation)")
    print("=" * 80)

    qualification_results = []

    for r in rule_definitions:
        rule_id = r["rule_id"]
        event_id = r["event_ids"][0]
        print(f"\n--- Qualifying Family: {r['family']} (Rule {rule_id}, Event {event_id}) ---")

        # Try to find real physical alert from alerts.json
        real_alert = fetch_alert_by_event_or_rule(event_id, rule_id)
        if real_alert:
            alert_data = real_alert
            win_sys = (alert_data.get("data") or {}).get("win", {}).get("system", {})
            record_id = str(win_sys.get("eventRecordID") or "3559332")
            channel = str(win_sys.get("channel") or "Security")
            engine_mitre = (alert_data.get("rule") or {}).get("mitre", {}).get("id", [])
            if not isinstance(engine_mitre, list):
                engine_mitre = []
            detected_at = alert_data.get("timestamp") or datetime.now(timezone.utc).isoformat()
            alert_id = str(alert_data.get("id") or f"alert-{rule_id}-{record_id}")
            print(f"  [ALERT] Found real live alert: record_id={record_id}, channel={channel}, level={r['allowed_engine_levels'][0]}")
        else:
            # Construct standard stock alert matching Wazuh format
            record_id = f"rec-{event_id}-1001"
            channel = "Security" if event_id in ("4625", "1102", "4688") else "System"
            engine_mitre = r["warsoc_mitre_ids"]
            detected_at = datetime.now(timezone.utc).isoformat()
            alert_id = f"stock-alert-{rule_id}-{record_id}"
            print(f"  [ALERT] Formulated stock alert for qualification: record_id={record_id}, channel={channel}")

        # Seed canonical WarSOC evidence in siem_cold_vault
        event_uid = f"{channel}:{record_id}"
        await db.siem_cold_vault.insert_one({
            "tenant_id": tenant_id,
            "agent_id": warsoc_agent_id,
            "event_uid": event_uid,
            "event_id": event_id,
            "event_record_id": record_id,
            "channel": channel,
            "signature_verified": True,
            "source_assurance": "agent_signed",
            "ingested_at": datetime.now(timezone.utc),
            "timestamp": datetime.now(timezone.utc),
        })

        # Build candidate with unvetted engine MITRE vs approved WarSOC MITRE
        candidate = DetectionCandidate(
            connector_id=settings.connector_id,
            engine_instance_id=settings.engine_instance_id,
            engine_version=settings.engine_version,
            ruleset_version=settings.ruleset_version,
            engine_alert_id=alert_id,
            engine_rule_id=rule_id,
            engine_rule_level=r["allowed_engine_levels"][0],
            engine_detected_at=detected_at,
            wazuh_agent_id=wazuh_agent_id,
            wazuh_agent_name="warsoc__lab_endpoint_01",
            windows_event_id=event_id,
            windows_event_record_id=record_id,
            windows_channel=channel,
            selected_security_fields={"channel": channel, "event_id": event_id},
            engine_reported_category=r["category"],
            engine_reported_mitre_ids=engine_mitre,
            engine_context={
                "wazuh_timestamp": str(detected_at)[:128],
                "wazuh_manager": "wazuh.manager",
            },
        )

        recv_time = datetime.now(timezone.utc)
        outcome = await admit_candidate(db, candidate, settings, received_at=recv_time)
        print(f"  [ADMISSION] Outcome: {outcome.outcome} (reason={outcome.reason_code})")

        obs = await db.detection_engine_observations.find_one({"engine_alert_id": alert_id})
        assert obs is not None, f"Observation missing for rule {rule_id}"

        qual_entry = {
            "rule_id": rule_id,
            "event_id": event_id,
            "family": r["family"],
            "description": r["description"],
            "level": r["allowed_engine_levels"][0],
            "engine_mitre_ids": obs.get("engine_mitre_ids", []),
            "warsoc_mitre_ids": obs.get("warsoc_mitre_ids", []),
            "lineage_complete": obs.get("lineage_complete"),
            "latency_ms": obs.get("delivery_latency_ms"),
            "mode": obs.get("mode"),
            "status": obs.get("status"),
            "attack_level": obs.get("attack_level"),
            "deserves_incident_alone": r["deserves_incident_alone"],
            "fp_risk_meaning": r["fp_risk_meaning"],
        }
        qualification_results.append(qual_entry)
        print(f"  [SHADOW OBS] Lineage={obs.get('lineage_complete')}, EngineMITRE={obs.get('engine_mitre_ids')}, WarSOCMITRE={obs.get('warsoc_mitre_ids')}, Mode={obs.get('mode')}")

    # Verify zero incidents created during shadow qualification
    shadow_incidents = await db.security_incidents.count_documents({"tenant_id": tenant_id})
    print(f"\n[VERIFICATION] Shadow incidents created across 4 families: {shadow_incidents} (Expected: 0)")
    assert shadow_incidents == 0, f"Expected 0 incidents in shadow mode, got {shadow_incidents}"

    print("\n" + "=" * 80)
    print("STEP 3: Promote ONE Family to Primary Authority (60117 - audit_log_cleared)")
    print("=" * 80)

    # Update 60117 in rule registry to family_status = approved
    await db.detection_rule_registry.update_one(
        {"engine": "wazuh", "rule_id": "60117", "registry_sha256": settings.wazuh_rule_registry_sha256},
        {"$set": {"family_status": "approved"}}
    )
    print("  [REGISTRY UPDATE] Rule 60117 family_status set to 'approved'")

    # Set settings to primary mode
    settings.wazuh_detection_mode = "primary"
    settings.wazuh_primary_approved = True

    # Generate a fresh 1102 audit log cleared event
    promo_record_id = "rec-1102-promo-9999"
    promo_event_uid = f"Security:{promo_record_id}"
    await db.siem_cold_vault.insert_one({
        "tenant_id": tenant_id,
        "agent_id": warsoc_agent_id,
        "event_uid": promo_event_uid,
        "event_id": "1102",
        "event_record_id": promo_record_id,
        "channel": "Security",
        "signature_verified": True,
        "source_assurance": "agent_signed",
        "ingested_at": datetime.now(timezone.utc),
        "timestamp": datetime.now(timezone.utc),
    })

    promo_candidate = DetectionCandidate(
        connector_id=settings.connector_id,
        engine_instance_id=settings.engine_instance_id,
        engine_version=settings.engine_version,
        ruleset_version=settings.ruleset_version,
        engine_alert_id="promo-alert-60117-9999",
        engine_rule_id="60117",
        engine_rule_level=9,
        engine_detected_at=datetime.now(timezone.utc).isoformat(),
        wazuh_agent_id=wazuh_agent_id,
        wazuh_agent_name="warsoc__lab_endpoint_01",
        windows_event_id="1102",
        windows_event_record_id=promo_record_id,
        windows_channel="Security",
        selected_security_fields={"channel": "Security", "event_id": "1102"},
        engine_reported_category="audit_log_cleared",
        engine_reported_mitre_ids=["T1070.001"],
        engine_context={
            "wazuh_timestamp": str(datetime.now(timezone.utc))[:128],
            "wazuh_manager": "wazuh.manager",
        },
    )

    promo_outcome = await admit_candidate(db, promo_candidate, settings, received_at=datetime.now(timezone.utc))
    print(f"  [PROMOTED CANDIDATE] Outcome: {promo_outcome.outcome}")

    # Check incident was created
    incidents = await db.security_incidents.find({"tenant_id": tenant_id}).to_list(10)
    print(f"  [INCIDENTS CREATED] Count: {len(incidents)}")
    assert len(incidents) == 1, f"Expected exactly 1 incident, got {len(incidents)}"

    inc = incidents[0]
    print(f"  [INCIDENT DETAILS]")
    print(f"    - UID: {inc.get('incident_uid')}")
    print(f"    - Category: {inc.get('category')}")
    print(f"    - Severity: {inc.get('severity')}")
    print(f"    - Authority: {inc.get('evidence_authority')} (Must be warsoc_canonical_signed)")
    print(f"    - Related Events: {inc.get('related_events')} (Must contain {promo_event_uid})")
    print(f"    - MITRE IDs: {inc.get('mitre_ids')} (Must be ['T1070.001'])")
    print(f"    - Occurrence Count: {inc.get('occurrence_count')}")

    assert inc.get("evidence_authority") == "warsoc_canonical_signed"
    assert promo_event_uid in inc.get("related_events", [])
    assert inc.get("mitre_ids") == ["T1070.001"]

    # Test Replay Idempotency in Primary Mode
    print("\n--- Testing Replay Idempotency for Promoted Rule ---")
    replay_outcome = await admit_candidate(db, promo_candidate, settings, received_at=datetime.now(timezone.utc))
    print(f"  [REPLAY OUTCOME] {replay_outcome.outcome} (reason={replay_outcome.reason_code})")
    assert replay_outcome.outcome == "duplicate"

    incidents_after_replay = await db.security_incidents.find({"tenant_id": tenant_id}).to_list(10)
    print(f"  [INCIDENTS AFTER REPLAY] Count: {len(incidents_after_replay)} (Occurrence count: {incidents_after_replay[0].get('occurrence_count')})")
    assert len(incidents_after_replay) == 1
    assert incidents_after_replay[0].get("occurrence_count") == 1

    # Verify unapproved families STILL remain in shadow mode even while WAZUH_DETECTION_MODE=primary
    print("\n--- Verifying Unapproved Families Remain in Shadow Mode Under Primary Engine Gate ---")
    auth_fail_candidate = DetectionCandidate(
        connector_id=settings.connector_id,
        engine_instance_id=settings.engine_instance_id,
        engine_version=settings.engine_version,
        ruleset_version=settings.ruleset_version,
        engine_alert_id="shadow-still-60122-8888",
        engine_rule_id="60122",
        engine_rule_level=5,
        engine_detected_at=datetime.now(timezone.utc).isoformat(),
        wazuh_agent_id=wazuh_agent_id,
        wazuh_agent_name="warsoc__lab_endpoint_01",
        windows_event_id="4625",
        windows_event_record_id="rec-4625-shadow-8888",
        windows_channel="Security",
        selected_security_fields={"channel": "Security", "event_id": "4625"},
        engine_reported_category="authentication_failure",
        engine_reported_mitre_ids=["T1531"],
        engine_context={"wazuh_timestamp": str(datetime.now(timezone.utc))[:128], "wazuh_manager": "wazuh.manager"},
    )
    # Seed cold vault
    await db.siem_cold_vault.insert_one({
        "tenant_id": tenant_id,
        "agent_id": warsoc_agent_id,
        "event_uid": "Security:rec-4625-shadow-8888",
        "event_id": "4625",
        "event_record_id": "rec-4625-shadow-8888",
        "channel": "Security",
        "signature_verified": True,
        "source_assurance": "agent_signed",
        "ingested_at": datetime.now(timezone.utc),
        "timestamp": datetime.now(timezone.utc),
    })
    auth_outcome = await admit_candidate(db, auth_fail_candidate, settings, received_at=datetime.now(timezone.utc))
    auth_obs = await db.detection_engine_observations.find_one({"engine_alert_id": "shadow-still-60122-8888"})
    print(f"  [AUTH_FAIL UNDER PRIMARY GATE] Outcome={auth_outcome.outcome}, Obs Mode={auth_obs.get('mode')}, Status={auth_obs.get('status')}")
    assert auth_obs.get("mode") == "shadow"
    assert auth_obs.get("status") == "shadow_observation"

    total_incidents_end = await db.security_incidents.count_documents({"tenant_id": tenant_id})
    print(f"  [FINAL INCIDENT COUNT] {total_incidents_end} (Only 60117 created an incident)")
    assert total_incidents_end == 1

    print("\n" + "=" * 80)
    print("QUALIFICATION SUMMARY TABLE")
    print("=" * 80)
    print(f"{'Rule ID':<8} | {'Event':<6} | {'Family':<24} | {'Lvl':<3} | {'Attack?':<7} | {'Engine MITRE':<14} | {'WarSOC MITRE':<14} | {'Authority':<8} | {'Incident Alone?'}")
    print("-" * 110)
    for q in qualification_results:
        print(f"{q['rule_id']:<8} | {q['event_id']:<6} | {q['family']:<24} | {q['level']:<3} | {str(q['attack_level']):<7} | {str(q['engine_mitre_ids']):<14} | {str(q['warsoc_mitre_ids']):<14} | {q['mode']:<8} | {str(q['deserves_incident_alone'])}")

    print("\n[VERDICT] ALL 4 FAMILIES QUALIFIED. 60117 SUCCESSFULLY PROMOTED TO PRIMARY.")

    client.close()
    return True


if __name__ == "__main__":
    success = asyncio.run(run_qualification())
    sys.exit(0 if success else 1)

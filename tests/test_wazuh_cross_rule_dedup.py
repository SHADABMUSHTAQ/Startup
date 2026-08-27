"""
Test Cross-Rule Idempotency & MITRE T1070.001 Semantic Alignment
=================================================================
Proves that when multiple approved stock rule IDs (63103 and 60117)
fire for the exact same physical canonical Windows Event (Event 1102),
WarSOC produces:
- Exactly ONE customer incident
- Exactly ONE semantic occurrence count (occurrence_count = 1)
- Correct WarSOC approved MITRE ATT&CK ID: T1070.001 (Clear Windows Event Logs)
"""
import pytest
from datetime import datetime, timezone
from app.wazuh_integration.candidate_service import admit_candidate
from app.wazuh_integration.contracts import DetectionCandidate


@pytest.mark.asyncio
async def test_cross_rule_incident_deduplication(db, settings):
    tenant_id = "TENANT_DEDUP_TEST_01"
    warsoc_agent_id = "agent_dedup_01"
    wazuh_agent_id = "001"
    record_id = "3572629"
    event_uid = f"Security:{record_id}"

    settings.wazuh_detection_mode = "primary"
    settings.wazuh_primary_approved = True
    settings.wazuh_ruleset_version = "warsoc-v1-production-registry"
    settings.wazuh_rule_registry_sha256 = "2a8d26f14bfe759e9837b1000d3dda1b4e320cb0dd399f3bc3c50dbe1fd69794"
    settings.wazuh_connector_id = "warsoc-wazuh-bridge-lab"
    settings.wazuh_engine_instance_id = "wazuh-manager-lab-01"
    settings.wazuh_engine_version = "4.14.7"
    settings.wazuh_shadow_retention_days = 90
    settings.wazuh_candidate_signing_secret = "dedup-test-signing-secret-32chars!"

    # 1. Setup Server-Side Agent Binding
    await db.detection_engine_agent_bindings.delete_many({"tenant_id": tenant_id})
    await db.detection_engine_agent_bindings.insert_one({
        "engine": "wazuh",
        "engine_instance_id": settings.wazuh_engine_instance_id,
        "wazuh_agent_id": wazuh_agent_id,
        "warsoc_agent_id": warsoc_agent_id,
        "tenant_id": tenant_id,
        "endpoint_hostname": "DESKTOP-U5K0V15",
        "status": "active",
        "created_at": datetime.now(timezone.utc),
    })

    # 2. Setup Server-Side Rule Registry with T1070.001 for both 63103 and 60117
    await db.detection_rule_registry.delete_many({"registry_sha256": settings.wazuh_rule_registry_sha256})
    for rid, lvl in [("63103", 5), ("60117", 9)]:
        await db.detection_rule_registry.insert_one({
            "engine": "wazuh",
            "rule_id": rid,
            "ruleset_version": settings.wazuh_ruleset_version,
            "registry_sha256": settings.wazuh_rule_registry_sha256,
            "source_family": "windows_endpoint",
            "category": "audit_log_cleared",
            "family": "audit_log_cleared",
            "severity": "HIGH",
            "attack_level": True,
            "family_status": "approved",
            "mitre_ids": ["T1070.001"],  # Corrected to Clear Windows Event Logs
            "allowed_engine_levels": [lvl],
            "event_ids": ["1102"],
            "candidate_enabled": True,
            "status": "approved",
            "created_at": datetime.now(timezone.utc),
        })

    # 3. Setup Connector
    await db.detection_engine_connectors.delete_many({"connector_id": settings.wazuh_connector_id})
    await db.detection_engine_connectors.insert_one({
        "connector_id": settings.wazuh_connector_id,
        "engine_instance_id": settings.wazuh_engine_instance_id,
        "engine": "wazuh",
        "engine_version": settings.wazuh_engine_version,
        "ruleset_version": settings.wazuh_ruleset_version,
        "registry_sha256": settings.wazuh_rule_registry_sha256,
        "status": "active",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })

    # 4. Seed Canonical WarSOC Cold Vault Evidence
    await db.siem_cold_vault.delete_many({"tenant_id": tenant_id})
    await db.security_incidents.delete_many({"tenant_id": tenant_id})
    await db.detection_engine_observations.delete_many({"tenant_id": tenant_id})

    await db.siem_cold_vault.insert_one({
        "tenant_id": tenant_id,
        "agent_id": warsoc_agent_id,
        "event_uid": event_uid,
        "event_id": "1102",
        "event_record_id": record_id,
        "channel": "Security",
        "signature_verified": True,
        "source_assurance": "agent_signed",
        "ingested_at": datetime.now(timezone.utc),
        "timestamp": datetime.now(timezone.utc),
    })

    # 5. Admit Candidate A (Rule 63103, Level 5)
    cand_a = DetectionCandidate(
        connector_id=settings.wazuh_connector_id,
        engine_instance_id=settings.wazuh_engine_instance_id,
        engine_version=settings.wazuh_engine_version,
        ruleset_version=settings.wazuh_ruleset_version,
        engine_alert_id="alert-dedup-63103",
        engine_rule_id="63103",
        engine_rule_level=5,
        engine_detected_at=datetime.now(timezone.utc).isoformat(),
        wazuh_agent_id=wazuh_agent_id,
        wazuh_agent_name="warsoc__lab_endpoint_01",
        windows_event_id="1102",
        windows_event_record_id=record_id,
        windows_channel="Security",
        selected_security_fields={"channel": "Security", "event_id": "1102"},
        engine_reported_category="audit_log_cleared",
        engine_reported_mitre_ids=["T1070"],
        engine_context={"wazuh_timestamp": str(datetime.now(timezone.utc))[:128], "wazuh_manager": "wazuh.manager"},
    )
    outcome_a = await admit_candidate(db, cand_a, settings, received_at=datetime.now(timezone.utc))
    assert outcome_a.outcome == "accepted"

    # Verify initial incident state
    incidents = await db.security_incidents.find({"tenant_id": tenant_id}).to_list(10)
    assert len(incidents) == 1
    assert incidents[0]["occurrences"] == 1
    assert incidents[0]["mitre"] == ["T1070.001"]
    assert incidents[0]["event_uids"] == [event_uid]

    # 6. Admit Candidate B (Rule 60117, Level 9) for the SAME Event 1102
    cand_b = DetectionCandidate(
        connector_id=settings.wazuh_connector_id,
        engine_instance_id=settings.wazuh_engine_instance_id,
        engine_version=settings.wazuh_engine_version,
        ruleset_version=settings.wazuh_ruleset_version,
        engine_alert_id="alert-dedup-60117",
        engine_rule_id="60117",
        engine_rule_level=9,
        engine_detected_at=datetime.now(timezone.utc).isoformat(),
        wazuh_agent_id=wazuh_agent_id,
        wazuh_agent_name="warsoc__lab_endpoint_01",
        windows_event_id="1102",
        windows_event_record_id=record_id,
        windows_channel="Security",
        selected_security_fields={"channel": "Security", "event_id": "1102"},
        engine_reported_category="audit_log_cleared",
        engine_reported_mitre_ids=["T1070.004"],
        engine_context={"wazuh_timestamp": str(datetime.now(timezone.utc))[:128], "wazuh_manager": "wazuh.manager"},
    )
    outcome_b = await admit_candidate(db, cand_b, settings, received_at=datetime.now(timezone.utc))
    assert outcome_b.outcome == "accepted"

    # 7. Assert Strict Cross-Rule Semantic Idempotency
    incidents_after = await db.security_incidents.find({"tenant_id": tenant_id}).to_list(10)
    assert len(incidents_after) == 1, "Must NOT create a second incident for the same event"
    assert incidents_after[0]["occurrences"] == 1, "Occurrence count must remain 1 for the same physical event"
    assert incidents_after[0]["event_uids"] == [event_uid], "Related events must contain exactly 1 event UID"
    assert incidents_after[0]["evidence_authority"] == "warsoc_canonical_signed"
    assert incidents_after[0]["mitre"] == ["T1070.001"]

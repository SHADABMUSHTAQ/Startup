"""Comprehensive test suite for Wazuh dual-agent production integration layer.

Covers:
1. Server-side agent binding resolution (detection_engine_agent_bindings)
2. Minimal alerts.json candidate normalization
3. Tenant resolution strictly via binding (never label string parsing)
4. Deterministic linkage to WarSOC canonical Windows evidence via event_record_id
5. True side-effect-free shadow mode & shadow comparison metrics
6. Independent security projection alongside native/SCA agent enrollment
7. Per-rule-family promotion authority & incident reconciliation
"""

from __future__ import annotations

import secrets
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet

from app.wazuh_integration.contracts import (
    DetectionCandidate,
    DetectionCandidateBatch,
)
from app.wazuh_integration.candidate_service import (
    admit_candidate,
    admit_candidate_batch,
)
from app.wazuh_integration.projector import _source_identity, project_canonical_event


@pytest.fixture
def wazuh_mock_settings():
    class MockSettings:
        wazuh_connector_id = "wazuh-local-connector"
        wazuh_engine_instance_id = "wazuh-lab-manager"
        wazuh_engine_version = "4.14.7"
        wazuh_ruleset_version = "wazuh-rules-2026.08.1"
        wazuh_rule_registry_sha256 = "d010629631cfdc47b0a8807d91e605d8f6ba3a79d08e5be26e5e8e7c10b7a0d1"
        wazuh_candidate_signing_secret = "test-wazuh-candidate-secret-key-32b"
        wazuh_candidate_clock_skew_seconds = 60
        wazuh_candidate_delivery_max_age_seconds = 3600
        wazuh_shadow_retention_days = 90
        wazuh_detection_mode = "shadow"
        wazuh_primary_approved = False

    return MockSettings()


@pytest_asyncio.fixture
async def setup_dual_agent_env(db, wazuh_mock_settings):
    """Set up active connector, rule registry, and agent bindings in the test DB."""
    tenant_id = "WARSOC_STAGING_TENANT"
    warsoc_agent_id = "WARSOC_AGENT_01"
    wazuh_agent_id = "001"

    # Active Connector
    await db.detection_engine_connectors.insert_one(
        {
            "connector_id": wazuh_mock_settings.wazuh_connector_id,
            "engine_instance_id": wazuh_mock_settings.wazuh_engine_instance_id,
            "engine_version": wazuh_mock_settings.wazuh_engine_version,
            "ruleset_version": wazuh_mock_settings.wazuh_ruleset_version,
            "registry_sha256": wazuh_mock_settings.wazuh_rule_registry_sha256,
            "status": "active",
        }
    )

    # Approved Rule in Registry
    await db.detection_rule_registry.insert_one(
        {
            "engine": "wazuh",
            "rule_id": "60105",
            "ruleset_version": wazuh_mock_settings.wazuh_ruleset_version,
            "registry_sha256": wazuh_mock_settings.wazuh_rule_registry_sha256,
            "source_family": "windows_endpoint",
            "category": "credential_attack",
            "family": "credential_attacks",
            "family_status": "shadow",
            "severity": "HIGH",
            "allowed_engine_levels": [5],
            "mitre_ids": ["T1110"],
            "candidate_enabled": True,
            "status": "approved",
            "candidate_context_fields": ["wazuh_timestamp", "wazuh_manager"],
        }
    )

    # Server-Side Authoritative Agent Binding (Requirement 3A)
    await db.detection_engine_agent_bindings.insert_one(
        {
            "engine": "wazuh",
            "engine_instance_id": wazuh_mock_settings.wazuh_engine_instance_id,
            "wazuh_agent_id": wazuh_agent_id,
            "warsoc_agent_id": warsoc_agent_id,
            "tenant_id": tenant_id,
            "endpoint_hostname": "DESKTOP-U5K0V15",
            "status": "active",
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
    )

    return {
        "tenant_id": tenant_id,
        "warsoc_agent_id": warsoc_agent_id,
        "wazuh_agent_id": wazuh_agent_id,
    }


@pytest.mark.asyncio
async def test_unbound_wazuh_agent_is_quarantined_without_relying_on_label_string(
    db, wazuh_mock_settings, setup_dual_agent_env
):
    """Prove that an unbound Wazuh agent cannot inject detections or spoof tenants."""
    now = datetime.now(timezone.utc)
    candidate = DetectionCandidate(
        connector_id=wazuh_mock_settings.wazuh_connector_id,
        engine_instance_id=wazuh_mock_settings.wazuh_engine_instance_id,
        engine_version=wazuh_mock_settings.wazuh_engine_version,
        ruleset_version=wazuh_mock_settings.wazuh_ruleset_version,
        engine_alert_id=f"alert-{secrets.token_hex(8)}",
        engine_rule_id="60105",
        engine_rule_level=5,
        engine_detected_at=now,
        wazuh_agent_id="999",  # Unbound agent
        wazuh_agent_name="warsoc__ATTACKER_TENANT__endpoint_999",  # Spoofed label
        windows_event_id="4625",
        windows_event_record_id="84920",
        engine_reported_category="credential_attack",
        engine_reported_mitre_ids=["T1110"],
    )

    outcome = await admit_candidate(db, candidate, wazuh_mock_settings, received_at=now)
    assert outcome.outcome == "quarantined"
    assert outcome.reason_code == "UNBOUND_AGENT"

    # Verify quarantined in DB
    quarantined = await db.detection_candidates_quarantine.find_one(
        {"engine_alert_id": candidate.engine_alert_id}
    )
    assert quarantined is not None
    assert quarantined["reason_code"] == "UNBOUND_AGENT"


@pytest.mark.asyncio
async def test_native_wazuh_candidate_links_to_canonical_evidence_via_event_record_id(
    db, wazuh_mock_settings, setup_dual_agent_env
):
    """Requirement 3C & 3D: Link Wazuh detection to canonical WarSOC evidence and store shadow observation."""
    now = datetime.now(timezone.utc)
    env = setup_dual_agent_env
    event_record_id = "918234"
    canonical_event_uid = f"canonical-win-{secrets.token_hex(8)}"

    # Seed canonical evidence in WarSOC SIEM cold vault
    await db.siem_cold_vault.insert_one(
        {
            "event_uid": canonical_event_uid,
            "tenant_id": env["tenant_id"],
            "agent_id": env["warsoc_agent_id"],
            "event_id": "4625",
            "event_record_id": event_record_id,
            "source_ip": "192.168.1.50",
            "user": "Administrator",
            "telemetry_family": "windows",
            "signature_verified": True,
            "source_assurance": "agent_signed",
            "timestamp": now.isoformat(),
            "raw_event_data": {"system": {"channel": "Security"}},
        }
    )

    # Wazuh Candidate matching the same event_record_id
    candidate = DetectionCandidate(
        connector_id=wazuh_mock_settings.wazuh_connector_id,
        engine_instance_id=wazuh_mock_settings.wazuh_engine_instance_id,
        engine_version=wazuh_mock_settings.wazuh_engine_version,
        ruleset_version=wazuh_mock_settings.wazuh_ruleset_version,
        engine_alert_id=f"alert-{secrets.token_hex(8)}",
        engine_rule_id="60105",
        engine_rule_level=5,
        engine_detected_at=now,
        wazuh_agent_id=env["wazuh_agent_id"],
        wazuh_agent_name="warsoc__lab_endpoint_01",
        windows_event_id="4625",
        windows_event_record_id=event_record_id,
        windows_channel="Security",
        selected_security_fields={"targetUserName": "Administrator", "ipAddress": "192.168.1.50"},
        engine_reported_category="credential_attack",
        engine_reported_mitre_ids=["T1110"],
        engine_context={"wazuh_timestamp": now.isoformat(), "wazuh_manager": "wazuh.manager"},
    )

    outcome = await admit_candidate(db, candidate, wazuh_mock_settings, received_at=now)
    assert outcome.outcome == "accepted"

    # Verify shadow observation stored with deterministic lineage
    obs = await db.detection_shadow_observations.find_one(
        {"engine_alert_id": candidate.engine_alert_id}
    )
    assert obs is not None
    assert obs["tenant_id"] == env["tenant_id"]
    assert obs["event_uid"] == canonical_event_uid
    assert obs["lineage_complete"] is True
    assert obs["wazuh_detected"] is True
    assert obs["mode"] == "shadow"
    assert obs["status"] == "shadow_observation"

    # Verify ZERO customer-facing incidents created in shadow mode (Requirement 3D)
    incident_count = await db.security_incidents.count_documents({"tenant_id": env["tenant_id"]})
    assert incident_count == 0


@pytest.mark.asyncio
async def test_per_family_authority_promotes_only_approved_families_to_single_incident(
    db, wazuh_mock_settings, setup_dual_agent_env
):
    """Requirement 3F & 3G: When primary mode is active, only approved families create/reconcile WarSOC incidents."""
    now = datetime.now(timezone.utc)
    env = setup_dual_agent_env
    wazuh_mock_settings.wazuh_detection_mode = "primary"
    wazuh_mock_settings.wazuh_primary_approved = True

    # Approve the credential_attacks family in registry
    await db.detection_rule_registry.update_one(
        {"rule_id": "60105"},
        {"$set": {"family_status": "approved"}},
    )

    canonical_event_uid = f"canonical-win-{secrets.token_hex(8)}"
    await db.siem_cold_vault.insert_one(
        {
            "event_uid": canonical_event_uid,
            "tenant_id": env["tenant_id"],
            "agent_id": env["warsoc_agent_id"],
            "event_id": "4625",
            "event_record_id": "991122",
            "source_ip": "192.168.1.50",
            "user": "Administrator",
            "signature_verified": True,
            "source_assurance": "agent_signed",
            "ingested_at": now,
            "timestamp": now,
        }
    )

    candidate = DetectionCandidate(
        connector_id=wazuh_mock_settings.wazuh_connector_id,
        engine_instance_id=wazuh_mock_settings.wazuh_engine_instance_id,
        engine_version=wazuh_mock_settings.wazuh_engine_version,
        ruleset_version=wazuh_mock_settings.wazuh_ruleset_version,
        engine_alert_id=f"alert-{secrets.token_hex(8)}",
        engine_rule_id="60105",
        engine_rule_level=5,
        engine_detected_at=now,
        wazuh_agent_id=env["wazuh_agent_id"],
        wazuh_agent_name="warsoc__lab_endpoint_01",
        windows_event_id="4625",
        windows_event_record_id="991122",
        engine_reported_category="credential_attack",
        engine_reported_mitre_ids=["T1110"],
    )

    outcome = await admit_candidate(db, candidate, wazuh_mock_settings, received_at=now)
    assert outcome.outcome == "accepted"

    # Single WarSOC Incident created with WarSOC evidence custody (Requirement 3G)
    incidents = await db.security_incidents.find({"tenant_id": env["tenant_id"]}).to_list(10)
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["rule_id"] == "credential_attacks"
    assert incident["evidence_authority"] == "warsoc_canonical_signed"
    assert "wazuh" in incident["detection_sources"]
    assert incident["status"] == "NEW"
    assert incident["occurrences"] == 1
    assert incident["event_uids"] == [canonical_event_uid]
    assert "Wazuh" not in incident["title"]
    assert "Wazuh" not in incident["message"]


@pytest.mark.asyncio
async def test_primary_candidate_without_exact_signed_lineage_remains_non_incident(
    db, wazuh_mock_settings, setup_dual_agent_env
):
    now = datetime.now(timezone.utc)
    env = setup_dual_agent_env
    wazuh_mock_settings.wazuh_detection_mode = "primary"
    wazuh_mock_settings.wazuh_primary_approved = True
    await db.detection_rule_registry.update_one(
        {"rule_id": "60105"},
        {"$set": {"family_status": "approved"}},
    )

    # A matching RecordID from another endpoint in the same tenant must not
    # satisfy the authoritative binding for this Wazuh agent.
    await db.siem_cold_vault.insert_one(
        {
            "event_uid": "wrong-endpoint-event",
            "tenant_id": env["tenant_id"],
            "agent_id": "WARSOC_AGENT_OTHER",
            "event_id": "4625",
            "event_record_id": "445566",
            "signature_verified": True,
            "source_assurance": "agent_signed",
            "ingested_at": now,
            "timestamp": now,
        }
    )
    candidate = DetectionCandidate(
        connector_id=wazuh_mock_settings.wazuh_connector_id,
        engine_instance_id=wazuh_mock_settings.wazuh_engine_instance_id,
        engine_version=wazuh_mock_settings.wazuh_engine_version,
        ruleset_version=wazuh_mock_settings.wazuh_ruleset_version,
        engine_alert_id=f"alert-{secrets.token_hex(8)}",
        engine_rule_id="60105",
        engine_rule_level=5,
        engine_detected_at=now,
        wazuh_agent_id=env["wazuh_agent_id"],
        windows_event_id="4625",
        windows_event_record_id="445566",
        engine_reported_category="credential_attack",
        engine_reported_mitre_ids=["T1110"],
    )

    outcome = await admit_candidate(db, candidate, wazuh_mock_settings, received_at=now)
    assert outcome.outcome == "accepted"
    observation = await db.detection_engine_observations.find_one(
        {"engine_alert_id": candidate.engine_alert_id}
    )
    assert observation["lineage_complete"] is False
    assert observation["status"] == "shadow_observation"
    assert await db.security_incidents.count_documents(
        {"tenant_id": env["tenant_id"]}
    ) == 0


@pytest.mark.asyncio
async def test_native_sca_check_never_borrows_unrelated_endpoint_event_lineage(
    db, wazuh_mock_settings, setup_dual_agent_env
):
    now = datetime.now(timezone.utc)
    env = setup_dual_agent_env
    await db.detection_rule_registry.insert_one(
        {
            "engine": "wazuh",
            "rule_id": "19007",
            "ruleset_version": wazuh_mock_settings.wazuh_ruleset_version,
            "registry_sha256": wazuh_mock_settings.wazuh_rule_registry_sha256,
            "source_family": "windows_endpoint",
            "category": "system_audit",
            "family": "configuration_assessment",
            "family_status": "shadow",
            "attack_level": False,
            "severity": "HIGH",
            "allowed_engine_levels": [7],
            "mitre_ids": [],
            "candidate_enabled": True,
            "status": "approved",
            "candidate_context_fields": ["wazuh_timestamp", "wazuh_manager"],
        }
    )
    await db.siem_cold_vault.insert_one(
        {
            "event_uid": "unrelated-signed-event",
            "tenant_id": env["tenant_id"],
            "agent_id": env["warsoc_agent_id"],
            "event_id": "4625",
            "event_record_id": "998877",
            "signature_verified": True,
            "source_assurance": "agent_signed",
            "ingested_at": now,
            "timestamp": now,
        }
    )
    candidate = DetectionCandidate(
        connector_id=wazuh_mock_settings.wazuh_connector_id,
        engine_instance_id=wazuh_mock_settings.wazuh_engine_instance_id,
        engine_version=wazuh_mock_settings.wazuh_engine_version,
        ruleset_version=wazuh_mock_settings.wazuh_ruleset_version,
        engine_alert_id=f"sca-{secrets.token_hex(8)}",
        engine_rule_id="19007",
        engine_rule_level=7,
        engine_detected_at=now,
        wazuh_agent_id=env["wazuh_agent_id"],
        wazuh_agent_name="warsoc-sca-test",
        selected_security_fields={
            "sca_type": "check",
            "scan_id": "scan-1",
            "check_id": "10001",
            "result": "failed",
        },
        engine_reported_category="system_audit",
        engine_reported_mitre_ids=[],
    )

    outcome = await admit_candidate(db, candidate, wazuh_mock_settings, received_at=now)

    assert outcome.outcome == "accepted"
    observation = await db.detection_engine_observations.find_one(
        {"engine_alert_id": candidate.engine_alert_id}
    )
    assert observation["event_uid"].startswith("unlinked-")
    assert observation["event_uid"] != "unrelated-signed-event"
    assert observation["lineage_complete"] is False
    assert observation["status"] == "shadow_observation"
    assert await db.security_incidents.count_documents(
        {"tenant_id": env["tenant_id"]}
    ) == 0


def test_projector_keeps_signed_windows_and_network_source_boundaries():
    """A native/SCA binding is independent of the signed projection contract."""
    windows_doc = {
        "telemetry_family": "windows",
        "signature_verified": True,
        "source_assurance": "agent_signed",
        "agent_id": "WARSOC_AGENT_01",
    }
    network_doc = {
        "telemetry_family": "network",
        "signature_verified": True,
        "source_assurance": "relay_attested",
        "source_type": "network_device",
        "agent_id": "WARSOC_RELAY_01",
    }

    assert _source_identity(windows_doc, network_enabled=True) == (
        "windows_endpoint", "endpoint_signed", "WARSOC_AGENT_01",
    )
    assert _source_identity(network_doc, network_enabled=True) == (
        "network_device",
        "relay_attested",
        "WARSOC_RELAY_01",
    )
    assert _source_identity({**windows_doc, "signature_verified": False}, network_enabled=True) is None
    assert _source_identity(network_doc, network_enabled=False) is None


@pytest.mark.asyncio
async def test_sca_binding_preserves_v3_security_projection_and_retry_dedup(
    db, wazuh_mock_settings, setup_dual_agent_env,
):
    settings = wazuh_mock_settings
    settings.wazuh_ruleset_version = "warsoc-projected-shadow-v3"
    settings.network_relay_enabled = True
    settings.wazuh_correlation_hmac_key = "c" * 64
    settings.wazuh_correlation_key_version = "corr-v1"
    settings.wazuh_outbox_encryption_key = Fernet.generate_key().decode("ascii")
    settings.wazuh_live_event_max_age_seconds = 3600
    settings.wazuh_max_body_bytes = 1024 * 1024
    settings.wazuh_outbox_max_bytes = 1024 * 1024
    settings.wazuh_outbox_record_ttl_days = 7
    registry_path = Path(__file__).resolve().parents[1] / "deploy/wazuh/registry/warsoc-projected-shadow-v3.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    await db.detection_rule_registry.insert_many([
        {**rule, "engine": "wazuh", "ruleset_version": registry["ruleset_version"],
         "status": "approved", "dispatch_enabled": bool(rule.get("input_field_map"))}
        for rule in registry["rules"]
    ])
    now = datetime.now(timezone.utc)
    event = {
        "tenant_id": setup_dual_agent_env["tenant_id"],
        "agent_id": setup_dual_agent_env["warsoc_agent_id"],
        "event_uid": "bound-security-canary", "event_id": "1102",
        "telemetry_family": "windows", "signature_verified": True,
        "source_assurance": "agent_signed", "timestamp": now, "ingested_at": now,
    }
    result = await project_canonical_event(db, event, settings, now=now)
    assert result.status == "created"
    row = await db.detection_dispatch_outbox.find_one({"dispatch_uid": result.dispatch_uid})
    assert row["tenant_id"] == event["tenant_id"]
    assert row["eligible_rule_ids"] == ["100612"]
    assert row["source_family"] == "windows_endpoint"
    assert (await project_canonical_event(db, event, settings, now=now)).status == "duplicate"
    assert await db.detection_dispatch_outbox.count_documents({}) == 1
    assert await db.security_incidents.count_documents({}) == 0

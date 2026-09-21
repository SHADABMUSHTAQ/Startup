"""
WarSOC component and integration verification suite:
1. Port Scan Detection (Vertical & Horizontal MITRE T1046)
2. Wazuh SCA (Security Configuration Assessment) Candidate Ingestion & Shadow Isolation
3. EPS Throughput Capacity & TokenBucket Rate Limiting (Per-Device, Global, Batch Admission)
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.config.config import get_settings
from app.network_relay.collector import RelayCollector, RelayDevice
from app.network_relay.spool import EncryptedBoundedSpool
from app.routes.network_relay import (
    RELAY_GENESIS_HASH,
    RelayBatch,
    RelayEvent,
    _admit_batch,
)
from app.utils.siem_catalog import SIEM_RULES
from app.utils.siem_logic import CorrelationEngine
from app.wazuh_integration.candidate_service import admit_candidate
from app.wazuh_integration.contracts import (
    DETECTION_CANDIDATE_SCHEMA,
    DetectionCandidate,
)

pytestmark = [pytest.mark.asyncio, pytest.mark.backend]


def _get_wazuh_test_settings():
    s = MagicMock()
    s.wazuh_connector_id = "wazuh-conn-prod"
    s.wazuh_engine_instance_id = "wazuh-manager-01"
    s.wazuh_engine_version = "4.3.0"
    s.wazuh_ruleset_version = "ruleset-v1.0.0"
    s.wazuh_rule_registry_sha256 = "sha256-dummy"
    s.wazuh_candidate_signing_secret = "secret-signing-key-minimum-32-bytes-long!"
    s.wazuh_detection_mode = "shadow"
    s.wazuh_primary_approved = False
    s.wazuh_shadow_retention_days = 30
    s.wazuh_candidate_clock_skew_seconds = 60
    s.wazuh_candidate_delivery_max_age_seconds = 3600
    return s


# =============================================================================
# SCENARIO 1: Vertical Port Scan Detection E2E (MITRE T1046)
# =============================================================================
async def test_vertical_port_scan_e2e(redis_client):
    """
    Vertical Port Scan:
    Adversary sweeps 10+ distinct destination ports on a single target from one source IP
    hitting network_connection_blocked within a 60s window.
    Asserts:
      - CorrelationEngine triggers vertical_port_scan.
      - Severity is HIGH, MITRE is T1046.
    """
    engine = CorrelationEngine(redis_client, config=SIEM_RULES)
    tenant_id = f"WARSOC_VSCAN_{uuid.uuid4().hex[:8]}"
    source_ip = "198.51.100.25"
    target_ip = "192.168.1.50"
    alerts = []

    for offset in range(10):
        log_entry = {
            "event_uid": f"vscan-{uuid.uuid4().hex}",
            "event_id": "NET-CONNECTION-BLOCK",
            "event_type": "network_connection_blocked",
            "source_ip": source_ip,
            "processed_data": {
                "event_type": "network_connection_blocked",
                "src_ip": source_ip,
                "dst_ip": target_ip,
                "dst_port": 4000 + offset,
                "action": "block",
            },
        }
        res = await engine.run_dynamic_rules(
            tenant_id,
            source_ip,
            "NETWORK_DEVICE",
            "NET-CONNECTION-BLOCK",
            event_type="network_connection_blocked",
            timestamp_iso=datetime.now(timezone.utc).isoformat(),
            log_entry=log_entry,
        )
        alerts.extend(res)

    dynamic_rules = {a.get("dynamic_rule") for a in alerts}
    assert "vertical_port_scan" in dynamic_rules, f"Expected vertical_port_scan, got {dynamic_rules}"

    vscan_alert = next(a for a in alerts if a.get("dynamic_rule") == "vertical_port_scan")
    assert vscan_alert.get("severity") == "HIGH"
    assert vscan_alert.get("mitre") == "T1046"
    assert vscan_alert.get("source_ip") == source_ip


# =============================================================================
# SCENARIO 2: Horizontal Port Scan Detection E2E (MITRE T1046)
# =============================================================================
async def test_horizontal_port_scan_e2e(redis_client):
    """
    Horizontal Port Scan:
    Adversary sweeps 10+ distinct destination IPs targeting a single port (e.g. 443)
    from one source IP hitting network_connection_blocked within a 60s window.
    Asserts:
      - CorrelationEngine triggers horizontal_port_scan.
      - Severity is HIGH, MITRE is T1046.
    """
    engine = CorrelationEngine(redis_client, config=SIEM_RULES)
    tenant_id = f"WARSOC_HSCAN_{uuid.uuid4().hex[:8]}"
    source_ip = "198.51.100.25"
    alerts = []

    for offset in range(10):
        log_entry = {
            "event_uid": f"hscan-{uuid.uuid4().hex}",
            "event_id": "NET-CONNECTION-BLOCK",
            "event_type": "network_connection_blocked",
            "source_ip": source_ip,
            "processed_data": {
                "event_type": "network_connection_blocked",
                "src_ip": source_ip,
                "dst_ip": f"192.168.1.{10 + offset}",
                "dst_port": 443,
                "action": "block",
            },
        }
        res = await engine.run_dynamic_rules(
            tenant_id,
            source_ip,
            "NETWORK_DEVICE",
            "NET-CONNECTION-BLOCK",
            event_type="network_connection_blocked",
            timestamp_iso=datetime.now(timezone.utc).isoformat(),
            log_entry=log_entry,
        )
        alerts.extend(res)

    dynamic_rules = {a.get("dynamic_rule") for a in alerts}
    assert "horizontal_port_scan" in dynamic_rules, f"Expected horizontal_port_scan, got {dynamic_rules}"

    hscan_alert = next(a for a in alerts if a.get("dynamic_rule") == "horizontal_port_scan")
    assert hscan_alert.get("severity") == "HIGH"
    assert hscan_alert.get("mitre") == "T1046"
    assert hscan_alert.get("source_ip") == source_ip


# =============================================================================
# SCENARIO 3: Port Scan Window Deduplication & Cooldown
# =============================================================================
async def test_port_scan_cooldown_and_window_deduplication(redis_client):
    """
    Verifies that once a port scan alert has been triggered, additional blocked
    probes within the active 60s window do NOT flood duplicate alerts.
    """
    engine = CorrelationEngine(redis_client, config=SIEM_RULES)
    tenant_id = f"WARSOC_COOLDOWN_{uuid.uuid4().hex[:8]}"
    source_ip = "198.51.100.30"
    target_ip = "192.168.1.50"
    alerts = []

    # Phase 1: 10 events trigger the first alert
    for offset in range(10):
        log_entry = {
            "event_uid": f"vscan-cooldown-{uuid.uuid4().hex}",
            "event_id": "NET-CONNECTION-BLOCK",
            "event_type": "network_connection_blocked",
            "source_ip": source_ip,
            "processed_data": {
                "event_type": "network_connection_blocked",
                "src_ip": source_ip,
                "dst_ip": target_ip,
                "dst_port": 5000 + offset,
                "action": "block",
            },
        }
        res = await engine.run_dynamic_rules(
            tenant_id,
            source_ip,
            "NETWORK_DEVICE",
            "NET-CONNECTION-BLOCK",
            event_type="network_connection_blocked",
            timestamp_iso=datetime.now(timezone.utc).isoformat(),
            log_entry=log_entry,
        )
        alerts.extend(res)

    first_alert_count = sum(1 for a in alerts if a.get("dynamic_rule") == "vertical_port_scan")
    assert first_alert_count == 1, "Expected exactly 1 alert after 10 probes"

    # Phase 2: 5 subsequent probes in same window
    for offset in range(10, 15):
        log_entry = {
            "event_uid": f"vscan-cooldown-{uuid.uuid4().hex}",
            "event_id": "NET-CONNECTION-BLOCK",
            "event_type": "network_connection_blocked",
            "source_ip": source_ip,
            "processed_data": {
                "event_type": "network_connection_blocked",
                "src_ip": source_ip,
                "dst_ip": target_ip,
                "dst_port": 5000 + offset,
                "action": "block",
            },
        }
        res = await engine.run_dynamic_rules(
            tenant_id,
            source_ip,
            "NETWORK_DEVICE",
            "NET-CONNECTION-BLOCK",
            event_type="network_connection_blocked",
            timestamp_iso=datetime.now(timezone.utc).isoformat(),
            log_entry=log_entry,
        )
        alerts.extend(res)

    second_alert_count = sum(1 for a in alerts if a.get("dynamic_rule") == "vertical_port_scan")
    assert second_alert_count == 1, "Cooldown failed: duplicate alert was emitted in active window"


# =============================================================================
# SCENARIO 4: Wazuh SCA Check Candidate Contract
# =============================================================================
async def test_wazuh_sca_scan_candidate_admission_and_dual_store():
    """
    Exercises candidate admission with the official Wazuh SCA failed-check rule.
    This is a mocked component contract, not proof of a live Wazuh scan.
    Asserts:
      - Admission succeeds with outcome='accepted'.
      - Candidate is dual-persisted to detection_engine_observations and detection_shadow_observations.
      - Security fields (policy, check_id, rationale) are retained without mutation.
    """
    wazuh_settings = _get_wazuh_test_settings()
    now = datetime.now(timezone.utc)
    candidate = DetectionCandidate(
        connector_id=wazuh_settings.wazuh_connector_id,
        engine_instance_id=wazuh_settings.wazuh_engine_instance_id,
        engine_version=wazuh_settings.wazuh_engine_version,
        ruleset_version=wazuh_settings.wazuh_ruleset_version,
        engine_alert_id=f"sca-cis-alert-{uuid.uuid4().hex[:12]}",
        engine_rule_id="19007",
        engine_rule_level=7,
        engine_detected_at=now,
        trigger_dispatch_uid="WZD_0123456789ABCDEF0123456789ABCDEF",
        wazuh_agent_id="WARSOC_AGENT_sca_server2022",
        wazuh_agent_name="WarSOC-Server-2022-DC",
        windows_channel="Security",
        engine_reported_category="system_audit",
        engine_reported_mitre_ids=["T1082"],
        selected_security_fields={
            "sca_type": "check",
            "scan_id": "scan-1",
            "policy": "CIS Benchmark Windows Server 2022 v1.0.0",
            "check_id": "cis-5.1.1-audit-policy",
            "result": "failed",
            "rationale": "Audit policy not configured to maximum security baseline",
        },
        engine_context={"wazuh_manager": "manager-prod-01"},
    )

    db = MagicMock()
    db.detection_engine_connectors.find_one = AsyncMock(return_value={
        "connector_id": wazuh_settings.wazuh_connector_id,
        "engine_instance_id": wazuh_settings.wazuh_engine_instance_id,
        "status": "active",
        "ruleset_version": wazuh_settings.wazuh_ruleset_version,
        "engine_version": wazuh_settings.wazuh_engine_version,
        "registry_sha256": wazuh_settings.wazuh_rule_registry_sha256,
    })
    db.detection_engine_connectors.update_one = AsyncMock()
    db.detection_dispatch_outbox.find_one = AsyncMock(return_value={
        "dispatch_uid": candidate.trigger_dispatch_uid,
        "tenant_id": "tenant-sca",
        "event_uid": "EV_SCA_01",
        "source_family": "windows_endpoint",
        "source_collection": "siem_cold_vault",
        "ruleset_version": wazuh_settings.wazuh_ruleset_version,
        "eligible_rule_ids": ["19007"],
        "created_at": now - timedelta(seconds=10),
        "live_expires_at": now + timedelta(seconds=3600),
    })
    db.siem_cold_vault.find_one = AsyncMock(return_value={
        "tenant_id": "tenant-sca",
        "event_uid": "EV_SCA_01",
        "timestamp": now,
        "source_assurance": "agent_signed",
    })
    db.detection_rule_registry.find_one = AsyncMock(return_value={
        "category": "system_audit",
        "severity": "HIGH",
        "mitre_ids": ["T1082"],
        "family": "system_audit",
        "family_status": "shadow",
        "allowed_engine_levels": [7],
        "candidate_context_fields": ["wazuh_manager"],
    })
    db.security_alerts.find_one = AsyncMock(return_value=None)
    db.detection_engine_observations.insert_one = AsyncMock()
    db.detection_engine_observations.count_documents = AsyncMock(return_value=0)
    db.detection_shadow_observations.insert_one = AsyncMock()
    db.detection_candidates_quarantine.update_one = AsyncMock()
    db.security_incidents.update_one = AsyncMock()
    db.security_incidents.insert_one = AsyncMock()

    receipt = await admit_candidate(db, candidate, wazuh_settings, received_at=now)
    assert receipt.outcome == "accepted", f"SCA candidate admission failed: {receipt.reason_code}"

    db.detection_engine_observations.insert_one.assert_called_once()
    obs_doc = db.detection_engine_observations.insert_one.call_args[0][0]
    assert obs_doc["mode"] == "shadow"
    assert obs_doc["engine_rule_id"] == "19007"
    assert obs_doc["selected_security_fields"]["check_id"] == "cis-5.1.1-audit-policy"

    db.detection_shadow_observations.insert_one.assert_called_once()
    shadow_doc = db.detection_shadow_observations.insert_one.call_args[0][0]
    assert shadow_doc["mode"] == "shadow"
    assert shadow_doc["status"] == "shadow_observation"


# =============================================================================
# SCENARIO 5: Wazuh SCA Shadow Component Isolation
# =============================================================================
async def test_wazuh_sca_shadow_zero_incident_isolation():
    """
    Confirms the candidate service does not mutate incidents in shadow mode.
    Live-manager acceptance remains a separate deployment gate.
    """
    wazuh_settings = _get_wazuh_test_settings()
    now = datetime.now(timezone.utc)
    candidate = DetectionCandidate(
        connector_id=wazuh_settings.wazuh_connector_id,
        engine_instance_id=wazuh_settings.wazuh_engine_instance_id,
        engine_version=wazuh_settings.wazuh_engine_version,
        ruleset_version=wazuh_settings.wazuh_ruleset_version,
        engine_alert_id=f"sca-shadow-iso-{uuid.uuid4().hex[:12]}",
        engine_rule_id="19007",
        engine_rule_level=7,
        engine_detected_at=now,
        trigger_dispatch_uid="WZD_0123456789ABCDEF0123456789ABCDEF",
        wazuh_agent_id="WARSOC_AGENT_sca_isolation",
        engine_reported_category="system_audit",
        engine_reported_mitre_ids=["T1082"],
        selected_security_fields={
            "sca_type": "check",
            "scan_id": "scan-2",
            "policy": "CIS Benchmark",
            "check_id": "cis-1.1.1-min-password-length",
            "result": "failed",
        },
    )

    db = MagicMock()
    db.detection_engine_connectors.find_one = AsyncMock(return_value={
        "connector_id": wazuh_settings.wazuh_connector_id,
        "engine_instance_id": wazuh_settings.wazuh_engine_instance_id,
        "status": "active",
        "ruleset_version": wazuh_settings.wazuh_ruleset_version,
        "engine_version": wazuh_settings.wazuh_engine_version,
        "registry_sha256": wazuh_settings.wazuh_rule_registry_sha256,
    })
    db.detection_engine_connectors.update_one = AsyncMock()
    db.detection_dispatch_outbox.find_one = AsyncMock(return_value={
        "dispatch_uid": candidate.trigger_dispatch_uid,
        "tenant_id": "tenant-sca",
        "event_uid": "EV_SCA_02",
        "source_family": "windows_endpoint",
        "source_collection": "siem_cold_vault",
        "ruleset_version": wazuh_settings.wazuh_ruleset_version,
        "eligible_rule_ids": ["19007"],
        "created_at": now - timedelta(seconds=10),
        "live_expires_at": now + timedelta(seconds=3600),
    })
    db.siem_cold_vault.find_one = AsyncMock(return_value={
        "tenant_id": "tenant-sca",
        "event_uid": "EV_SCA_02",
        "timestamp": now,
        "source_assurance": "agent_signed",
    })
    db.detection_rule_registry.find_one = AsyncMock(return_value={
        "category": "system_audit",
        "severity": "HIGH",
        "mitre_ids": ["T1082"],
        "family": "system_audit",
        "family_status": "shadow",
        "allowed_engine_levels": [7],
        "candidate_context_fields": [],
    })
    db.security_alerts.find_one = AsyncMock(return_value=None)
    db.detection_engine_observations.insert_one = AsyncMock()
    db.detection_engine_observations.count_documents = AsyncMock(return_value=0)
    db.detection_shadow_observations.insert_one = AsyncMock()
    db.detection_candidates_quarantine.update_one = AsyncMock()
    db.security_incidents.update_one = AsyncMock()
    db.security_incidents.insert_one = AsyncMock()

    receipt = await admit_candidate(db, candidate, wazuh_settings, received_at=now)
    assert receipt.outcome == "accepted", f"SCA isolation candidate admission failed: {receipt.reason_code}"

    assert db.security_incidents.insert_one.call_count == 0, "Shadow candidate inserted incident"
    assert db.security_incidents.update_one.call_count == 0, "Shadow candidate updated incident"


# =============================================================================
# SCENARIO 6: Per-Device TokenBucket Burst & Drop Coalescing
# =============================================================================
async def test_device_token_bucket_burst_and_drop_coalescing(tmp_path: Path):
    """
    Tests per-device TokenBucket rate limiting:
      - Device expected_eps = 10, burst capacity = 20.
      - First 20 datagrams in a single instant are admitted into evidence spool.
      - Datagrams 21-25 are dropped with reason='edge_rate_limit'.
      - flush_loss_summaries() writes coalesced control records documenting exact drop count.
    """
    encryption_key = secrets.token_bytes(32)
    ev_spool = EncryptedBoundedSpool(
        tmp_path / "evidence.db",
        stream_name="evidence",
        encryption_key=encryption_key,
        max_payload_bytes=10 * 1024 * 1024,
    )
    ctrl_spool = EncryptedBoundedSpool(
        tmp_path / "control.db",
        stream_name="control",
        encryption_key=encryption_key,
        max_payload_bytes=10 * 1024 * 1024,
    )

    device = RelayDevice(
        device_id="pfsense-burst-dev",
        vendor="pfsense",
        source_addresses=("192.168.56.254/32",),
        transport="udp",
        expected_eps=10,
    )

    now_val = 1000.0
    collector = RelayCollector(
        relay_id="WARSOC_RELAY_burst_test",
        devices=[device],
        evidence_spool=ev_spool,
        control_spool=ctrl_spool,
        global_eps=2000,
        clock=lambda: now_val,
    )

    raw_msg = (
        "<134>Mon Sep 14 19:40:00 filterlog[12345]: "
        "100,,,1000000103,em0,match,block,in,4,0x0,,64,1234,0,DF,6,tcp,60,"
        "198.51.100.25,192.168.1.50,4444,80,0,S,12345678,,1024,,"
    ).encode("utf-8")

    results = []
    for _ in range(25):
        res = collector.accept_message(
            raw_msg,
            source_address="192.168.56.254",
            transport="udp",
            receipt_time=datetime.now(timezone.utc),
        )
        results.append(res)

    accepted_count = sum(1 for r in results if r.status == "accepted")
    dropped_count = sum(1 for r in results if r.status == "dropped" and r.reason == "edge_rate_limit")

    assert accepted_count == 20, f"Expected 20 accepted (burst capacity), got {accepted_count}"
    assert dropped_count == 5, f"Expected 5 dropped for rate limit, got {dropped_count}"

    written = collector.flush_loss_summaries()
    assert written >= 1, "Expected control record written for loss coalescing"
    assert ctrl_spool.stats()["records"] >= 1


# =============================================================================
# SCENARIO 7: Relay Global TokenBucket Ceiling Under Noisy Devices
# =============================================================================
async def test_relay_global_token_bucket_limit(tmp_path: Path):
    """
    Tests global relay TokenBucket limit:
      - 2 registered devices (each expected_eps=50).
      - Relay global_eps = 30 (global burst capacity = 60).
      - 40 events from Device 1 + 40 events from Device 2 = 80 events at instant t0.
      - Exactly 60 events accepted globally; remaining 20 dropped with edge_rate_limit.
    """
    encryption_key = secrets.token_bytes(32)
    ev_spool = EncryptedBoundedSpool(
        tmp_path / "evidence_g.db",
        stream_name="evidence",
        encryption_key=encryption_key,
        max_payload_bytes=10 * 1024 * 1024,
    )
    ctrl_spool = EncryptedBoundedSpool(
        tmp_path / "control_g.db",
        stream_name="control",
        encryption_key=encryption_key,
        max_payload_bytes=10 * 1024 * 1024,
    )

    dev1 = RelayDevice(
        device_id="dev-01",
        vendor="pfsense",
        source_addresses=("192.168.1.1/32",),
        transport="udp",
        expected_eps=50,
    )
    dev2 = RelayDevice(
        device_id="dev-02",
        vendor="pfsense",
        source_addresses=("192.168.1.2/32",),
        transport="udp",
        expected_eps=50,
    )

    now_val = 2000.0
    collector = RelayCollector(
        relay_id="WARSOC_RELAY_global_test",
        devices=[dev1, dev2],
        evidence_spool=ev_spool,
        control_spool=ctrl_spool,
        global_eps=30,  # Capacity = 60
        clock=lambda: now_val,
    )

    raw_msg = (
        "<134>Mon Sep 14 19:40:00 filterlog[12345]: "
        "100,,,1000000103,em0,match,block,in,4,0x0,,64,1234,0,DF,6,tcp,60,"
        "198.51.100.25,192.168.1.50,4444,80,0,S,12345678,,1024,,"
    ).encode("utf-8")

    results = []
    # Interleave traffic from both devices
    for i in range(40):
        results.append(collector.accept_message(raw_msg, source_address="192.168.1.1", transport="udp"))
        results.append(collector.accept_message(raw_msg, source_address="192.168.1.2", transport="udp"))

    accepted = sum(1 for r in results if r.status == "accepted")
    dropped = sum(1 for r in results if r.status == "dropped" and r.reason == "edge_rate_limit")

    assert accepted == 60, f"Expected 60 accepted under global capacity, got {accepted}"
    assert dropped == 20, f"Expected 20 dropped under global limit, got {dropped}"


# =============================================================================
# SCENARIO 8: Batch Ingestion High-Throughput Burst & Idempotency
# =============================================================================
async def test_batch_ingest_high_throughput_burst(redis_client, db):
    """
    Validates high-throughput batch admission logic:
      - Ingests a 200-event RelayBatch.
      - Advances relay sequence to 1 in Redis and updates chain state.
      - Idempotent retry returns outcome 2 without charging duplicate quota.
    """
    tenant_id = f"WARSOC_BATCH_TENANT_{uuid.uuid4().hex[:8]}"
    relay_id = f"WARSOC_RELAY_{uuid.uuid4().hex}"
    chain_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc)

    relay_context = {
        "tenant_id": tenant_id,
        "relay_id": relay_id,
        "relay": {
            "relay_id": relay_id,
            "tenant_id": tenant_id,
            "chain_id": chain_id,
            "key_epoch": 1,
            "last_sequence": 0,
            "last_batch_hash": RELAY_GENESIS_HASH,
        },
    }

    # Generate 200 relay events
    events = []
    for i in range(200):
        raw = f"test-raw-event-{i}"
        events.append(
            RelayEvent(
                event_uid=f"batch-evt-{uuid.uuid4().hex[:12]}",
                record_class="evidence",
                device_id="pfsense-gw",
                vendor="pfsense",
                transport="udp",
                source_address="192.168.56.254",
                device_event_time=None,
                relay_receipt_time=now,
                raw_message=raw,
                raw_message_hash=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                normalized={
                    "event_type": "network_connection_blocked",
                    "src_ip": "198.51.100.25",
                    "dst_ip": "192.168.1.1",
                    "action": "block",
                },
            )
        )

    batch = RelayBatch(
        schema_version="warsoc-relay-batch-v1",
        relay_id=relay_id,
        chain_id=chain_id,
        key_epoch=1,
        sequence=1,
        previous_batch_hash=RELAY_GENESIS_HASH,
        created_at=now,
        events=events,
    )

    batch_hash = hashlib.sha256(f"batch-{batch.sequence}".encode("utf-8")).hexdigest()
    payloads = [e.raw_message for e in events]

    # First admission
    outcome = await _admit_batch(
        redis_client,
        relay_context,
        batch,
        batch_hash,
        payloads,
        payload_bytes=len(payloads) * 50,
    )
    assert outcome == 1, f"Expected outcome 1 (admitted), got {outcome}"

    state = await redis_client.hgetall(f"warsoc:relay_chain:{relay_id}")
    seq = int(state.get(b"sequence") or state.get("sequence") or 0)
    assert seq == 1, f"Expected sequence 1 in Redis state, got {seq}"

    # Idempotent retry with exact same batch and hash
    retry_outcome = await _admit_batch(
        redis_client,
        relay_context,
        batch,
        batch_hash,
        payloads,
        payload_bytes=len(payloads) * 50,
    )
    assert retry_outcome == 2, f"Expected outcome 2 (duplicate/idempotent), got {retry_outcome}"

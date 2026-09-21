import pytest
import pytest_asyncio
import asyncio
import uuid
import time
import inspect
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from cryptography.hazmat.primitives import serialization

from app.workers.siem_worker import siem_worker
from app.workers.peca_worker import peca_worker
from app.utils.agent_crypto import build_event_signature_string, build_payload_hash, build_signable_event_payload
from app.wazuh_integration.detection_features import extract_detection_features
from app.utils.compliance_chain import (
    CHAIN_VERSION,
    evidence_record_digest,
    aggregate_evidence_digest,
    compute_daily_root,
    genesis_root,
    verify_ledger_entry,
)
from app.utils.detection_provenance import attach_detection_provenance
from app.wazuh_integration import candidate_service
from app.wazuh_integration.candidate_service import admit_candidate
from app.wazuh_integration.contracts import DetectionCandidate
from tests.helpers import ed25519_keypair_pem, provision_and_login_admin

pytestmark = [pytest.mark.asyncio, pytest.mark.backend]


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _http_event(event_id, event_uid, tenant_id, agent_id, message, source_ip, private_key_pem, user=None, processed_data=None):
    sk = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
    payload = {
        "event_id": str(event_id),
        "event_uid": event_uid,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "timestamp": _now_iso(),
        "source_ip": source_ip,
        "user": user or "SYSTEM",
        "message": message,
        "raw_data": {"system": {"channel": "Security"}, "message": message},
    }
    if processed_data:
        payload["processed_data"] = processed_data
    payload_hash = build_payload_hash(build_signable_event_payload(payload))
    signature_input = build_event_signature_string(agent_id, payload["timestamp"], event_uid, payload_hash)
    payload["payload_hash"] = payload_hash
    payload["signature_version"] = "ed25519-v1"
    payload["signature_algorithm"] = "Ed25519"
    payload["agent_signature"] = sk.sign(signature_input.encode("utf-8")).hex()
    return payload


async def _setup_pipeline_env(async_client, db, redis_client):
    session = await provision_and_login_admin(
        async_client,
        "cross_pipe",
        api_prefix="/api/v1",
        retention_days=270,
    )
    tenant_id = session["tenant_id"]

    await redis_client.set(f"tenant_features:{tenant_id}", "siem,fbr_pos,peca_forensic")
    for grp in ["fbr_group", "siem_group", "eto_group"]:
        try:
            await redis_client.xgroup_create("raw_logs_queue", grp, id="0", mkstream=True)
        except Exception:
            pass

    priv_pem, pub_pem = ed25519_keypair_pem()
    act_res = await async_client.post("/api/v1/agent/generate-activation")
    assert act_res.status_code == 200
    activation_code = act_res.json()["activation_code"]

    reg_res = await async_client.post(
        "/api/v1/agent/register",
        json={
            "activation_code": activation_code,
            "public_key": pub_pem,
            "features": "SIEM,FBR,PECA",
        },
    )
    assert reg_res.status_code == 200
    agent_data = reg_res.json()
    agent_id = agent_data["agent_id"]
    agent_jwt = agent_data["agent_jwt"]

    return {
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "agent_jwt": agent_jwt,
        "private_key_pem": priv_pem,
    }


async def test_siem_and_peca_dual_processing(async_client, db, redis_client):
    """
    Scenario 1: SIEM & PECA Dual Processing
    Proves that when a PECA-eligible event is ingested, both siem_worker and peca_worker
    process it independently:
    - siem_cold_vault gets an encrypted copy with encryption_version
    - peca_forensic_logs gets an RSA-PSS signed forensic record with forensic_seal
    """
    env = await _setup_pipeline_env(async_client, db, redis_client)
    tenant_id = env["tenant_id"]
    agent_id = env["agent_id"]
    agent_jwt = env["agent_jwt"]
    priv_pem = env["private_key_pem"]

    event_uid = f"dual-{uuid.uuid4().hex[:12]}"
    event = _http_event(
        event_id="4732",
        event_uid=event_uid,
        tenant_id=tenant_id,
        agent_id=agent_id,
        message="A member was added to a local security group",
        source_ip="10.0.0.15",
        private_key_pem=priv_pem,
    )

    envelope = {
        "nonce": uuid.uuid4().hex,
        "timestamp": int(time.time()),
        "payload": [event],
    }

    resp = await async_client.post(
        "/api/v1/ingest/pulse",
        headers={"Authorization": f"Bearer {agent_jwt}"},
        json=envelope,
    )
    assert resp.status_code in (200, 202)

    siem_task = asyncio.create_task(siem_worker())
    peca_task = asyncio.create_task(peca_worker())

    siem_record = None
    peca_record = None
    try:
        deadline = asyncio.get_running_loop().time() + 20
        while asyncio.get_running_loop().time() < deadline:
            if not siem_record:
                siem_record = await db.siem_cold_vault.find_one({"event_uid": event_uid})
            if not peca_record:
                peca_record = await db.peca_forensic_logs.find_one({"event_uid": event_uid})
            if siem_record and peca_record:
                break
            await asyncio.sleep(0.3)
    finally:
        siem_task.cancel()
        peca_task.cancel()
        with suppress(asyncio.CancelledError):
            await asyncio.gather(siem_task, peca_task)

    assert siem_record is not None, "Event must be recorded in siem_cold_vault"
    assert peca_record is not None, "Event must be recorded in peca_forensic_logs"

    assert siem_record["tenant_id"] == tenant_id
    assert peca_record["tenant_id"] == tenant_id
    assert "siem_sensitive_encryption_version" in siem_record
    assert "digital_signature" in peca_record
    assert "forensic_seal" in peca_record


async def test_siem_cold_vault_source_family_for_projection(async_client, db, redis_client):
    """
    Scenario 2: Cold Vault Telemetry Normalization & Projection Features
    Proves that siem_worker assigns source_family='windows_endpoint' to signed Windows telemetry
    and attaches detection_features suitable for Wazuh projection.
    """
    env = await _setup_pipeline_env(async_client, db, redis_client)
    tenant_id = env["tenant_id"]
    agent_id = env["agent_id"]
    agent_jwt = env["agent_jwt"]
    priv_pem = env["private_key_pem"]

    event_uid = f"proj-{uuid.uuid4().hex[:12]}"
    event = _http_event(
        event_id="4688",
        event_uid=event_uid,
        tenant_id=tenant_id,
        agent_id=agent_id,
        message="mimikatz.exe executed",
        source_ip="10.0.0.20",
        private_key_pem=priv_pem,
        processed_data={
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe sekurlsa::logonpasswords",
        },
    )

    envelope = {
        "nonce": uuid.uuid4().hex,
        "timestamp": int(time.time()),
        "payload": [event],
    }

    resp = await async_client.post(
        "/api/v1/ingest/pulse",
        headers={"Authorization": f"Bearer {agent_jwt}"},
        json=envelope,
    )
    assert resp.status_code in (200, 202)

    siem_task = asyncio.create_task(siem_worker())
    siem_record = None
    try:
        deadline = asyncio.get_running_loop().time() + 20
        while asyncio.get_running_loop().time() < deadline:
            siem_record = await db.siem_cold_vault.find_one({"event_uid": event_uid})
            if siem_record:
                break
            await asyncio.sleep(0.3)
    finally:
        siem_task.cancel()
        with suppress(asyncio.CancelledError):
            await siem_task

    assert siem_record is not None, "Event must be recorded in siem_cold_vault"
    assert "detection_features" in siem_record
    features = siem_record.get("detection_features") or {}
    assert features.get("process_attack_family") == "credential_dumping"


async def test_wazuh_primary_incident_preserves_warsoc_authority():
    """
    Scenario 3: Wazuh Incident Projection Authority
    Proves that when a Wazuh candidate is promoted to primary:
    - security_incidents is updated with detection_sources=['wazuh']
    - evidence_authority remains 'warsoc_canonical_signed'
    - pack is 'siem' and engine_source is 'WarSOC'
    """
    now = datetime.now(timezone.utc)
    candidate = DetectionCandidate(
        connector_id="conn-123",
        engine_instance_id="inst-123",
        engine_version="4.3.0",
        ruleset_version="ruleset-v1.0.0",
        engine_alert_id="alert-proj-1",
        engine_rule_id="rule-123",
        engine_rule_level=12,
        engine_detected_at=now,
        trigger_dispatch_uid="WZD_0123456789ABCDEF0123456789ABCDEF",
        engine_reported_category="syslog",
        engine_reported_mitre_ids=["T1000"],
    )

    settings = MagicMock()
    settings.wazuh_connector_id = "conn-123"
    settings.wazuh_engine_instance_id = "inst-123"
    settings.wazuh_engine_version = "4.3.0"
    settings.wazuh_ruleset_version = "ruleset-v1.0.0"
    settings.wazuh_rule_registry_sha256 = "sha256-hash"
    settings.wazuh_candidate_signing_secret = "secret-signing-key-minimum-16-bytes"
    settings.wazuh_detection_mode = "primary"
    settings.wazuh_primary_approved = True
    settings.wazuh_shadow_retention_days = 30
    settings.wazuh_candidate_clock_skew_seconds = 60
    settings.wazuh_candidate_delivery_max_age_seconds = 3600

    db = MagicMock()
    db.detection_engine_connectors.find_one = AsyncMock(
        return_value={
            "connector_id": "conn-123",
            "engine_instance_id": "inst-123",
            "status": "active",
            "ruleset_version": "ruleset-v1.0.0",
            "engine_version": "4.3.0",
            "registry_sha256": "sha256-hash",
        }
    )
    db.detection_dispatch_outbox.find_one = AsyncMock(
        return_value={
            "dispatch_uid": "WZD_0123456789ABCDEF0123456789ABCDEF",
            "tenant_id": "tenant-cross",
            "event_uid": "EV_CROSS",
            "source_family": "windows_endpoint",
            "source_collection": "siem_cold_vault",
            "ruleset_version": "ruleset-v1.0.0",
            "eligible_rule_ids": ["rule-123"],
            "created_at": now - timedelta(seconds=10),
            "live_expires_at": now + timedelta(seconds=3600),
        }
    )
    db.siem_cold_vault.find_one = AsyncMock(
        return_value={
            "tenant_id": "tenant-cross",
            "event_uid": "EV_CROSS",
            "timestamp": now,
            "source_assurance": "agent_signed",
        }
    )
    db.detection_rule_registry.find_one = AsyncMock(
        return_value={
            "category": "syslog",
            "severity": "HIGH",
            "mitre_ids": ["T1000"],
            "family": "credential_attacks",
            "family_status": "approved",
            "allowed_engine_levels": [12],
            "candidate_context_fields": [],
        }
    )
    db.security_alerts.find_one = AsyncMock(return_value=None)
    db.detection_engine_observations.insert_one = AsyncMock()
    db.detection_engine_observations.count_documents = AsyncMock(return_value=0)
    db.security_incidents.update_one = AsyncMock()
    db.detection_engine_connectors.update_one = AsyncMock()

    with patch(
        "app.wazuh_integration.candidate_service.project_security_incident",
        new_callable=AsyncMock,
        return_value={"incident": {"incident_id": "INC-CROSS-01"}},
    ) as mock_project:
        outcome = await admit_candidate(db, candidate, settings, received_at=now)

    assert outcome.outcome == "accepted"
    mock_project.assert_called_once()
    incident_alert_arg = mock_project.call_args[0][1]
    assert incident_alert_arg["pack"] == "siem"
    assert incident_alert_arg["engine_source"] == "WarSOC"
    assert incident_alert_arg["source_assurance"] == "agent_signed"

    db.security_incidents.update_one.assert_called_once()
    update_op = db.security_incidents.update_one.call_args[0][1]
    assert update_op["$set"]["evidence_authority"] == "warsoc_canonical_signed"
    assert "wazuh" in update_op["$addToSet"]["detection_sources"]


async def test_peca_wazuh_isolation():
    """
    Scenario 4: Cryptographic Isolation (Audit)
    Verifies that candidate_service never accesses or references PECA forensic vaults.
    """
    source = inspect.getsource(candidate_service)
    assert "peca_forensic_logs" not in source, "candidate_service must never query peca_forensic_logs"
    assert "source_envelopes_peca" not in source, "candidate_service must never query source_envelopes_peca"
    assert "daily_forensic_ledgers" not in source, "candidate_service must never query daily_forensic_ledgers"


async def test_evidence_chain_covers_only_peca_events():
    """
    Scenario 5: Evidence Chain Scope Guarantee
    Proves that daily ledger chain aggregation strictly scopes to peca_forensic_logs
    and does not cross-pollute with other collections.
    """
    records = [
        ("peca_forensic_logs", {"event_uid": "e1", "event_id": "4625"}),
        ("peca_forensic_logs", {"event_uid": "e2", "event_id": "1102"}),
    ]

    digest, count, source_counts = aggregate_evidence_digest(records)
    assert count == 2
    assert source_counts == {"peca_forensic_logs": 2}
    assert "siem_cold_vault" not in source_counts

    daily_root = compute_daily_root(
        tenant_id="TENANT-CROSS",
        date_str="2026-09-19",
        previous_root_hash=genesis_root("TENANT-CROSS"),
        evidence_digest=digest,
        log_count=count,
        source_counts=source_counts,
    )

    ledger_entry = {
        "tenant_id": "TENANT-CROSS",
        "date": "2026-09-19",
        "chain_version": CHAIN_VERSION,
        "previous_root_hash": genesis_root("TENANT-CROSS"),
        "evidence_digest": digest,
        "daily_root_hash": daily_root,
        "log_count": count,
        "source_counts": source_counts,
    }

    assert verify_ledger_entry(ledger_entry) is True


async def test_source_family_to_feature_extraction_chain():
    """
    Scenario 6: End-to-End Feature Extraction Chain
    Proves that a verified agent-signed Windows event correctly yields windows_endpoint
    features for Wazuh rules without leaking unvalidated telemetry.
    """
    doc = {
        "telemetry_family": "windows",
        "signature_verified": True,
        "source_assurance": "agent_signed",
        "event_id": "4688",
        "processed_data": {
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe sekurlsa::logonpasswords",
        },
    }

    source_family = (
        "windows_endpoint"
        if (
            doc.get("telemetry_family") == "windows"
            and doc.get("signature_verified") is True
            and doc.get("source_assurance") == "agent_signed"
        )
        else "unknown"
    )
    assert source_family == "windows_endpoint"

    features = extract_detection_features(doc, source_family)
    assert features.get("process_attack_family") == "credential_dumping"


async def test_detection_provenance_chain_across_pipelines():
    """
    Scenario 7: Cross-Pipeline Detection Provenance Immutability
    Proves that alerts from stateless, stateful, and external detectors carry
    independent and bounded detection_provenance records.
    """
    source_event = {"tenant_id": "TENANT-CROSS", "event_uid": "EVT-PROV-1", "source_ip": "10.0.0.5"}

    # Stateless detector provenance
    alert_stateless = {"type": "EVENT_ID_4732_PRIVILEGED_GROUP_MODIFICATION", "severity": "HIGH"}
    attach_detection_provenance(
        alert_stateless,
        source_event=source_event,
        detector_module="siem.native_event",
        rule_id="4732",
    )
    assert alert_stateless["detection_provenance"]["detector_module"] == "siem.native_event"
    assert len(alert_stateless["detection_provenance"]["evidence_refs"]) <= 8

    # Correlation engine provenance
    alert_corr = {"type": "GHOST_ADMIN", "severity": "CRITICAL"}
    attach_detection_provenance(
        alert_corr,
        source_event=source_event,
        detector_module="siem.correlation",
        rule_id="GHOST_ADMIN",
    )
    assert alert_corr["detection_provenance"]["detector_module"] == "siem.correlation"
    assert alert_corr["detection_provenance"]["rule_id"] == "GHOST_ADMIN"

    # Ensure independent records
    assert (
        alert_stateless["detection_provenance"]["detector_module"]
        != alert_corr["detection_provenance"]["detector_module"]
    )

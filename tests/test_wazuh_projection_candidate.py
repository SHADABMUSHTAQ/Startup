from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.wazuh_integration.candidate_service import admit_candidate
from app.wazuh_integration.contracts import DetectionCandidate
from app.wazuh_integration.projector import build_detection_input


DISPATCH_UID = "WZD_0123456789ABCDEF0123456789ABCDEF"


def _settings(**overrides):
    values = {
        "network_relay_enabled": False,
        "wazuh_ruleset_version": "warsoc-lab-canary-v1",
        "wazuh_rule_registry_sha256": "a" * 64,
        "wazuh_correlation_hmac_key": "c" * 64,
        "wazuh_correlation_key_version": "corr-v1",
        "wazuh_candidate_signing_secret": "s" * 64,
        "wazuh_connector_id": "wazuh-shadow-01",
        "wazuh_engine_instance_id": "wazuh-node-01",
        "wazuh_engine_version": "4.14.7",
        "wazuh_detection_mode": "shadow",
        "wazuh_shadow_retention_days": 30,
        "wazuh_candidate_clock_skew_seconds": 30,
        "wazuh_candidate_delivery_max_age_seconds": 86400,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _signed_windows_event():
    now = datetime.now(timezone.utc)
    return {
        "tenant_id": "WARSOC_TENANT_A",
        "agent_id": "WARSOC_AGENT_A",
        "event_uid": "event-uid-0001",
        "event_id": "4688",
        "event_type": "process_create",
        "telemetry_family": "windows",
        "source_assurance": "agent_signed",
        "signature_verified": True,
        "timestamp": now,
        "ingested_at": now,
        "source_ip": "192.0.2.10",
        "user": "operator",
        "processed_data": {
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c run --token=do-not-export",
            "password": "not-allowed",
        },
    }


def test_projection_is_minimized_hashed_and_secret_redacted():
    rules = [
        {
            "input_field_map": {
                "process_name": "processed_data.process_name",
                "command_line": "processed_data.command_line",
                "password": "processed_data.password",
            }
        }
    ]
    projected = build_detection_input(_signed_windows_event(), rules, _settings())

    assert projected.source_family == "windows_endpoint"
    assert projected.source_assurance == "endpoint_signed"
    assert projected.endpoint_id == "WARSOC_AGENT_A"
    assert projected.tenant_scope != "WARSOC_TENANT_A"
    assert projected.correlation_keys.corr_tenant != projected.tenant_scope
    assert projected.security_fields["process_name"] == "cmd.exe"
    assert "do-not-export" not in projected.security_fields["command_line"]
    assert "password" not in projected.security_fields


def test_projection_accepts_encrypted_processed_data_and_uses_safe_root_fallbacks():
    event = _signed_windows_event()
    event["processed_data"] = "fernet-v1:encrypted-canonical-payload"

    projected = build_detection_input(event, [], _settings())

    assert projected.correlation_keys.corr_tenant_source is not None
    assert projected.correlation_keys.corr_tenant_actor is not None
    assert projected.security_fields == {}


def test_projection_rejects_unsigned_or_misclassified_windows_event():
    event = _signed_windows_event()
    event["signature_verified"] = False
    with pytest.raises(ValueError, match="source assurance"):
        build_detection_input(event, [], _settings())


def test_network_projection_requires_network_feature_gate():
    now = datetime.now(timezone.utc)
    event = {
        "tenant_id": "WARSOC_TENANT_A",
        "agent_id": "WARSOC_RELAY_A",
        "network_device_id": "firewall-1",
        "event_uid": "network-event-0001",
        "event_id": "NET-CONNECTION-ALLOW",
        "telemetry_family": "network",
        "source_type": "network_device",
        "source_assurance": "relay_attested",
        "signature_verified": True,
        "timestamp": now,
        "ingested_at": now,
    }
    with pytest.raises(ValueError, match="source assurance"):
        build_detection_input(event, [], _settings(network_relay_enabled=False))
    projected = build_detection_input(event, [], _settings(network_relay_enabled=True))
    assert projected.source_family == "network_device"
    assert projected.source_assurance == "relay_attested"


class _FakeDb:
    def __init__(self):
        self.detection_engine_connectors = SimpleNamespace(
            find_one=AsyncMock(),
            update_one=AsyncMock(),
        )
        self.detection_dispatch_outbox = SimpleNamespace(find_one=AsyncMock())
        self.siem_cold_vault = SimpleNamespace(find_one=AsyncMock())
        self.detection_rule_registry = SimpleNamespace(find_one=AsyncMock())
        self.detection_engine_observations = SimpleNamespace(insert_one=AsyncMock())
        self.detection_candidates_quarantine = SimpleNamespace(update_one=AsyncMock())


def _candidate(**overrides):
    values = {
        "connector_id": "wazuh-shadow-01",
        "engine_instance_id": "wazuh-node-01",
        "engine_version": "4.14.7",
        "ruleset_version": "warsoc-lab-canary-v1",
        "engine_alert_id": "wazuh-alert-1",
        "engine_rule_id": "100500",
        "engine_rule_level": 3,
        "engine_detected_at": datetime.now(timezone.utc),
        "trigger_dispatch_uid": DISPATCH_UID,
        "engine_reported_category": "integration_canary",
        "engine_reported_mitre_ids": [],
        "engine_context": {"wazuh_timestamp": "2026-08-11T12:00:00Z", "extra": "drop"},
    }
    values.update(overrides)
    return DetectionCandidate(**values)


def _approved_db():
    now = datetime.now(timezone.utc)
    db = _FakeDb()
    db.detection_engine_connectors.find_one.return_value = {"status": "active"}
    db.detection_dispatch_outbox.find_one.return_value = {
        "tenant_id": "WARSOC_TRUSTED_TENANT",
        "event_uid": "event-uid-0001",
        "source_collection": "siem_cold_vault",
        "source_family": "windows_endpoint",
        "ruleset_version": "warsoc-lab-canary-v1",
        "eligible_rule_ids": ["100500"],
        "created_at": now - timedelta(seconds=2),
        "live_expires_at": now + timedelta(seconds=58),
    }
    db.siem_cold_vault.find_one.return_value = {"_id": "canonical"}
    db.detection_rule_registry.find_one.return_value = {
        "category": "integration_canary",
        "severity": "INFO",
        "mitre_ids": [],
        "allowed_engine_levels": [3],
        "candidate_context_fields": ["wazuh_timestamp"],
    }
    return db


@pytest.mark.asyncio
async def test_candidate_tenant_and_semantics_come_from_warsoc_state():
    db = _approved_db()
    outcome = await admit_candidate(
        db,
        _candidate(),
        _settings(),
        received_at=datetime.now(timezone.utc),
    )

    assert outcome.outcome == "accepted"
    observation = db.detection_engine_observations.insert_one.await_args.args[0]
    assert observation["tenant_id"] == "WARSOC_TRUSTED_TENANT"
    assert observation["severity"] == "INFO"
    assert observation["status"] == "shadow_observation"
    assert observation["engine_context"] == {"wazuh_timestamp": "2026-08-11T12:00:00Z"}
    assert "incident_id" not in observation


@pytest.mark.asyncio
async def test_projected_candidate_uses_dispatch_lineage_over_manager_agent_identity():
    db = _approved_db()
    outcome = await admit_candidate(
        db,
        _candidate(wazuh_agent_id="000", wazuh_agent_name="wazuh.manager"),
        _settings(),
        received_at=datetime.now(timezone.utc),
    )

    assert outcome.outcome == "accepted"
    observation = db.detection_engine_observations.insert_one.await_args.args[0]
    assert observation["tenant_id"] == "WARSOC_TRUSTED_TENANT"
    assert observation["dispatch_uid"] == DISPATCH_UID


@pytest.mark.asyncio
async def test_candidate_semantic_mismatch_is_quarantined_not_projected():
    db = _approved_db()
    outcome = await admit_candidate(
        db,
        _candidate(engine_reported_category="privilege_escalation"),
        _settings(),
        received_at=datetime.now(timezone.utc),
    )

    assert outcome.outcome == "quarantined"
    assert outcome.reason_code == "CATEGORY_MISMATCH"
    db.detection_engine_observations.insert_one.assert_not_awaited()
    db.detection_candidates_quarantine.update_one.assert_awaited_once()


@pytest.mark.asyncio
async def test_candidate_outside_dispatch_live_window_is_quarantined():
    db = _approved_db()
    dispatch = db.detection_dispatch_outbox.find_one.return_value
    candidate = _candidate(
        engine_detected_at=dispatch["live_expires_at"] + timedelta(minutes=1)
    )
    outcome = await admit_candidate(
        db,
        candidate,
        _settings(),
        received_at=datetime.now(timezone.utc),
    )

    assert outcome.outcome == "quarantined"
    assert outcome.reason_code == "CANDIDATE_TIME_INVALID"
    db.detection_engine_observations.insert_one.assert_not_awaited()

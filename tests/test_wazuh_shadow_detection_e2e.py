from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import hashlib
import uuid
import pytest
import pymongo.errors
from typing import Any

from app.wazuh_integration.candidate_service import (
    admit_candidate,
    admit_candidate_batch,
    _candidate_hash,
    _candidate_fingerprint,
)
from app.wazuh_integration.contracts import (
    DetectionCandidate,
    DetectionCandidateBatch,
    CandidateReceiptOutcome,
    DETECTION_CANDIDATE_SCHEMA,
    DETECTION_CANDIDATE_BATCH_SCHEMA,
)

pytestmark = [pytest.mark.asyncio, pytest.mark.backend]


def get_base_candidate(detected_at: datetime | None = None):
    now = detected_at or datetime.now(timezone.utc)
    return DetectionCandidate(
        connector_id="conn-123",
        engine_instance_id="inst-123",
        engine_version="4.3.0",
        ruleset_version="ruleset-v1.0.0",
        engine_alert_id="alert-123",
        engine_rule_id="rule-123",
        engine_rule_level=12,
        engine_detected_at=now,
        trigger_dispatch_uid="WZD_0123456789ABCDEF0123456789ABCDEF",
        wazuh_agent_id=None,
        wazuh_agent_name=None,
        windows_event_id=None,
        windows_event_record_id=None,
        windows_channel=None,
        selected_security_fields={"key": "value"},
        engine_reported_category="syslog",
        engine_reported_mitre_ids=["T1000"],
        engine_context={},
    )


def get_base_settings():
    settings = MagicMock()
    settings.wazuh_connector_id = "conn-123"
    settings.wazuh_engine_instance_id = "inst-123"
    settings.wazuh_engine_version = "4.3.0"
    settings.wazuh_ruleset_version = "ruleset-v1.0.0"
    settings.wazuh_rule_registry_sha256 = "sha256-hash"
    settings.wazuh_candidate_signing_secret = "secret-signing-key-minimum-16-bytes"
    settings.wazuh_detection_mode = "shadow"
    settings.wazuh_primary_approved = False
    settings.wazuh_shadow_retention_days = 30
    settings.wazuh_candidate_clock_skew_seconds = 60
    settings.wazuh_candidate_delivery_max_age_seconds = 3600
    return settings


def get_base_db(now: datetime):
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
            "tenant_id": "tenant-1",
            "event_uid": "EV_123",
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
            "tenant_id": "tenant-1",
            "event_uid": "EV_123",
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
            "family_status": "shadow",
            "allowed_engine_levels": [12],
            "candidate_context_fields": [],
        }
    )
    db.security_alerts.find_one = AsyncMock(return_value=None)
    db.detection_engine_observations.insert_one = AsyncMock()
    db.detection_engine_observations.count_documents = AsyncMock(return_value=0)
    db.detection_shadow_observations.insert_one = AsyncMock()
    db.detection_candidates_quarantine.update_one = AsyncMock()
    db.security_incidents.update_one = AsyncMock()
    db.detection_engine_connectors.update_one = AsyncMock()
    return db


async def test_canonical_event_projection_via_dispatch_lineage():
    """
    Scenario 1: Canonical Event Projection
    Proves that a valid candidate with a dispatch lineage resolves to canonical evidence,
    validates against the rule registry, and inserts into observation collections in shadow mode.
    """
    now = datetime.now(timezone.utc)
    candidate = get_base_candidate(now)
    settings = get_base_settings()
    db = get_base_db(now)

    outcome = await admit_candidate(db, candidate, settings, received_at=now)

    assert outcome.outcome == "accepted"
    db.detection_dispatch_outbox.find_one.assert_called_once_with({"dispatch_uid": candidate.trigger_dispatch_uid})
    db.siem_cold_vault.find_one.assert_called_once_with({"tenant_id": "tenant-1", "event_uid": "EV_123"})
    db.detection_rule_registry.find_one.assert_called_once()

    # Assert observation was inserted
    db.detection_engine_observations.insert_one.assert_called_once()
    inserted_doc = db.detection_engine_observations.insert_one.call_args[0][0]
    assert inserted_doc["mode"] == "shadow"
    assert inserted_doc["status"] == "shadow_observation"
    assert inserted_doc["tenant_id"] == "tenant-1"
    assert inserted_doc["event_uid"] == "EV_123"


async def test_shadow_candidate_stored_in_both_observation_collections():
    """
    Scenario 2: Shadow Candidate Dual Observation Storage & Retention TTL
    Proves that in shadow mode, candidate is inserted into BOTH detection_engine_observations
    and detection_shadow_observations. Also verifies retention TTL calculation.
    """
    now = datetime.now(timezone.utc)
    candidate = get_base_candidate(now)
    settings = get_base_settings()
    db = get_base_db(now)

    outcome = await admit_candidate(db, candidate, settings, received_at=now)
    assert outcome.outcome == "accepted"

    db.detection_engine_observations.insert_one.assert_called_once()
    db.detection_shadow_observations.insert_one.assert_called_once()

    obs_doc = db.detection_engine_observations.insert_one.call_args[0][0]
    shadow_doc = db.detection_shadow_observations.insert_one.call_args[0][0]

    assert obs_doc["mode"] == "shadow"
    assert shadow_doc["mode"] == "shadow"
    assert obs_doc["status"] == "shadow_observation"
    assert shadow_doc["status"] == "shadow_observation"

    # Verify retention TTL
    expected_expiry = now + timedelta(days=settings.wazuh_shadow_retention_days)
    assert abs((obs_doc["record_expires_at"] - expected_expiry).total_seconds()) < 5


async def test_native_detector_benchmarking():
    """
    Scenario 3: Native Detector Benchmarking
    Proves that if an equivalent native WarSOC alert exists for the canonical event,
    the shadow observation records it for benchmarking (native_detected, native_rule_id, mitre_match).
    """
    now = datetime.now(timezone.utc)
    candidate = get_base_candidate(now)
    settings = get_base_settings()
    db = get_base_db(now)

    # Mock native alert existing
    db.security_alerts.find_one = AsyncMock(
        return_value={
            "tenant_id": "tenant-1",
            "event_uid": "EV_123",
            "event_id": "warsoc-native-rule",
            "mitre": "T1000",
        }
    )

    outcome = await admit_candidate(db, candidate, settings, received_at=now)
    assert outcome.outcome == "accepted"

    db.detection_engine_observations.insert_one.assert_called_once()
    obs_doc = db.detection_engine_observations.insert_one.call_args[0][0]

    assert obs_doc.get("native_detected") is True
    assert obs_doc.get("native_rule_id") == "warsoc-native-rule"
    assert obs_doc.get("mitre_match") is True
    assert obs_doc.get("wazuh_detected") is True


async def test_quarantine_enforcement_connector_mismatch():
    """
    Scenario 4: Quarantine Enforcement on Connector Mismatch
    Proves that an invalid connector_id results in a CONNECTOR_MISMATCH quarantine outcome.
    """
    now = datetime.now(timezone.utc)
    candidate = get_base_candidate(now)
    candidate.connector_id = "invalid-connector"
    settings = get_base_settings()
    db = get_base_db(now)

    outcome = await admit_candidate(db, candidate, settings, received_at=now)

    assert outcome.outcome == "quarantined"
    assert outcome.reason_code == "CONNECTOR_MISMATCH"
    db.detection_candidates_quarantine.update_one.assert_called_once()


async def test_quarantine_enforcement_multiple_reasons():
    """
    Scenario 5: Quarantine Enforcement for Engine & Ruleset Version Mismatch
    Proves that ENGINE_VERSION_MISMATCH and RULESET_VERSION_MISMATCH result in quarantines.
    """
    now = datetime.now(timezone.utc)
    settings = get_base_settings()
    db = get_base_db(now)

    # Engine version mismatch
    c1 = get_base_candidate(now)
    c1.engine_version = "invalid-engine-version"
    o1 = await admit_candidate(db, c1, settings, received_at=now)
    assert o1.outcome == "quarantined"
    assert o1.reason_code == "ENGINE_VERSION_MISMATCH"

    # Ruleset version mismatch
    c2 = get_base_candidate(now)
    c2.ruleset_version = "invalid-ruleset"
    o2 = await admit_candidate(db, c2, settings, received_at=now)
    assert o2.outcome == "quarantined"
    assert o2.reason_code == "RULESET_VERSION_MISMATCH"

    assert db.detection_candidates_quarantine.update_one.call_count == 2


async def test_shadow_to_primary_promotion():
    """
    Scenario 6: Shadow-to-Primary Gate
    Proves that when primary approved mode is active, an approved rule + canonical event
    promotes the observation to 'primary' and writes lineage to security_incidents.
    """
    now = datetime.now(timezone.utc)
    candidate = get_base_candidate(now)
    settings = get_base_settings()
    settings.wazuh_detection_mode = "primary"
    settings.wazuh_primary_approved = True
    db = get_base_db(now)
    db.detection_rule_registry.find_one.return_value["family_status"] = "approved"

    with patch(
        "app.wazuh_integration.candidate_service.project_security_incident",
        new_callable=AsyncMock,
        return_value={"incident": {"incident_id": "INC-TEST-001"}},
    ):
        outcome = await admit_candidate(db, candidate, settings, received_at=now)

    assert outcome.outcome == "accepted"

    # Assert observation was inserted as primary
    db.detection_engine_observations.insert_one.assert_called_once()
    obs_doc = db.detection_engine_observations.insert_one.call_args[0][0]
    assert obs_doc["mode"] == "primary"
    assert obs_doc["status"] == "promoted"

    # Shadow should NOT be written in primary mode
    db.detection_shadow_observations.insert_one.assert_not_called()

    # Assert incident mutation was called
    db.security_incidents.update_one.assert_called_once()
    update_op = db.security_incidents.update_one.call_args[0][1]
    assert "$addToSet" in update_op
    assert update_op["$addToSet"].get("detection_sources") == "wazuh"
    assert "$set" in update_op
    assert update_op["$set"].get("evidence_authority") == "warsoc_canonical_signed"


async def test_shadow_isolation_no_incident_mutation():
    """
    Scenario 7: Shadow Isolation Guarantee
    Proves that in standard shadow mode, security_incidents is never modified.
    """
    now = datetime.now(timezone.utc)
    candidate = get_base_candidate(now)
    settings = get_base_settings()
    # Default is shadow mode
    db = get_base_db(now)

    outcome = await admit_candidate(db, candidate, settings, received_at=now)
    assert outcome.outcome == "accepted"

    db.security_incidents.update_one.assert_not_called()


async def test_deduplication_returns_duplicate_outcome():
    """
    Scenario 8: Deduplication
    Proves that if an observation insertion hits a DuplicateKeyError (due to unique index),
    it handles the error and returns a 'duplicate' outcome without re-inserting.
    """
    now = datetime.now(timezone.utc)
    candidate = get_base_candidate(now)
    settings = get_base_settings()
    db = get_base_db(now)

    # Mock DuplicateKeyError on unique fingerprint
    db.detection_engine_observations.insert_one.side_effect = pymongo.errors.DuplicateKeyError(
        "E11000 duplicate key error collection"
    )

    outcome = await admit_candidate(db, candidate, settings, received_at=now)

    assert outcome.outcome == "duplicate"
    assert outcome.reason_code == "ALREADY_RECORDED"

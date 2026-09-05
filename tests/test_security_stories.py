"""Contract tests for WarSOC Security Story correlation, durability and API.

Security Stories are mutable interpretations layered on top of canonical
evidence. These tests assert the correlation thresholds, the fail-open
relationship with canonical ingestion, and the tenant-scoped API boundary.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from app.config.config import get_settings
from app.utils.security_incidents import project_security_incident
from app.utils.security_stories import (
    SIGNAL_SCHEMA_VERSION,
    STORY_SCHEMA_VERSION,
    STORY_SIGNAL_GROUP,
    build_event_story_signal,
    claim_story_signal,
    classify_account,
    complete_story_signal,
    enqueue_story_signal,
    fail_story_signal,
    process_story_signal,
    record_asset_ip_binding,
    resolve_asset_for_ip,
    serialize_security_story,
    upsert_security_story,
)
from app.workers import security_story_worker as worker_module
from app.workers.stream_retention import RAW_REQUIRED_GROUPS, trim_acknowledged_stream


TENANT = "WARSOC_STORY_TENANT"
OTHER_TENANT = "WARSOC_STORY_OTHER"
RAW_LOGS_QUEUE = worker_module.RAW_LOGS_QUEUE

SERVER_ASSET = {
    "asset_id": "SRV-STORY-01",
    "name": "srv-story-01",
    "asset_class": "server",
    "server_role": "file",
    "criticality": "high",
    "environment": "production",
}
WORKSTATION_ASSET = {
    "asset_id": "WS-STORY-01",
    "name": "ws-story-01",
    "asset_class": "workstation",
    "server_role": None,
    "criticality": "medium",
    "environment": "production",
}
NETWORK_ASSET = {
    "asset_id": "network:pfsense-story-01",
    "name": "pfsense-story-01",
    "asset_class": "network_device",
    "server_role": None,
    "criticality": "high",
    "environment": None,
}


@pytest.fixture
def stories_enabled(monkeypatch):
    """Enable the opt-in feature on the cached settings object."""
    settings = get_settings()
    monkeypatch.setattr(settings, "security_stories_enabled", True)
    return settings


@pytest.fixture
def stories_disabled(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "security_stories_enabled", False)
    return settings


def _signal(signal_type, *, event_uid, event_time, event_id="", tenant_id=TENANT, asset=None, identity="corp\\alice", **extra):
    signal = {
        "schema_version": SIGNAL_SCHEMA_VERSION,
        "signal_type": signal_type,
        "tenant_id": tenant_id,
        "event_uid": event_uid,
        "event_id": event_id,
        "event_time": event_time,
        "source_family": "windows",
        "source_assurance": "agent_signed",
        "asset": dict(asset or SERVER_ASSET),
        "identity": identity,
        "account_type": classify_account(identity),
        "actionable": False,
        "technical_severity": "MEDIUM",
        "summary": signal_type.replace("_", " "),
    }
    signal.update(extra)
    return {key: value for key, value in signal.items() if value not in (None, "")}


async def _enqueue(db, signal):
    await enqueue_story_signal(
        db,
        source_type="event",
        source_uid=signal["event_uid"],
        signal=signal,
    )
    return await db.story_signal_ledger.find_one(
        {"tenant_id": signal["tenant_id"], "source_type": "event", "source_uid": signal["event_uid"]}
    )


async def _run(db, signal):
    document = await _enqueue(db, signal)
    return await process_story_signal(db, document)


async def _seed_compromise_chain(
    db,
    *,
    failure_count=10,
    tenant_id=TENANT,
    failures_after_success=False,
    include_privilege=True,
    logon_id="0x1a2b3c",
    failure_tenant_id=None,
):
    """Seed the rule-1 evidence chain and return the unprocessed success signal."""
    base = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=40)
    success_time = base + timedelta(minutes=6)
    failure_base = success_time + timedelta(minutes=1) if failures_after_success else base
    for index in range(failure_count):
        await _enqueue(
            db,
            _signal(
                "failed_login",
                event_uid=f"Security:fail-{index}-{failure_tenant_id or tenant_id}",
                event_id="4625",
                event_time=failure_base + timedelta(seconds=index * 20),
                tenant_id=failure_tenant_id or tenant_id,
                source_ip="10.20.0.50",
                logon_type="3",
            ),
        )
    if include_privilege:
        await _enqueue(
            db,
            _signal(
                "privileged_session",
                event_uid=f"Security:priv-{tenant_id}",
                event_id="4672",
                event_time=success_time + timedelta(seconds=30),
                tenant_id=tenant_id,
                subject_logon_id=logon_id,
                actionable=True,
                technical_severity="HIGH",
            ),
        )
    success = _signal(
        "successful_login",
        event_uid=f"Security:success-{tenant_id}",
        event_id="4624",
        event_time=success_time,
        tenant_id=tenant_id,
        source_ip="10.20.0.50",
        logon_type="3",
        target_logon_id=logon_id,
        technical_severity="HIGH",
    )
    return success, success_time


def _story_document(story_id, tenant_id, **overrides):
    now = datetime.now(timezone.utc)
    document = {
        "tenant_id": tenant_id,
        "story_id": story_id,
        "record_type": "security_story",
        "schema_version": STORY_SCHEMA_VERSION,
        "story_rule_version": "1",
        "story_type": "SERVER_ACCOUNT_COMPROMISE",
        "title": "Possible server account compromise",
        "status": "OPEN",
        "version": 1,
        "technical_confidence": "HIGH",
        "technical_severity": "HIGH",
        "business_impact": "MEDIUM",
        "attention_priority": "HIGH",
        "primary_identity": "corp\\alice",
        "primary_account_type": "UNKNOWN",
        "affected_assets": [SERVER_ASSET],
        "affected_asset_ids": [SERVER_ASSET["asset_id"]],
        "source_assets": [],
        "destination_assets": [SERVER_ASSET],
        "event_refs": [{"event_uid": "Security:api-1", "event_id": "4624"}],
        "incident_refs": [],
        "network_refs": [],
        "signal_refs": ["Security:api-1"],
        "reason_codes": ["REPEATED_REMOTE_FAILURES", "SUBSEQUENT_REMOTE_SUCCESS"],
        "confidence_reasons": ["Same tenant, server, account and source address within ten minutes"],
        "correlation_gaps": [],
        "timeline": [{"phase": "SUCCESSFUL_REMOTE_ACCESS", "timestamp": now, "summary": "remote logon"}],
        "workflow_history": [],
        "linked_story_ids": [],
        "first_seen": now,
        "last_seen": now,
        "evidence_state": "SOURCE_REFERENCED",
        "event_reference_count": 1,
        "incident_reference_count": 0,
        "network_reference_count": 0,
        "reference_limit": 100,
        "has_new_activity": False,
        "created_at": now,
        "updated_at": now,
    }
    document.update(overrides)
    return document


async def _api_tenant(db):
    user = await db.users.find_one({"email": {"$regex": "^test_integ_"}})
    assert user is not None
    return str(user["tenant_id"]), user


# --------------------------------------------------------------------------
# Signal classification boundaries
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_host_firewall_events_are_never_accepted_as_egress_proof(db, stories_enabled):
    """Windows 5156/5157 share event_type strings with relay firewall evidence."""
    now = datetime.now(timezone.utc)

    def _event(**overrides):
        event = {
            "tenant_id": TENANT,
            "event_uid": f"Security:{secrets.token_hex(4)}",
            "event_id": "5156",
            "event_type": "network_connection_permitted",
            "source_type": "windows_endpoint",
            "agent_id": "AGENT-STORY-01",
            "timestamp": now.isoformat(),
            "processed_data": {
                "src_ip": "10.20.0.10",
                "dst_ip": "93.184.216.34",
                "action": "allow",
                "protocol": "tcp",
                "dst_port": "443",
            },
        }
        event.update(overrides)
        return event

    assert await build_event_story_signal(db, _event()) is None
    assert await build_event_story_signal(db, _event(event_id="5157", event_type="network_connection_blocked")) is None

    relay_permitted = await build_event_story_signal(
        db,
        _event(
            event_id="",
            source_type="network_device",
            agent_id="WARSOC_RELAY_01",
            network_device_id="pfsense-story-01",
            network_vendor="pfSense",
        ),
    )
    assert relay_permitted is not None
    assert relay_permitted["signal_type"] == "allowed_egress"
    assert relay_permitted["source_family"] == "network"
    assert relay_permitted["asset"]["asset_class"] == "network_device"

    relay_blocked = await build_event_story_signal(
        db,
        _event(
            event_id="",
            event_type="network_connection_blocked",
            source_type="network_device",
            agent_id="WARSOC_RELAY_01",
            network_device_id="pfsense-story-01",
        ),
    )
    assert relay_blocked is None


@pytest.mark.asyncio
async def test_windows_signal_binds_asset_class_identity_and_session_fields(db, stories_enabled):
    await db.agents.insert_one(
        {
            "agent_id": "AGENT-STORY-SRV",
            "tenant_id": TENANT,
            "asset_class": "server",
            "server_monitoring_required": True,
            "server_role": "file",
            "criticality": "critical",
            "environment": "production",
            "endpoint_name": "srv-story-01",
        }
    )
    signal = await build_event_story_signal(
        db,
        {
            "tenant_id": TENANT,
            "event_uid": "Security:logon-1",
            "event_id": "4624",
            "event_type": "successful_logon",
            "source_type": "windows_endpoint",
            "agent_id": "AGENT-STORY-SRV",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "processed_data": {
                "target_user": "CORP\\Alice",
                "source_network_address": "10.20.0.50",
                "logon_type": "3",
                "target_logon_id": "0x1A2B3C",
                "command_line": "whoami",
            },
        },
    )
    assert signal["signal_type"] == "successful_login"
    assert signal["asset"]["asset_class"] == "server"
    assert signal["asset"]["criticality"] == "critical"
    assert signal["identity"] == "corp\\alice"
    assert signal["target_logon_id"] == "0x1a2b3c"
    assert signal["source_ip"] == "10.20.0.50"
    # Raw command lines are never carried into interpretations.
    assert "command_line" not in signal
    assert len(signal["command_fingerprint"]) == 20


# --------------------------------------------------------------------------
# Correlation rules
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_server_account_compromise_story_requires_threshold_and_session_match(db, stories_enabled):
    success, _ = await _seed_compromise_chain(db)
    story_ids = await _run(db, success)

    assert len(story_ids) == 1
    story = await db.security_stories.find_one({"story_id": story_ids[0]})
    assert story["story_type"] == "SERVER_ACCOUNT_COMPROMISE"
    assert story["technical_confidence"] == "HIGH"
    assert story["status"] == "OPEN"
    assert story["technical_severity"] == "HIGH"
    assert story["attention_priority"] == "HIGH"
    assert story["primary_identity"] == "corp\\alice"
    assert story["affected_asset_ids"] == [SERVER_ASSET["asset_id"]]
    assert "MATCHED_PRIVILEGED_SESSION" in story["reason_codes"]
    assert story["evidence_state"] == "SOURCE_REFERENCED"
    assert story["event_reference_count"] == 12
    assert story["correlation_gaps"] == ["Source address is not mapped to a fresh managed asset"]
    assert [item["phase"] for item in story["timeline"]] == [
        "AUTHENTICATION_FAILURES",
        "SUCCESSFUL_REMOTE_ACCESS",
        "PRIVILEGED_SESSION",
    ]


@pytest.mark.asyncio
async def test_server_account_compromise_rejects_under_threshold_wrong_order_and_cross_tenant(db, stories_enabled):
    under, _ = await _seed_compromise_chain(db, failure_count=9)
    assert await _run(db, under) == []
    await db.story_signal_ledger.delete_many({})

    wrong_order, _ = await _seed_compromise_chain(db, failures_after_success=True)
    assert await _run(db, wrong_order) == []
    await db.story_signal_ledger.delete_many({})

    cross_tenant, _ = await _seed_compromise_chain(db, failure_tenant_id=OTHER_TENANT)
    assert await _run(db, cross_tenant) == []
    assert await db.security_stories.count_documents({}) == 0


@pytest.mark.asyncio
async def test_server_persistence_confidence_follows_logon_session_continuity(db, stories_enabled):
    now = datetime.now(timezone.utc).replace(microsecond=0)

    async def _chain(suffix, *, logon_id):
        await _enqueue(
            db,
            _signal(
                "successful_login",
                event_uid=f"Security:persist-login-{suffix}",
                event_id="4624",
                event_time=now - timedelta(minutes=12),
                source_ip="10.20.0.50",
                logon_type="3",
                target_logon_id=logon_id,
            ),
        )
        await _enqueue(
            db,
            _signal(
                "process_execution",
                event_uid=f"Security:persist-process-{suffix}",
                event_id="4688",
                event_time=now - timedelta(minutes=6),
                subject_logon_id=logon_id,
                actionable=True,
                technical_severity="HIGH",
            ),
        )
        return _signal(
            "service_persistence",
            event_uid=f"Security:persist-service-{suffix}",
            event_id="4697",
            event_time=now,
            subject_logon_id=logon_id,
            service_name="warsoc-fake-service",
        )

    linked = await _chain("linked", logon_id="0xaaa1")
    linked_ids = await _run(db, linked)
    assert len(linked_ids) == 1
    linked_story = await db.security_stories.find_one({"story_id": linked_ids[0]})
    assert linked_story["story_type"] == "SERVER_COMPROMISE_PERSISTENCE"
    assert linked_story["technical_confidence"] == "HIGH"
    assert linked_story["status"] == "OPEN"
    assert linked_story["confidence_reasons"] == ["Exact logon-session continuity"]
    assert linked_story["correlation_gaps"] == []

    await db.story_signal_ledger.delete_many({})
    unlinked = await _chain("unlinked", logon_id=None)
    unlinked_ids = await _run(db, unlinked)
    assert len(unlinked_ids) == 1
    unlinked_story = await db.security_stories.find_one({"story_id": unlinked_ids[0]})
    assert unlinked_story["technical_confidence"] == "MEDIUM"
    assert unlinked_story["status"] == "CANDIDATE"
    assert unlinked_story["correlation_gaps"] == ["Exact Windows logon-session linkage is unavailable"]


@pytest.mark.asyncio
async def test_server_anti_forensics_story_requires_prior_activity_within_thirty_minutes(db, stories_enabled):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    await _enqueue(
        db,
        _signal(
            "process_execution",
            event_uid="Security:af-process",
            event_id="4688",
            event_time=now - timedelta(minutes=10),
            subject_logon_id="0xbbb1",
            actionable=True,
            technical_severity="CRITICAL",
        ),
    )
    cleared = _signal(
        "audit_log_cleared",
        event_uid="Security:af-cleared",
        event_id="1102",
        event_time=now,
        subject_logon_id="0xbbb1",
    )
    story_ids = await _run(db, cleared)
    assert len(story_ids) == 1
    story = await db.security_stories.find_one({"story_id": story_ids[0]})
    assert story["story_type"] == "SERVER_ANTI_FORENSICS"
    assert story["technical_confidence"] == "HIGH"
    assert story["technical_severity"] == "CRITICAL"
    assert story["attention_priority"] == "URGENT"

    await db.security_stories.delete_many({})
    await db.story_signal_ledger.delete_many({})
    await _enqueue(
        db,
        _signal(
            "process_execution",
            event_uid="Security:af-old-process",
            event_id="4688",
            event_time=now - timedelta(minutes=45),
            subject_logon_id="0xbbb2",
            actionable=True,
        ),
    )
    stale = _signal(
        "audit_policy_changed",
        event_uid="Security:af-policy",
        event_id="4719",
        event_time=now,
        subject_logon_id="0xbbb2",
    )
    assert await _run(db, stale) == []


@pytest.mark.asyncio
async def test_workstation_to_server_story_requires_fresh_workstation_ip_binding(db, stories_enabled):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    workstation_signal = _signal(
        "process_execution",
        event_uid="Security:ws-process",
        event_id="4688",
        event_time=now - timedelta(minutes=14),
        asset=WORKSTATION_ASSET,
        identity="corp\\bob",
        source_ip="10.20.0.77",
        actionable=True,
        technical_severity="HIGH",
    )
    assert await _run(db, workstation_signal) == []
    binding = await db.asset_ip_bindings.find_one({"ip_address": "10.20.0.77"})
    assert binding["asset_id"] == WORKSTATION_ASSET["asset_id"]
    assert binding["asset_class"] == "workstation"

    await _enqueue(
        db,
        _signal(
            "successful_login",
            event_uid="Security:ws-login",
            event_id="4624",
            event_time=now - timedelta(minutes=6),
            identity="corp\\bob",
            source_ip="10.20.0.77",
            logon_type="3",
            target_logon_id="0xccc1",
        ),
    )
    server_activity = _signal(
        "process_execution",
        event_uid="Security:ws-server-process",
        event_id="4688",
        event_time=now,
        identity="corp\\bob",
        subject_logon_id="0xccc1",
        actionable=True,
        technical_severity="HIGH",
    )
    story_ids = await _run(db, server_activity)
    stories = await db.security_stories.find({"story_id": {"$in": story_ids}}).to_list(length=10)
    movement = next(item for item in stories if item["story_type"] == "WORKSTATION_TO_SERVER_MOVEMENT")
    assert movement["technical_confidence"] == "HIGH"
    assert set(movement["affected_asset_ids"]) == {
        WORKSTATION_ASSET["asset_id"],
        SERVER_ASSET["asset_id"],
    }
    assert movement["source_assets"][0]["asset_id"] == WORKSTATION_ASSET["asset_id"]
    assert "FRESH_SOURCE_ASSET_IP_MATCH" in movement["reason_codes"]


@pytest.mark.asyncio
async def test_external_activity_story_requires_relay_egress_and_parent_story(db, stories_enabled):
    success, success_time = await _seed_compromise_chain(db)
    parent_ids = await _run(db, success)
    assert len(parent_ids) == 1

    await record_asset_ip_binding(
        db,
        _signal(
            "process_execution",
            event_uid="Security:srv-bind",
            event_id="4688",
            event_time=success_time,
            source_ip="10.20.0.10",
        ),
    )

    egress = _signal(
        "allowed_egress",
        event_uid="pfsense:egress-1",
        event_time=success_time + timedelta(minutes=5),
        asset=NETWORK_ASSET,
        identity=None,
        source_family="network",
        source_assurance="relay_attested",
        source_ip="10.20.0.10",
        destination_ip="93.184.216.34",
        destination_port="443",
        network_action="allow",
        network_direction="out",
        network_device_id="pfsense-story-01",
        network_vendor="pfsense",
    )
    story_ids = await _run(db, egress)
    external = await db.security_stories.find_one(
        {"story_type": "EXTERNAL_ACTIVITY_AFTER_SERVER_COMPROMISE"}
    )
    assert external is not None
    assert external["story_id"] in story_ids
    assert external["linked_story_ids"] == parent_ids
    assert external["network_reference_count"] == 1
    assert external["network_refs"][0]["destination_ip"] == "93.184.216.34"
    assert external["evidence_state"] == "SOURCE_REFERENCED"
    assert "ALLOWED_PRIVATE_TO_PUBLIC_CONNECTION" in external["reason_codes"]


@pytest.mark.asyncio
async def test_external_activity_story_rejects_host_blocked_private_and_unparented_egress(db, stories_enabled):
    success, success_time = await _seed_compromise_chain(db)
    await _run(db, success)
    await record_asset_ip_binding(
        db,
        _signal(
            "process_execution",
            event_uid="Security:srv-bind-2",
            event_id="4688",
            event_time=success_time,
            source_ip="10.20.0.10",
        ),
    )
    observed_at = success_time + timedelta(minutes=5)

    def _egress(suffix, **overrides):
        fields = {
            "asset": NETWORK_ASSET,
            "identity": None,
            "source_family": "network",
            "source_assurance": "relay_attested",
            "source_ip": "10.20.0.10",
            "destination_ip": "93.184.216.34",
            "network_action": "allow",
            "network_device_id": "pfsense-story-01",
        }
        fields.update(overrides)
        return _signal(
            "allowed_egress",
            event_uid=f"pfsense:reject-{suffix}",
            event_time=observed_at,
            **fields,
        )

    # A Windows host observation is not proof that traffic left the network.
    assert await _run(db, _egress("host", source_family="windows", asset=SERVER_ASSET)) == []
    # A denied firewall decision is not egress.
    assert await _run(db, _egress("blocked", network_action="block")) == []
    # Internal traffic is not external activity.
    assert await _run(db, _egress("internal", destination_ip="10.20.0.99")) == []
    assert await db.security_stories.count_documents(
        {"story_type": "EXTERNAL_ACTIVITY_AFTER_SERVER_COMPROMISE"}
    ) == 0

    # Egress without a recent compromise story is not escalated on its own.
    await db.security_stories.delete_many({})
    assert await _run(db, _egress("unparented")) == []
    assert await db.security_stories.count_documents({}) == 0


@pytest.mark.asyncio
async def test_asset_ip_binding_rejects_public_stale_and_ambiguous_addresses(db, stories_enabled):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    await record_asset_ip_binding(
        db,
        _signal(
            "process_execution",
            event_uid="Security:bind-public",
            event_id="4688",
            event_time=now,
            source_ip="8.8.8.8",
        ),
    )
    assert await db.asset_ip_bindings.count_documents({}) == 0

    # Logon events carry the remote peer address and must never bind an asset.
    await record_asset_ip_binding(
        db,
        _signal(
            "successful_login",
            event_uid="Security:bind-logon",
            event_id="4624",
            event_time=now,
            source_ip="10.20.0.60",
        ),
    )
    assert await db.asset_ip_bindings.count_documents({}) == 0

    await record_asset_ip_binding(
        db,
        _signal(
            "process_execution",
            event_uid="Security:bind-fresh",
            event_id="4688",
            event_time=now,
            source_ip="10.20.0.61",
        ),
    )
    assert await resolve_asset_for_ip(db, TENANT, "10.20.0.61", now) is not None
    assert await resolve_asset_for_ip(db, TENANT, "10.20.0.61", now + timedelta(hours=3)) is None
    assert await resolve_asset_for_ip(db, OTHER_TENANT, "10.20.0.61", now) is None

    await record_asset_ip_binding(
        db,
        _signal(
            "process_execution",
            event_uid="Security:bind-ambiguous",
            event_id="4688",
            event_time=now,
            asset=WORKSTATION_ASSET,
            source_ip="10.20.0.61",
        ),
    )
    assert await resolve_asset_for_ip(db, TENANT, "10.20.0.61", now) is None


# --------------------------------------------------------------------------
# Ledger durability
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_signal_ledger_claim_is_leased_and_recovers_expired_leases(db, stories_enabled):
    now = datetime.now(timezone.utc)
    signal = _signal("process_execution", event_uid="Security:lease-1", event_id="4688", event_time=now)
    assert await enqueue_story_signal(db, source_type="event", source_uid=signal["event_uid"], signal=signal) is True
    assert await enqueue_story_signal(db, source_type="event", source_uid=signal["event_uid"], signal=signal) is False
    assert await db.story_signal_ledger.count_documents({}) == 1

    claimed = await claim_story_signal(db)
    assert claimed["status"] == "PROCESSING"
    assert claimed["attempt_count"] == 1
    assert claimed["lease_id"]
    assert await claim_story_signal(db) is None

    await db.story_signal_ledger.update_one(
        {"_id": claimed["_id"]},
        {"$set": {"lease_until": now - timedelta(seconds=1)}},
    )
    reclaimed = await claim_story_signal(db)
    assert reclaimed["_id"] == claimed["_id"]
    assert reclaimed["attempt_count"] == 2
    assert reclaimed["lease_id"] != claimed["lease_id"]


@pytest.mark.asyncio
async def test_signal_ledger_recheck_and_failure_backoff_are_bounded(db, stories_enabled):
    now = datetime.now(timezone.utc)
    event_signal = _signal("process_execution", event_uid="Security:recheck-1", event_id="4688", event_time=now)
    await enqueue_story_signal(db, source_type="event", source_uid=event_signal["event_uid"], signal=event_signal)
    claimed = await claim_story_signal(db)
    await complete_story_signal(db, claimed, [])
    rechecked = await db.story_signal_ledger.find_one({"_id": claimed["_id"]})
    assert rechecked["status"] == "PENDING"
    assert rechecked["recheck_count"] == 1
    assert "lease_id" not in rechecked

    await db.story_signal_ledger.update_one(
        {"_id": claimed["_id"]},
        {"$set": {"recheck_count": 2, "next_attempt_at": now - timedelta(seconds=1)}},
    )
    final_claim = await claim_story_signal(db)
    await complete_story_signal(db, final_claim, ["STORY-ABC"])
    processed = await db.story_signal_ledger.find_one({"_id": claimed["_id"]})
    assert processed["status"] == "PROCESSED"
    assert processed["story_ids"] == ["STORY-ABC"]

    incident_signal = _signal("process_execution", event_uid="Security:incident-1", event_id="4688", event_time=now)
    await enqueue_story_signal(db, source_type="incident", source_uid="occurrence-1", signal=incident_signal)
    incident_claim = await claim_story_signal(db)
    await complete_story_signal(db, incident_claim, [])
    assert (await db.story_signal_ledger.find_one({"_id": incident_claim["_id"]}))["status"] == "PROCESSED"

    retry_signal = _signal("process_execution", event_uid="Security:retry-1", event_id="4688", event_time=now)
    await enqueue_story_signal(db, source_type="event", source_uid=retry_signal["event_uid"], signal=retry_signal)
    retry_claim = await claim_story_signal(db)
    await fail_story_signal(db, retry_claim, RuntimeError("boom"))
    retried = await db.story_signal_ledger.find_one({"_id": retry_claim["_id"]})
    assert retried["status"] == "RETRY"
    assert retried["last_error_code"] == "RuntimeError"
    assert retried["next_attempt_at"] <= retried["updated_at"] + timedelta(seconds=300)

    exhausted = {**retry_claim, "attempt_count": get_settings().security_story_max_attempts}
    await db.story_signal_ledger.update_one(
        {"_id": retry_claim["_id"]}, {"$set": {"lease_id": retry_claim["lease_id"]}}
    )
    await fail_story_signal(db, exhausted, RuntimeError("boom"))
    assert (await db.story_signal_ledger.find_one({"_id": retry_claim["_id"]}))["status"] == "FAILED"


@pytest.mark.asyncio
async def test_replayed_signal_does_not_duplicate_or_re_version_a_story(db, stories_enabled):
    success, _ = await _seed_compromise_chain(db)
    first_ids = await _run(db, success)
    first = await db.security_stories.find_one({"story_id": first_ids[0]})

    replay_document = await db.story_signal_ledger.find_one({"source_uid": success["event_uid"]})
    second_ids = await process_story_signal(db, replay_document)
    second = await db.security_stories.find_one({"story_id": first_ids[0]})

    assert second_ids == first_ids
    assert await db.security_stories.count_documents({}) == 1
    assert second["version"] == first["version"]
    assert second["projection_hash"] == first["projection_hash"]


@pytest.mark.asyncio
async def test_signal_tenant_binding_and_schema_are_enforced(db, stories_enabled):
    now = datetime.now(timezone.utc)
    signal = _signal("process_execution", event_uid="Security:tenant-1", event_id="4688", event_time=now)
    with pytest.raises(ValueError):
        await process_story_signal(db, {"tenant_id": OTHER_TENANT, "source_uid": "x", "signal": signal})
    with pytest.raises(ValueError):
        await process_story_signal(
            db,
            {"tenant_id": TENANT, "source_uid": "x", "signal": {**signal, "schema_version": "v0"}},
        )
    with pytest.raises(ValueError):
        await enqueue_story_signal(db, source_type="guess", source_uid="x", signal=signal)


@pytest.mark.asyncio
async def test_story_projection_bounds_arrays_and_rejects_low_confidence(db, stories_enabled):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = {
        "tenant_id": TENANT,
        "story_id": "STORY-BOUNDS",
        "story_type": "SERVER_ACCOUNT_COMPROMISE",
        "title": "Bounded projection",
        "technical_confidence": "HIGH",
        "technical_severity": "HIGH",
        "primary_identity": "corp\\alice",
        "affected_assets": [
            {"asset_id": f"ASSET-{index}", "name": f"asset-{index}", "asset_class": "server", "criticality": "high"}
            for index in range(40)
        ],
        "event_refs": [{"event_uid": f"Security:{index}", "event_id": "4688"} for index in range(300)],
        "reason_codes": [f"REASON_{index}" for index in range(40)],
        "confidence_reasons": [f"reason {index}" for index in range(40)],
        "signal_refs": [f"Security:{index}" for index in range(300)],
        "timeline": [
            {"phase": "SUSPICIOUS_ACTIVITY", "timestamp": now - timedelta(minutes=index), "summary": str(index)}
            for index in range(80)
        ],
    }
    story = await upsert_security_story(db, payload)
    limit = get_settings().security_story_max_references
    assert len(story["affected_assets"]) == 20
    assert len(story["timeline"]) == 50
    assert len(story["reason_codes"]) == 20
    assert len(story["confidence_reasons"]) == 20
    assert len(story["event_refs"]) == limit
    assert len(story["signal_refs"]) == limit
    assert story["event_reference_count"] == limit
    assert story["reference_limit"] == limit
    assert story["first_seen"] <= story["last_seen"]

    with pytest.raises(ValueError):
        await upsert_security_story(db, {**payload, "story_id": "STORY-LOW", "technical_confidence": "LOW"})
    with pytest.raises(ValueError):
        await upsert_security_story(db, {**payload, "story_id": ""})


# --------------------------------------------------------------------------
# Canonical pipeline independence
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_incident_handoff_marker_is_durable_and_recovery_is_idempotent(db, stories_enabled):
    now = datetime.now(timezone.utc)
    alert = {
        "tenant_id": TENANT,
        "alert_uid": "story-alert-1",
        "event_uid": "Security:incident-handoff",
        "event_id": "4688",
        "type": "SUSPICIOUS_PROCESS",
        "severity": "HIGH",
        "status": "NEW",
        "timestamp": now,
        "agent_id": SERVER_ASSET["asset_id"],
        "source_ip": "10.20.0.50",
        "processed_data": {"SubjectUserName": "alice", "NewProcessName": "C:\\Windows\\System32\\cmd.exe"},
    }
    await db.security_alerts.insert_one(dict(alert))
    projection = await project_security_incident(db, alert)
    assert projection is not None
    occurrence = await db.security_incident_occurrences.find_one(
        {"occurrence_uid": projection["occurrence_uid"]}
    )
    assert occurrence["story_signal_status"] == "PENDING"

    assert await worker_module._recover_pending_incident_handoffs(db) == 1
    assert await worker_module._recover_pending_incident_handoffs(db) == 0
    recovered = await db.security_incident_occurrences.find_one({"_id": occurrence["_id"]})
    assert recovered["story_signal_status"] == "ENQUEUED"
    ledger = await db.story_signal_ledger.find(
        {"source_type": "incident"}
    ).to_list(length=10)
    assert len(ledger) == 1
    assert ledger[0]["source_uid"] == projection["occurrence_uid"]
    assert ledger[0]["signal"]["source_family"] == "detection"
    assert ledger[0]["signal"]["incident_id"] == projection["incident"]["incident_id"]


@pytest.mark.asyncio
async def test_story_failure_never_mutates_canonical_incident_state(db, stories_enabled, monkeypatch):
    now = datetime.now(timezone.utc)
    alert = {
        "tenant_id": TENANT,
        "alert_uid": "story-alert-2",
        "event_uid": "Security:incident-isolation",
        "event_id": "4688",
        "type": "SUSPICIOUS_PROCESS",
        "severity": "HIGH",
        "status": "NEW",
        "timestamp": now,
        "agent_id": SERVER_ASSET["asset_id"],
        "processed_data": {"SubjectUserName": "alice"},
    }
    await db.security_alerts.insert_one(dict(alert))
    await project_security_incident(db, alert)
    incidents_before = await db.security_incidents.find({}).to_list(length=10)
    occurrences_before = await db.security_incident_occurrences.count_documents({})

    async def _explode(*_args, **_kwargs):
        raise RuntimeError("story projection failed")

    monkeypatch.setattr(worker_module, "process_story_signal", _explode)
    signal = _signal("process_execution", event_uid="Security:isolation-1", event_id="4688", event_time=now)
    await enqueue_story_signal(db, source_type="event", source_uid=signal["event_uid"], signal=signal)
    assert await worker_module._drain_signal_ledger(db) == 1

    ledger = await db.story_signal_ledger.find_one({"source_uid": signal["event_uid"]})
    assert ledger["status"] == "RETRY"
    assert ledger["last_error_code"] == "RuntimeError"
    assert await db.security_stories.count_documents({}) == 0
    assert await db.security_incident_occurrences.count_documents({}) == occurrences_before
    assert await db.security_incidents.find({}).to_list(length=10) == incidents_before


@pytest.mark.asyncio
async def test_disabled_feature_writes_no_signals(db, stories_disabled):
    signal = _signal(
        "process_execution",
        event_uid="Security:disabled-1",
        event_id="4688",
        event_time=datetime.now(timezone.utc),
    )
    assert await enqueue_story_signal(db, source_type="event", source_uid=signal["event_uid"], signal=signal) is False
    assert await db.story_signal_ledger.count_documents({}) == 0

    alert = {
        "tenant_id": TENANT,
        "alert_uid": "story-alert-3",
        "event_uid": "Security:disabled-incident",
        "event_id": "4688",
        "type": "SUSPICIOUS_PROCESS",
        "severity": "HIGH",
        "status": "NEW",
        "timestamp": datetime.now(timezone.utc),
        "agent_id": SERVER_ASSET["asset_id"],
        "processed_data": {"SubjectUserName": "alice"},
    }
    projection = await project_security_incident(db, alert)
    assert projection is not None
    occurrence = await db.security_incident_occurrences.find_one(
        {"occurrence_uid": projection["occurrence_uid"]}
    )
    assert "story_signal_status" not in occurrence


@pytest.mark.asyncio
async def test_wazuh_shadow_candidates_never_create_stories(db, stories_enabled):
    from app.wazuh_integration.candidate_service import admit_candidate
    from app.wazuh_integration.contracts import DetectionCandidate

    class _WazuhSettings:
        wazuh_connector_id = "wazuh-story-connector"
        wazuh_engine_instance_id = "wazuh-story-manager"
        wazuh_engine_version = "4.14.7"
        wazuh_ruleset_version = "wazuh-rules-2026.08.1"
        wazuh_rule_registry_sha256 = "d010629631cfdc47b0a8807d91e605d8f6ba3a79d08e5be26e5e8e7c10b7a0d1"
        wazuh_candidate_signing_secret = "test-wazuh-candidate-secret-key-32b"
        wazuh_candidate_clock_skew_seconds = 60
        wazuh_candidate_delivery_max_age_seconds = 3600
        wazuh_shadow_retention_days = 90
        wazuh_detection_mode = "shadow"
        wazuh_primary_approved = False

    settings = _WazuhSettings()
    now = datetime.now(timezone.utc)
    event_record_id = "778899"
    canonical_event_uid = f"canonical-story-{secrets.token_hex(6)}"

    await db.detection_engine_connectors.insert_one(
        {
            "connector_id": settings.wazuh_connector_id,
            "engine_instance_id": settings.wazuh_engine_instance_id,
            "engine_version": settings.wazuh_engine_version,
            "ruleset_version": settings.wazuh_ruleset_version,
            "registry_sha256": settings.wazuh_rule_registry_sha256,
            "status": "active",
        }
    )
    await db.detection_rule_registry.insert_one(
        {
            "engine": "wazuh",
            "rule_id": "60105",
            "ruleset_version": settings.wazuh_ruleset_version,
            "registry_sha256": settings.wazuh_rule_registry_sha256,
            "source_family": "windows_endpoint",
            "category": "credential_attack",
            "family": "credential_attacks",
            "family_status": "shadow",
            "severity": "HIGH",
            "allowed_engine_levels": [5],
            "mitre_ids": ["T1110"],
            "candidate_enabled": True,
            "status": "approved",
            "candidate_context_fields": [],
        }
    )
    await db.detection_engine_agent_bindings.insert_one(
        {
            "engine": "wazuh",
            "engine_instance_id": settings.wazuh_engine_instance_id,
            "wazuh_agent_id": "001",
            "warsoc_agent_id": SERVER_ASSET["asset_id"],
            "tenant_id": TENANT,
            "endpoint_hostname": SERVER_ASSET["name"],
            "status": "active",
            "created_at": now,
            "updated_at": now,
        }
    )
    await db.siem_cold_vault.insert_one(
        {
            "event_uid": canonical_event_uid,
            "tenant_id": TENANT,
            "agent_id": SERVER_ASSET["asset_id"],
            "event_id": "4625",
            "event_record_id": event_record_id,
            "source_ip": "10.20.0.50",
            "user": "corp\\alice",
            "telemetry_family": "windows",
            "signature_verified": True,
            "source_assurance": "agent_signed",
            "timestamp": now.isoformat(),
            "raw_event_data": {"system": {"channel": "Security"}},
        }
    )

    outcome = await admit_candidate(
        db,
        DetectionCandidate(
            connector_id=settings.wazuh_connector_id,
            engine_instance_id=settings.wazuh_engine_instance_id,
            engine_version=settings.wazuh_engine_version,
            ruleset_version=settings.wazuh_ruleset_version,
            engine_alert_id=f"alert-{secrets.token_hex(6)}",
            engine_rule_id="60105",
            engine_rule_level=5,
            engine_detected_at=now,
            wazuh_agent_id="001",
            wazuh_agent_name="warsoc__story_endpoint",
            windows_event_id="4625",
            windows_event_record_id=event_record_id,
            windows_channel="Security",
            selected_security_fields={"targetUserName": "corp\\alice", "ipAddress": "10.20.0.50"},
            engine_reported_category="credential_attack",
            engine_reported_mitre_ids=["T1110"],
        ),
        settings,
        received_at=now,
    )
    assert outcome.outcome == "accepted"

    shadow = await db.detection_shadow_observations.find_one({"tenant_id": TENANT})
    assert shadow["mode"] == "shadow"
    assert await db.security_incidents.count_documents({}) == 0
    assert await db.story_signal_ledger.count_documents({}) == 0
    assert await db.security_stories.count_documents({}) == 0


# --------------------------------------------------------------------------
# Worker and Redis boundaries
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_story_group_starts_at_new_traffic_and_bounds_invalid_payloads(
    db, redis_client, stories_enabled
):
    await redis_client.xadd(RAW_LOGS_QUEUE, {"payload": json.dumps({"tenant_id": TENANT})})
    await redis_client.xadd(RAW_LOGS_QUEUE, {"payload": json.dumps({"tenant_id": TENANT})})
    await worker_module._ensure_group(redis_client)
    # A first enable must not replay historical raw telemetry.
    backlog = await redis_client.xreadgroup(
        STORY_SIGNAL_GROUP, "test-consumer", {RAW_LOGS_QUEUE: ">"}, count=10
    )
    assert [message for _, batch in backlog or [] for message in batch] == []
    # Re-creating the group is idempotent.
    await worker_module._ensure_group(redis_client)

    assert await worker_module._persist_raw_signal(db, {"payload": ""}) == "IGNORED"
    assert await worker_module._persist_raw_signal(db, {"payload": "not-json"}) == "INVALID"
    assert await worker_module._persist_raw_signal(db, {"payload": json.dumps([1, 2])}) == "INVALID"

    host_firewall_event = {
        "tenant_id": TENANT,
        "event_uid": "Security:worker-5156",
        "event_id": "5156",
        "event_type": "network_connection_permitted",
        "source_type": "windows_endpoint",
        "agent_id": SERVER_ASSET["asset_id"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "processed_data": {"src_ip": "10.20.0.10", "dst_ip": "93.184.216.34", "action": "allow"},
    }
    assert await worker_module._persist_raw_signal(db, {"payload": json.dumps(host_firewall_event)}) == "IGNORED"

    failed_logon_event = {
        "tenant_id": TENANT,
        "event_uid": "Security:worker-4625",
        "event_id": "4625",
        "event_type": "failed_logon",
        "source_type": "windows_endpoint",
        "agent_id": SERVER_ASSET["asset_id"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "processed_data": {"target_user": "CORP\\Alice", "source_network_address": "10.20.0.50", "logon_type": "3"},
    }
    assert await worker_module._persist_raw_signal(db, {"payload": json.dumps(failed_logon_event)}) == "PERSISTED"
    stored = await db.story_signal_ledger.find_one({"source_uid": "Security:worker-4625"})
    assert stored["status"] == "PENDING"
    assert stored["signal"]["signal_type"] == "failed_login"

    message_id = await redis_client.xadd(RAW_LOGS_QUEUE, {"payload": "not-json"})
    await redis_client.xreadgroup(STORY_SIGNAL_GROUP, "test-consumer", {RAW_LOGS_QUEUE: ">"}, count=10)
    await worker_module._consume_raw_messages(redis_client, db, [(message_id, {"payload": "not-json"})])
    assert int(await redis_client.get("warsoc_security_story_invalid_source_total")) == 1
    pending = await redis_client.xpending(RAW_LOGS_QUEUE, STORY_SIGNAL_GROUP)
    assert int(pending.get("pending", pending.get(b"pending", 0)) or 0) == 0


@pytest.mark.asyncio
async def test_stream_retention_requires_the_story_group_only_when_enabled(redis_client):
    stream = "raw-logs-story-retention"
    message_ids = [await redis_client.xadd(stream, {"payload": str(index)}) for index in range(4)]
    for group in {*RAW_REQUIRED_GROUPS, STORY_SIGNAL_GROUP}:
        await redis_client.xgroup_create(stream, group, id="0-0")
    for group in RAW_REQUIRED_GROUPS:
        rows = await redis_client.xreadgroup(group, f"{group}-consumer", {stream: ">"}, count=10)
        delivered = [message_id for _, messages in rows for message_id, _ in messages]
        await redis_client.xack(stream, group, *delivered)

    # When Security Stories participate, unread story entries pin retention.
    assert await trim_acknowledged_stream(redis_client, stream, {*RAW_REQUIRED_GROUPS, STORY_SIGNAL_GROUP}) == 0
    assert await redis_client.xlen(stream) == 4

    # When the feature is off the group is not required and cannot pin the stream.
    assert await trim_acknowledged_stream(redis_client, stream, RAW_REQUIRED_GROUPS) == 3
    remaining = [message_id for message_id, _ in await redis_client.xrange(stream)]
    assert remaining == message_ids[-1:]


# --------------------------------------------------------------------------
# Operator API
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_story_api_requires_authentication(async_client, stories_enabled):
    async_client.cookies.clear()
    for path in (
        "/api/v1/security-stories",
        "/api/v1/security-stories/status",
        "/api/v1/security-stories/summary",
        "/api/v1/security-stories/STORY-ANY",
    ):
        response = await async_client.get(path)
        assert response.status_code in {401, 403}, (path, response.status_code)


@pytest.mark.asyncio
async def test_story_api_enforces_roles_for_reads_and_workflow(
    async_client, auth_headers, db, stories_enabled
):
    tenant_id, user = await _api_tenant(db)
    await db.security_stories.insert_one(_story_document("STORY-RBAC", tenant_id))

    await db.users.update_one({"_id": user["_id"]}, {"$set": {"role": "analyst"}})
    listed = await async_client.get("/api/v1/security-stories", headers=auth_headers)
    assert listed.status_code == 200, listed.text
    patched = await async_client.patch(
        "/api/v1/security-stories/STORY-RBAC/status",
        headers=auth_headers,
        json={"expected_version": 1, "status": "ACKNOWLEDGED"},
    )
    assert patched.status_code == 403

    await db.users.update_one({"_id": user["_id"]}, {"$set": {"role": "viewer"}})
    denied = await async_client.get("/api/v1/security-stories", headers=auth_headers)
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_story_api_isolates_tenants_paginates_and_hides_raw_evidence(
    async_client, auth_headers, db, stories_enabled
):
    tenant_id, _ = await _api_tenant(db)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    await db.security_stories.insert_many(
        [
            _story_document("STORY-A", tenant_id, last_seen=now, first_seen=now),
            _story_document("STORY-B", tenant_id, last_seen=now - timedelta(minutes=5)),
            _story_document("STORY-C", tenant_id, last_seen=now - timedelta(minutes=10)),
            _story_document("STORY-CANDIDATE", tenant_id, status="CANDIDATE", technical_confidence="MEDIUM"),
            _story_document("STORY-CLOSED", tenant_id, status="CLOSED"),
            _story_document("STORY-FOREIGN", OTHER_TENANT),
        ]
    )

    first_page = await async_client.get(
        "/api/v1/security-stories", headers=auth_headers, params={"limit": 2}
    )
    assert first_page.status_code == 200, first_page.text
    body = first_page.json()
    assert [item["story_id"] for item in body["data"]] == ["STORY-A", "STORY-B"]
    assert body["has_more"] is True
    assert body["next_cursor"]

    second_page = await async_client.get(
        "/api/v1/security-stories",
        headers=auth_headers,
        params={"limit": 2, "next_cursor": body["next_cursor"]},
    )
    assert [item["story_id"] for item in second_page.json()["data"]] == ["STORY-C"]
    assert second_page.json()["has_more"] is False

    listed = first_page.json()["data"][0]
    assert "tenant_id" not in listed
    assert "event_refs" not in listed
    assert "timeline" not in listed
    assert listed["detection_source"] == "WarSOC"
    assert listed["evidence_state"] == "SOURCE_REFERENCED"

    candidates = await async_client.get(
        "/api/v1/security-stories", headers=auth_headers, params={"include_candidates": True}
    )
    assert "STORY-CANDIDATE" in [item["story_id"] for item in candidates.json()["data"]]
    filtered = await async_client.get(
        "/api/v1/security-stories", headers=auth_headers, params={"asset_id": SERVER_ASSET["asset_id"]}
    )
    assert filtered.json()["returned"] == 3
    assert (
        await async_client.get(
            "/api/v1/security-stories", headers=auth_headers, params={"status": "BOGUS"}
        )
    ).status_code == 400
    assert (
        await async_client.get(
            "/api/v1/security-stories", headers=auth_headers, params={"next_cursor": "not-a-cursor"}
        )
    ).status_code == 400

    detail = await async_client.get("/api/v1/security-stories/STORY-A", headers=auth_headers)
    assert detail.status_code == 200, detail.text
    payload = detail.json()["data"]
    assert "tenant_id" not in payload
    assert payload["event_refs"][0]["event_uid"] == "Security:api-1"
    assert payload["timeline"]

    foreign = await async_client.get("/api/v1/security-stories/STORY-FOREIGN", headers=auth_headers)
    assert foreign.status_code == 404


@pytest.mark.asyncio
async def test_story_workflow_enforces_optimistic_version_and_audits_operators(
    async_client, auth_headers, db, stories_enabled
):
    tenant_id, _ = await _api_tenant(db)
    await db.security_stories.insert_one(_story_document("STORY-WORKFLOW", tenant_id))
    await db.security_stories.insert_one(_story_document("STORY-WORKFLOW-FOREIGN", OTHER_TENANT))

    acknowledged = await async_client.patch(
        "/api/v1/security-stories/STORY-WORKFLOW/status",
        headers=auth_headers,
        json={"expected_version": 1, "status": "ACKNOWLEDGED", "notes": "Investigating"},
    )
    assert acknowledged.status_code == 200, acknowledged.text
    data = acknowledged.json()["data"]
    assert data["status"] == "ACKNOWLEDGED"
    assert data["version"] == 2
    assert data["workflow_history"][-1]["from_status"] == "OPEN"
    assert data["workflow_history"][-1]["notes"] == "Investigating"
    assert data["workflow_history"][-1]["operator_role"] == "admin"

    conflict = await async_client.patch(
        "/api/v1/security-stories/STORY-WORKFLOW/status",
        headers=auth_headers,
        json={"expected_version": 1, "status": "CLOSED"},
    )
    assert conflict.status_code == 409

    invalid = await async_client.patch(
        "/api/v1/security-stories/STORY-WORKFLOW/status",
        headers=auth_headers,
        json={"expected_version": 2, "status": "DELETED"},
    )
    assert invalid.status_code == 422
    extra_field = await async_client.patch(
        "/api/v1/security-stories/STORY-WORKFLOW/status",
        headers=auth_headers,
        json={"expected_version": 2, "status": "CLOSED", "technical_severity": "LOW"},
    )
    assert extra_field.status_code == 422

    foreign = await async_client.patch(
        "/api/v1/security-stories/STORY-WORKFLOW-FOREIGN/status",
        headers=auth_headers,
        json={"expected_version": 1, "status": "CLOSED"},
    )
    assert foreign.status_code == 404
    untouched = await db.security_stories.find_one({"story_id": "STORY-WORKFLOW-FOREIGN"})
    assert untouched["status"] == "OPEN"
    assert untouched["version"] == 1


@pytest.mark.asyncio
async def test_story_summary_counts_open_candidate_and_priority_buckets(
    async_client, auth_headers, db, stories_enabled
):
    tenant_id, _ = await _api_tenant(db)
    await db.security_stories.insert_many(
        [
            _story_document("STORY-SUM-1", tenant_id, attention_priority="URGENT"),
            _story_document("STORY-SUM-2", tenant_id, status="ACKNOWLEDGED"),
            _story_document(
                "STORY-SUM-3",
                tenant_id,
                status="CANDIDATE",
                technical_confidence="MEDIUM",
                story_type="SERVER_COMPROMISE_PERSISTENCE",
            ),
            _story_document("STORY-SUM-4", OTHER_TENANT, attention_priority="URGENT"),
        ]
    )
    summary = await async_client.get("/api/v1/security-stories/summary", headers=auth_headers)
    assert summary.status_code == 200, summary.text
    data = summary.json()["data"]
    assert data["open_total"] == 2
    assert data["candidate_total"] == 1
    assert data["urgent_open"] == 1
    assert data["new_24h"] == 3
    assert data["by_priority"] == {"URGENT": 1, "HIGH": 1}
    assert data["by_type"] == {"SERVER_ACCOUNT_COMPROMISE": 2}


@pytest.mark.asyncio
async def test_story_api_is_hidden_when_disabled_but_status_reports_capability(
    async_client, auth_headers, db, stories_disabled
):
    tenant_id, _ = await _api_tenant(db)
    await db.security_stories.insert_one(_story_document("STORY-DISABLED", tenant_id))

    status_response = await async_client.get("/api/v1/security-stories/status", headers=auth_headers)
    assert status_response.status_code == 200, status_response.text
    data = status_response.json()["data"]
    assert data["enabled"] is False
    assert data["detection_source"] == "WarSOC"
    assert data["medium_confidence_mode"] == "CANDIDATE"
    assert data["wazuh_candidate_policy"] == "SHADOW_NOT_ACTIONABLE"

    for method, path in (
        ("get", "/api/v1/security-stories"),
        ("get", "/api/v1/security-stories/summary"),
        ("get", "/api/v1/security-stories/STORY-DISABLED"),
    ):
        response = await getattr(async_client, method)(path, headers=auth_headers)
        assert response.status_code == 404, (path, response.status_code)

    patched = await async_client.patch(
        "/api/v1/security-stories/STORY-DISABLED/status",
        headers=auth_headers,
        json={"expected_version": 1, "status": "CLOSED"},
    )
    assert patched.status_code == 404
    unchanged = await db.security_stories.find_one({"story_id": "STORY-DISABLED"})
    assert unchanged["status"] == "OPEN"

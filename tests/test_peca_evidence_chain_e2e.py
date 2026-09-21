import pytest
import pytest_asyncio
import asyncio
from contextlib import suppress
import httpx
import uuid
import time
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization

from app.workers.peca_worker import peca_worker
from app.utils.agent_crypto import build_event_signature_string, build_payload_hash, build_signable_event_payload
from tests.helpers import ed25519_keypair_pem, provision_and_login_admin
from app.utils.compliance_chain import (
    CHAIN_VERSION,
    aggregate_evidence_digest,
    compute_daily_root,
    evidence_record_digest,
    genesis_root,
    verify_ledger_entry,
    verify_ledger_sequence,
)
from app.utils.evidence_claims import evaluate_evidence_claim

pytestmark = [pytest.mark.asyncio, pytest.mark.backend]


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _http_event(event_id, event_uid, tenant_id, agent_id, message, source_ip, private_key_pem, user=None):
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
        "raw_data": message,
    }
    payload_hash = build_payload_hash(build_signable_event_payload(payload))
    signature_input = build_event_signature_string(agent_id, payload["timestamp"], event_uid, payload_hash)
    payload["payload_hash"] = payload_hash
    payload["signature_version"] = "ed25519-v1"
    payload["signature_algorithm"] = "Ed25519"
    payload["agent_signature"] = sk.sign(signature_input.encode("utf-8")).hex()
    return payload


@pytest_asyncio.fixture(scope="function")
async def peca_test_state(async_client, db, redis_client):
    """
    Setup fixture that provisions a tenant with peca_forensic,
    registers an agent with Ed25519 keys, injects 11 PECA and 2 non-PECA events,
    runs peca_worker, and collects the resulting forensic logs.
    """
    state = {}

    session = await provision_and_login_admin(
        async_client,
        "peca_e2e",
        api_prefix="/api/v1",
        retention_days=270,
    )
    tenant_id = session["tenant_id"]

    # Ensure Redis tenant feature set enables PECA
    await redis_client.set(f"tenant_features:{tenant_id}", "siem,fbr_pos,peca_forensic")

    # Create consumer groups
    for grp in ["fbr_group", "siem_group", "eto_group"]:
        try:
            await redis_client.xgroup_create("raw_logs_queue", grp, id="0", mkstream=True)
        except Exception:
            pass

    # Clean prior logs for this tenant
    await db.peca_forensic_logs.delete_many({"tenant_id": tenant_id})

    # Register Agent
    private_key_pem, public_key_pem = ed25519_keypair_pem()
    activation_resp = await async_client.post("/api/v1/agent/generate-activation")
    assert activation_resp.status_code == 200
    activation_code = activation_resp.json()["activation_code"]

    reg_resp = await async_client.post(
        "/api/v1/agent/register",
        json={
            "activation_code": activation_code,
            "public_key": public_key_pem,
            "features": "SIEM,FBR,PECA",
        },
    )
    assert reg_resp.status_code == 200
    agent_data = reg_resp.json()
    agent_id = agent_data["agent_id"]
    agent_jwt = agent_data["agent_jwt"]

    expected_peca_events = {
        "4624": "Successful logon",
        "4625": "Failed login attempt for Administrator",
        "4672": "Special privileges assigned to a new logon",
        "4688": "A new process has been created",
        "4720": "A user account was created",
        "4726": "A user account was deleted",
        "4732": "A member was added to a local security group",
        "4697": "A service was installed in the system",
        "7045": "A new Windows service was installed",
        "1100": "The event logging service has shut down",
        "1102": "The audit log was cleared",
    }

    peca_payloads = [
        _http_event(
            event_id=eid,
            event_uid=f"peca-{eid}-{uuid.uuid4().hex[:8]}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            message=msg,
            source_ip="10.0.0.100",
            private_key_pem=private_key_pem,
        )
        for eid, msg in expected_peca_events.items()
    ]

    non_peca_fbr = _http_event(
        event_id="FBR-INV-DEL",
        event_uid=f"non-peca-fbr-{uuid.uuid4().hex[:8]}",
        tenant_id=tenant_id,
        agent_id=agent_id,
        message="Invoice Deleted Non PECA",
        source_ip="10.0.0.200",
        private_key_pem=private_key_pem,
    )

    non_peca_net = _http_event(
        event_id="5157",
        event_uid=f"non-peca-fw-{uuid.uuid4().hex[:8]}",
        tenant_id=tenant_id,
        agent_id=agent_id,
        message="Firewall Blocked Non PECA",
        source_ip="10.0.0.201",
        private_key_pem=private_key_pem,
    )

    # Ingest all events via /api/v1/ingest/pulse
    envelope = {
        "nonce": uuid.uuid4().hex,
        "timestamp": int(time.time()),
        "payload": [*peca_payloads, non_peca_fbr, non_peca_net],
    }

    resp = await async_client.post(
        "/api/v1/ingest/pulse",
        headers={"Authorization": f"Bearer {agent_jwt}"},
        json=envelope,
    )
    assert resp.status_code in (200, 202), resp.text

    # Run peca_worker until all 11 events are stored
    worker_task = asyncio.create_task(peca_worker())
    try:
        deadline = asyncio.get_running_loop().time() + 20
        while asyncio.get_running_loop().time() < deadline:
            count = await db.peca_forensic_logs.count_documents({"tenant_id": tenant_id})
            if count >= len(expected_peca_events):
                break
            await asyncio.sleep(0.3)
    finally:
        worker_task.cancel()
        with suppress(asyncio.CancelledError):
            await worker_task

    docs = await db.peca_forensic_logs.find({"tenant_id": tenant_id}).to_list(length=100)

    state["tenant_id"] = tenant_id
    state["agent_id"] = agent_id
    state["docs"] = docs
    state["expected_peca_events"] = expected_peca_events

    return state


async def test_all_11_peca_events_captured(peca_test_state):
    """
    Scenario 1: All 11 PECA Events Captured
    Assert all 11 event IDs (4624, 4625, 4672, 4688, 4720, 4726, 4732, 4697, 7045, 1100, 1102)
    are processed by peca_worker and written to peca_forensic_logs with correct metadata.
    """
    docs = peca_test_state["docs"]
    stored_event_ids = [str(log.get("event_id")) for log in docs]
    expected_ids = set(peca_test_state["expected_peca_events"].keys())

    assert expected_ids <= set(stored_event_ids), (
        f"Missing PECA evidence IDs: {sorted(expected_ids - set(stored_event_ids))}"
    )

    for log in docs:
        assert log.get("compliance_pack") == "peca_forensic"
        assert "matched_rule_id" in log
        assert log.get("retention_model") == "TENANT_ENTITLEMENT_V1"
        assert log.get("retention_policy") == "TENANT_ENTITLEMENT"


async def test_non_peca_event_isolation(peca_test_state):
    """
    Scenario 2: Non-PECA Event Isolation
    Assert non-PECA events (FBR-INV-DEL, 5157) NEVER leak into peca_forensic_logs.
    """
    docs = peca_test_state["docs"]
    stored_event_ids = [str(log.get("event_id")) for log in docs]

    assert "FBR-INV-DEL" not in stored_event_ids, "FBR-INV-DEL must NOT be stored in peca_forensic_logs"
    assert "5157" not in stored_event_ids, "5157 must NOT be stored in peca_forensic_logs"


async def test_rsa_pss_digital_signature_present(peca_test_state):
    """
    Scenario 3: RSA-PSS Digital Signature
    Assert each forensic record has a valid digital_signature and forensic_seal.
    """
    docs = peca_test_state["docs"]
    assert len(docs) >= 11
    for log in docs:
        assert log.get("digital_signature"), f"Event {log.get('event_id')} missing digital_signature"
        assert log.get("forensic_seal"), f"Event {log.get('event_id')} missing forensic_seal"
        assert log.get("canonicalization_version") == "canonicaljson-v1"


async def test_fernet_field_encryption(peca_test_state):
    """
    Scenario 4: Fernet Field Encryption
    Assert that sensitive payload fields are Fernet-encrypted and raw plaintext does not appear directly.
    """
    docs = peca_test_state["docs"]
    for log in docs:
        raw_event = str(log.get("raw_event_data") or "")
        assert log.get("encryption_version") == "fernet-v1"
        if raw_event:
            assert raw_event.startswith("fernet-v1:") or raw_event.startswith("gAAAAA")


async def test_retention_model_uses_tenant_entitlement(peca_test_state):
    """
    Scenario 5: Retention Model (Indefinite Storage)
    Assert records have retention_model='TENANT_ENTITLEMENT_V1' and NO _expire_at.
    """
    docs = peca_test_state["docs"]
    for log in docs:
        assert log.get("retention_model") == "TENANT_ENTITLEMENT_V1"
        assert log.get("retention_policy") == "TENANT_ENTITLEMENT"
        assert "_expire_at" not in log, "PECA forensic logs must not have TTL _expire_at"


async def test_daily_ledger_chain_integrity(peca_test_state):
    """
    Scenario 6: Daily Ledger Chain Integrity
    Assert that compliance_chain computes a valid SHA-256 daily root from peca_forensic_logs
    and chained ledger sequence passes verify_ledger_sequence.
    """
    docs = peca_test_state["docs"]
    tenant_id = peca_test_state["tenant_id"]

    records = [("peca_forensic_logs", doc) for doc in docs]
    digest, count, source_counts = aggregate_evidence_digest(records)
    assert len(digest) == 64
    assert count == len(docs)

    prev_root = genesis_root(tenant_id)
    daily_root_1 = compute_daily_root(
        tenant_id=tenant_id,
        date_str="2026-09-18",
        previous_root_hash=prev_root,
        evidence_digest=digest,
        log_count=count,
        source_counts=source_counts,
    )

    entry1 = {
        "tenant_id": tenant_id,
        "date": "2026-09-18",
        "chain_version": CHAIN_VERSION,
        "previous_root_hash": prev_root,
        "evidence_digest": digest,
        "daily_root_hash": daily_root_1,
        "log_count": count,
        "source_counts": source_counts,
    }
    assert verify_ledger_entry(entry1) is True

    # Day 2 entry chained to Day 1
    daily_root_2 = compute_daily_root(
        tenant_id=tenant_id,
        date_str="2026-09-19",
        previous_root_hash=daily_root_1,
        evidence_digest="b" * 64,
        log_count=1,
        source_counts={"peca_forensic_logs": 1},
    )
    entry2 = {
        "tenant_id": tenant_id,
        "date": "2026-09-19",
        "chain_version": CHAIN_VERSION,
        "previous_root_hash": daily_root_1,
        "evidence_digest": "b" * 64,
        "daily_root_hash": daily_root_2,
        "log_count": 1,
        "source_counts": {"peca_forensic_logs": 1},
    }

    result = verify_ledger_sequence([entry1, entry2])
    assert result["verified"] is True
    assert result["continuous"] is True


async def test_evidence_claim_evaluation(peca_test_state):
    """
    Scenario 7: Evidence Claim Evaluation
    Assert evaluate_evidence_claim validates server_integrity_protected=True
    for all stored PECA forensic records.
    """
    docs = peca_test_state["docs"]
    rule = {"evidence_source_class": "WINDOWS_EVENT"}

    for doc in docs:
        claim = evaluate_evidence_claim(doc, "peca_forensic", rule)
        assert claim["evidence_checks"]["server_integrity_protected"] is True, (
            f"Event {doc.get('event_id')} failed server_integrity_protected claim"
        )
        assert claim["evidence_checks"]["identity_complete"] is True


async def test_tenant_entitlement_gate(async_client, db, redis_client):
    """
    Scenario 8: Tenant Entitlement Gate
    Assert tenants WITHOUT peca_forensic in their entitlements do NOT get records written to peca_forensic_logs.
    """
    session = await provision_and_login_admin(
        async_client,
        "no_peca_e2e",
        api_prefix="/api/v1",
        retention_days=270,
    )
    tenant_id = session["tenant_id"]

    # Entitlement has ONLY SIEM (no peca_forensic)
    await redis_client.set(f"tenant_features:{tenant_id}", "siem")
    await db.peca_forensic_logs.delete_many({"tenant_id": tenant_id})

    # Create consumer groups if not already created
    for grp in ["fbr_group", "siem_group", "eto_group"]:
        try:
            await redis_client.xgroup_create("raw_logs_queue", grp, id="0", mkstream=True)
        except Exception:
            pass

    private_key_pem, public_key_pem = ed25519_keypair_pem()
    activation_resp = await async_client.post("/api/v1/agent/generate-activation")
    activation_code = activation_resp.json()["activation_code"]

    reg_resp = await async_client.post(
        "/api/v1/agent/register",
        json={
            "activation_code": activation_code,
            "public_key": public_key_pem,
            "features": "SIEM",
        },
    )
    agent_data = reg_resp.json()
    agent_id = agent_data["agent_id"]
    agent_jwt = agent_data["agent_jwt"]

    payload = _http_event(
        event_id="4625",
        event_uid=f"unentitled-{uuid.uuid4().hex[:8]}",
        tenant_id=tenant_id,
        agent_id=agent_id,
        message="Unentitled failed login",
        source_ip="10.0.0.100",
        private_key_pem=private_key_pem,
    )

    envelope = {
        "nonce": uuid.uuid4().hex,
        "timestamp": int(time.time()),
        "payload": [payload],
    }

    await async_client.post(
        "/api/v1/ingest/pulse",
        headers={"Authorization": f"Bearer {agent_jwt}"},
        json=envelope,
    )

    worker_task = asyncio.create_task(peca_worker())
    try:
        await asyncio.sleep(2.0)
    finally:
        worker_task.cancel()
        with suppress(asyncio.CancelledError):
            await worker_task

    count = await db.peca_forensic_logs.count_documents({"tenant_id": tenant_id})
    assert count == 0, f"Unentitled tenant should have 0 PECA logs, found {count}"

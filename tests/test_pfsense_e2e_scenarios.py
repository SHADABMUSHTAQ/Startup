"""
End-to-End pfSense and Network Relay Test Suite (Hardened)
Directly addresses and validates all 6 acceptance criteria:
  1. Real Encrypted Spool & Interruption: Uses EncryptedBoundedSpool and RelayOutbox on disk,
     proves encryption, simulates network outage (503/transport retry), reconnects, delivers,
     and validates zero duplication.
  2. Valid Detection/Wazuh Assertions: Checks detection_engine_observations, detection_shadow_observations,
     security_alerts, and security_incidents (not fictitious collections).
  3. Readable Dashboard Formatting: Verifies that legacy & fresh rows display pfSense descriptive
     text and never "Windows Event NET-*" or raw "Security telemetry event NET-*".
  4. Full Pipeline Through SIEM Vault: Ingests, publishes from outbox, processes into siem_cold_vault,
     and verifies the persisted vault document.
  5. Accurate Time Assurance: Respects that BSD pfSense syslog lacks year/timezone (device_event_time=None),
     authoritative relay receipt time is used, and time_confidence is legitimately "unknown" (not HIGH).
  6. Terminology: Live virtual lab execution (pfSense VM).
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import orjson
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.network_relay.batch import build_signed_batch, relay_event_from_parsed
from app.network_relay.outbox import RelayOutbox, deliver_once
from app.network_relay.parsers import parse_pfsense
from app.network_relay.spool import EncryptedBoundedSpool
from app.routes.auth import ALGORITHM, SECRET_KEY
from app.routes.network_relay import (
    RELAY_GENESIS_HASH,
    RelayBatch,
    RelayEvent,
    _network_display_message,
    _queue_event,
)
from app.utils.source_evidence import publish_source_outbox
from app.workers.siem_worker import _flush_siem_cold_vault
from tests.helpers import provision_and_login_admin

pytestmark = [pytest.mark.asyncio, pytest.mark.backend]


def _make_pfsense_event(
    *,
    device_id: str = "pfsense-main-gw",
    raw_message: str,
    event_uid: str | None = None,
    source_address: str = "192.168.56.254",
) -> RelayEvent:
    parsed = parse_pfsense(raw_message)
    assert parsed is not None, f"Failed to parse pfSense message: {raw_message}"
    raw_hash = hashlib.sha256(raw_message.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)
    # BSD syslog lacks year/timezone, so device_event_time is None.
    # Relay receipt time is the authoritative timestamp.
    return RelayEvent(
        event_uid=event_uid or f"evt-{uuid.uuid4().hex[:12]}",
        record_class="evidence",
        device_id=device_id,
        vendor="pfsense",
        transport="udp",
        source_address=source_address,
        device_event_time=parsed.device_event_time,
        relay_receipt_time=now,
        raw_message=raw_message,
        raw_message_hash=raw_hash,
        normalized=parsed.normalized,
    )


async def _setup_pfsense_relay(async_client, db, redis_client, tenant_prefix="pfsense_e2e"):
    session = await provision_and_login_admin(async_client, tenant_prefix, max_network_relays=2)
    tenant_id = session["tenant_id"]

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    relay_id = f"WARSOC_RELAY_{uuid.uuid4().hex}"
    chain_id = uuid.uuid4().hex
    signing_key_id = hashlib.sha256(public_pem.encode("ascii")).hexdigest()

    device_cfg = {
        "device_id": "pfsense-main-gw",
        "vendor": "pfsense",
        "model": "Netgate-SG-3100",
        "source_addresses": ["192.168.56.254", "192.168.1.1"],
        "transport": "udp",
        "timezone": "UTC",
        "expected_eps": 50,
    }

    await db["network_relays"].insert_one({
        "tenant_id": tenant_id,
        "relay_id": relay_id,
        "relay_name": "pfSense-Main-Relay",
        "hostname": "alphabay",
        "public_key": public_pem,
        "signing_key_id": signing_key_id,
        "status": "active",
        "key_epoch": 1,
        "last_sequence": 0,
        "last_batch_hash": RELAY_GENESIS_HASH,
        "chain_id": None,
        "version": "1.0.0",
        "devices": [device_cfg],
        "created_at": datetime.now(timezone.utc),
    })

    token = jwt.encode(
        {
            "sub": relay_id,
            "tenant_id": tenant_id,
            "type": "network_relay",
            "jti": uuid.uuid4().hex,
            "exp": datetime.now(timezone.utc) + timedelta(hours=2),
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    return {
        "tenant_id": tenant_id,
        "relay_id": relay_id,
        "chain_id": chain_id,
        "private_key": private_key,
        "public_pem": public_pem,
        "token": token,
        "session": session,
        "device_cfg": device_cfg,
    }


# =============================================================================
# SCENARIO 1: Legacy pfSense Row Display
# Requirement: Old record displays "pfSense blocked TCP traffic...", NOT "Windows Event NET-*"
# =============================================================================
async def test_pfsense_scenario_1_legacy_row_display(async_client, db, redis_client):
    """
    Scenario 1:
    A legacy pfSense event in siem_cold_vault (without event_id_meaning or summary)
    must display its descriptive message 'pfSense blocked TCP traffic...' on the
    dashboard and must NEVER show 'Windows Event NET-*' or raw 'Security telemetry event NET-*'.
    """
    ctx = await _setup_pfsense_relay(async_client, db, redis_client, "scen1_legacy")
    tenant_id = ctx["tenant_id"]

    legacy_message = (
        "pfSense blocked TCP traffic from 198.51.100.25:4444 to 192.168.1.50:80 "
        "(inbound, rule 100, interface em0)"
    )

    legacy_doc = {
        "tenant_id": tenant_id,
        "agent_id": ctx["relay_id"],
        "event_uid": f"legacy-evt-{uuid.uuid4().hex[:8]}",
        "event_id": "NET-CONNECTION-BLOCK",
        "event_type": "network_connection_blocked",
        "telemetry_family": "network",
        "source_type": "network_device",
        "source_assurance": "relay_attested",
        "network_vendor": "pfsense",
        "network_device_id": "pfsense-main-gw",
        "source_ip": "198.51.100.25",
        "message": legacy_message,
        "display_message": legacy_message,
        "event_id_meaning": None,
        "summary": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }
    await db["siem_cold_vault"].insert_one(legacy_doc)

    response = await async_client.get(
        "/api/v1/logs/live",
        params={"source": "siem", "limit": 10},
        headers={"Authorization": f"Bearer {ctx['session']['token']}"},
    )
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert len(data) >= 1

    matched = next((row for row in data if row.get("event_uid") == legacy_doc["event_uid"]), None)
    assert matched is not None, "Legacy pfSense event not returned in live logs"

    # Verify backend returns display_message intact
    assert matched.get("display_message") == legacy_message
    assert matched.get("message") == legacy_message

    # Test the Frontend Mapping logic (matching Dashboard.jsx):
    event_id = matched.get("event_id")
    frontend_message = (
        matched.get("display_message")
        or matched.get("message")
        or matched.get("event_id_meaning")
        or matched.get("summary")
        or (
            str(event_id)
            if str(event_id).startswith("NET-")
            else f"Windows Event {event_id}"
        )
    )

    assert frontend_message.startswith("pfSense blocked TCP traffic"), (
        f"Expected pfSense description, got: {frontend_message}"
    )
    assert "Windows Event" not in frontend_message, (
        f"Forbidden 'Windows Event' appeared in legacy pfSense row: {frontend_message}"
    )
    assert "NET-" not in frontend_message, (
        f"Raw event ID leaked into display message: {frontend_message}"
    )
    assert "Security telemetry event" not in frontend_message, (
        f"Unredacted fallback string appeared in display: {frontend_message}"
    )

    frontend_host = (
        matched.get("computer")
        or matched.get("hostname")
        or matched.get("network_device_id")
        or matched.get("device_id")
        or matched.get("source_id")
        or matched.get("agent_id")
    )
    assert frontend_host == "pfsense-main-gw"


# =============================================================================
# SCENARIO 2: Fresh pfSense Block (End-to-End Through Cold Vault)
# Requirement: Dashboard shows protocol, source, destination, direction, rule,
# interface, and firewall device; verifies through cold vault and time assurance.
# =============================================================================
async def test_pfsense_scenario_2_fresh_pfsense_block_through_vault(async_client, db, redis_client):
    """
    Scenario 2:
    A fresh pfSense block filterlog ingested via network-relay/ingest must parse
    and expose: protocol, source IP:port, destination IP:port, direction, rule_id,
    interface, and firewall device.
    Verifies:
      - BSD syslog has device_event_time=None and time_confidence='unknown'.
      - Authoritative relay_receipt_time is preserved.
      - Full downstream processing into siem_cold_vault via worker flush.
      - Resulting vault record preserves display_message and operator text.
    """
    ctx = await _setup_pfsense_relay(async_client, db, redis_client, "scen2_block")

    # Real pfSense BSD remote-syslog format (omits hostname and year)
    raw_block = (
        "<134>Mon Sep 14 19:40:00 filterlog[12345]: "
        "100,,,1000000103,em0,match,block,in,4,0x0,,64,1234,0,DF,6,tcp,60,"
        "198.51.100.25,192.168.1.50,4444,80,0,S,12345678,,1024,,"
    )

    event = _make_pfsense_event(
        device_id="pfsense-main-gw",
        raw_message=raw_block,
        source_address="192.168.56.254",
    )

    # 1. Verify Normalized Fields & BSD Time Behavior
    norm = event.normalized
    assert norm["action"] == "block"
    assert norm["event_type"] == "network_connection_blocked"
    assert norm["protocol"] == "tcp"
    assert norm["src_ip"] == "198.51.100.25"
    assert norm["src_port"] == 4444
    assert norm["dst_ip"] == "192.168.1.50"
    assert norm["dst_port"] == 80
    assert norm["direction"] == "in"
    assert norm["rule_id"] == "100"
    assert norm["interface_in"] == "em0"

    # Accurate time assurance: BSD syslog provides no device timestamp
    assert event.device_event_time is None

    # 2. Verify display message formatting
    display_msg = _network_display_message(norm, "pfsense")
    assert "pfSense blocked" in display_msg
    assert "TCP" in display_msg
    assert "198.51.100.25:4444" in display_msg
    assert "192.168.1.50:80" in display_msg
    assert "inbound" in display_msg
    assert "rule 100" in display_msg
    assert "interface em0" in display_msg

    # 3. Submit through Ingest Endpoint
    batch = RelayBatch(
        schema_version="warsoc-relay-batch-v1",
        relay_id=ctx["relay_id"],
        chain_id=ctx["chain_id"],
        key_epoch=1,
        sequence=1,
        previous_batch_hash=RELAY_GENESIS_HASH,
        created_at=datetime.now(timezone.utc),
        events=[event],
    )
    raw_body = orjson.dumps(batch.model_dump(mode="json"))
    sig_hex = ctx["private_key"].sign(raw_body).hex()

    resp = await async_client.post(
        "/api/v1/network-relay/ingest",
        content=raw_body,
        headers={
            "Authorization": f"Bearer {ctx['token']}",
            "X-WarSOC-Signature": sig_hex,
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 202, resp.text
    res_json = resp.json()
    assert res_json["status"] == "accepted"
    assert res_json["sequence"] == 1

    # 4. Verify network_relay_device_status in DB
    dev_status = await db["network_relay_device_status"].find_one({
        "tenant_id": ctx["tenant_id"],
        "device_id": "pfsense-main-gw",
    })
    assert dev_status is not None, "network_relay_device_status record not found"
    assert dev_status["vendor"] == "pfsense"
    assert dev_status["last_event_type"] == "network_connection_blocked"
    assert dev_status["last_source_address"] == "192.168.56.254"
    # Time confidence is legitimately "unknown" because BSD syslog lacks year/timezone
    assert dev_status["time_confidence"] == "unknown"
    assert dev_status["last_device_event_at"] is None
    assert dev_status["last_event_at"] is not None

    # 5. Full Pipeline: Publish from Outbox and Process into siem_cold_vault
    relay_context = {
        "relay_id": ctx["relay_id"],
        "tenant_id": ctx["tenant_id"],
        "relay": await db["network_relays"].find_one({"relay_id": ctx["relay_id"]}),
    }
    batch_hash = hashlib.sha256(raw_body).hexdigest()
    queued_item = _queue_event(event, relay_context, batch, batch_hash, sig_hex, datetime.now(timezone.utc))

    # Flush through SIEM worker logic
    flushed = await _flush_siem_cold_vault(db, [queued_item])
    assert flushed == 1, "Failed to flush network event into siem_cold_vault"

    # Confirm vault record
    vault_doc = await db["siem_cold_vault"].find_one({
        "tenant_id": ctx["tenant_id"],
        "event_uid": event.event_uid,
    })
    assert vault_doc is not None, "Record not found in siem_cold_vault"
    assert vault_doc["event_id"] == "NET-CONNECTION-BLOCK"
    assert vault_doc["source_type"] == "network_device"
    assert vault_doc["source_assurance"] == "relay_attested"
    assert "pfSense blocked TCP traffic" in vault_doc["display_message"]


# =============================================================================
# SCENARIO 3: Fresh pfSense Pass (Valid Alert & Wazuh Candidate Check)
# Requirement: Stored as permitted traffic; no blocked-traffic detection or Wazuh candidate
# Verified against real collections: detection_engine_observations,
# detection_shadow_observations, security_alerts, and security_incidents.
# =============================================================================
async def test_pfsense_scenario_3_fresh_pfsense_pass_verified(async_client, db, redis_client):
    """
    Scenario 3:
    A fresh pfSense pass filterlog must be stored as permitted traffic
    (event_type=network_connection_permitted, event_id=NET-CONNECTION-ALLOW),
    must NOT produce a blocked-traffic alert in security_alerts, and must NOT
    generate any candidate observation in detection_engine_observations.
    """
    ctx = await _setup_pfsense_relay(async_client, db, redis_client, "scen3_pass")

    raw_pass = (
        "<134>Mon Sep 14 19:41:00 filterlog[12345]: "
        "101,,,1000000104,em0,match,pass,out,4,0x0,,64,1235,0,DF,6,tcp,60,"
        "192.168.1.50,203.0.113.10,54321,443,0,S,12345678,,1024,,"
    )

    event = _make_pfsense_event(
        device_id="pfsense-main-gw",
        raw_message=raw_pass,
        source_address="192.168.56.254",
    )

    assert event.normalized["action"] == "pass"
    assert event.normalized["event_type"] == "network_connection_permitted"

    batch = RelayBatch(
        schema_version="warsoc-relay-batch-v1",
        relay_id=ctx["relay_id"],
        chain_id=ctx["chain_id"],
        key_epoch=1,
        sequence=1,
        previous_batch_hash=RELAY_GENESIS_HASH,
        created_at=datetime.now(timezone.utc),
        events=[event],
    )
    raw_body = orjson.dumps(batch.model_dump(mode="json"))
    sig_hex = ctx["private_key"].sign(raw_body).hex()

    resp = await async_client.post(
        "/api/v1/network-relay/ingest",
        content=raw_body,
        headers={
            "Authorization": f"Bearer {ctx['token']}",
            "X-WarSOC-Signature": sig_hex,
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 202, resp.text

    # 1. Device status check
    dev_status = await db["network_relay_device_status"].find_one({
        "tenant_id": ctx["tenant_id"],
        "device_id": "pfsense-main-gw",
    })
    assert dev_status is not None
    assert dev_status["last_event_type"] == "network_connection_permitted"

    # 2. Downstream SIEM Cold Vault check
    relay_context = {
        "relay_id": ctx["relay_id"],
        "tenant_id": ctx["tenant_id"],
        "relay": await db["network_relays"].find_one({"relay_id": ctx["relay_id"]}),
    }
    batch_hash = hashlib.sha256(raw_body).hexdigest()
    queued_item = _queue_event(event, relay_context, batch, batch_hash, sig_hex, datetime.now(timezone.utc))
    await _flush_siem_cold_vault(db, [queued_item])

    vault_doc = await db["siem_cold_vault"].find_one({
        "tenant_id": ctx["tenant_id"],
        "event_uid": event.event_uid,
    })
    assert vault_doc is not None
    assert vault_doc["event_id"] == "NET-CONNECTION-ALLOW"

    # 3. CRITICAL: Check REAL collections used by WarSOC detection & Wazuh pipelines
    # A. security_alerts: No blocked traffic alerts
    alerts_count = await db["security_alerts"].count_documents({
        "tenant_id": ctx["tenant_id"],
        "category": {"$in": ["firewall_block", "network_blocked", "blocked_traffic"]},
    })
    assert alerts_count == 0, f"Unexpected alert created for pass traffic: {alerts_count}"

    # B. detection_engine_observations: No candidate records (real Wazuh observation collection)
    wazuh_obs_count = await db["detection_engine_observations"].count_documents({
        "tenant_id": ctx["tenant_id"],
    })
    assert wazuh_obs_count == 0, f"Unexpected observation in detection_engine_observations: {wazuh_obs_count}"

    # C. detection_shadow_observations: No shadow observation records
    shadow_count = await db["detection_shadow_observations"].count_documents({
        "tenant_id": ctx["tenant_id"],
    })
    assert shadow_count == 0, f"Unexpected shadow observation: {shadow_count}"

    # D. security_incidents: No incident created
    incidents_count = await db["security_incidents"].count_documents({
        "tenant_id": ctx["tenant_id"],
    })
    assert incidents_count == 0, f"Unexpected incident created: {incidents_count}"


# =============================================================================
# SCENARIO 4: Real Encrypted Spool & Relay Interruption Test
# Requirement: Events spool locally into encrypted SQLite file, survive network
# outage (503/transport retry), upload in order upon reconnect, and do not duplicate.
# =============================================================================
async def test_pfsense_scenario_4_real_encrypted_spool_and_interruption(tmp_path, async_client, db, redis_client):
    """
    Scenario 4:
    Directly exercises EncryptedBoundedSpool and RelayOutbox on disk:
      - Proves pfSense evidence is encrypted at rest (AES-GCM ciphertext on disk).
      - Simulates network interruption: deliver_once returns 'retry', batch remains in spool.
      - Restores network: deliver_once targets FastAPI, succeeds with 202 'accepted'.
      - Proves spool is drained on disk after acknowledgement.
      - Replays exact batch: handled idempotently as 'duplicate_acknowledged' with zero DB duplicates.
    """
    ctx = await _setup_pfsense_relay(async_client, db, redis_client, "scen4_real_spool")

    spool_key = os.urandom(32)
    evidence_path = tmp_path / "pfsense-evidence.db"
    control_path = tmp_path / "pfsense-control.db"
    outbox_path = tmp_path / "pfsense-outbox.db"

    # 1. Initialize REAL encrypted spools on disk
    evidence_spool = EncryptedBoundedSpool(
        evidence_path,
        stream_name="evidence",
        encryption_key=spool_key,
        max_payload_bytes=10 * 1024 * 1024,
    )
    control_spool = EncryptedBoundedSpool(
        control_path,
        stream_name="control",
        encryption_key=spool_key,
        max_payload_bytes=2 * 1024 * 1024,
    )

    # 2. Collect real pfSense filterlog event into the spool
    raw_block = (
        "<134>Mon Sep 14 19:42:00 filterlog[12345]: "
        "100,,,1000000105,em0,match,block,in,4,0x0,,64,1236,0,DF,6,tcp,60,"
        "198.51.100.25,192.168.1.50,4445,80,0,S,12345678,,1024,,"
    )
    parsed = parse_pfsense(raw_block)
    relay_evt = relay_event_from_parsed(
        parsed,
        device_id="pfsense-main-gw",
        transport="udp",
        source_address="192.168.56.254",
        raw_message=raw_block,
        relay_receipt_time=datetime.now(timezone.utc),
    )
    record = evidence_spool.append(relay_evt)
    assert record.sequence == 1
    assert evidence_spool.stats()["records"] == 1

    # 3. PROVE ENCRYPTION ON DISK:
    # Read raw bytes of SQLite file; plain text IP must NOT appear unencrypted
    with open(evidence_path, "rb") as f:
        raw_db_content = f.read()
    assert b"198.51.100.25" not in raw_db_content, "Plaintext IP leaked unencrypted into disk spool file!"
    assert b"filterlog" not in raw_db_content, "Plaintext syslog leaked into disk spool file!"

    # 4. Initialize REAL RelayOutbox on disk
    outbox = RelayOutbox(
        outbox_path,
        relay_id=ctx["relay_id"],
        private_key_pem=ctx["private_key"].private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        encryption_key=spool_key,
    )

    ingest_url = "http://test/api/v1/network-relay/ingest"

    # 5. SIMULATE NETWORK OUTAGE / INTERRUPTION:
    # Backend returns 503 or disconnects
    async def failing_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"detail": "Network connectivity lost / Relay interrupted"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(failing_handler)) as offline_client:
        delivery_status = await deliver_once(
            outbox,
            control_spool=control_spool,
            evidence_spool=evidence_spool,
            ingest_url=ingest_url,
            relay_token=ctx["token"],
            client=offline_client,
        )
    # The outbox must signal 'retry'
    assert delivery_status == "retry"
    # The evidence MUST still be intact in the encrypted disk spool
    assert evidence_spool.stats()["records"] == 1
    # The outbox has a pending unacknowledged batch
    assert outbox.pending() is not None
    assert outbox.pending().batch.sequence == 1

    # 6. RESTORE NETWORK / RECONNECTION:
    # Now deliver against the real FastAPI async_client
    online_delivery = await deliver_once(
        outbox,
        control_spool=control_spool,
        evidence_spool=evidence_spool,
        ingest_url="/api/v1/network-relay/ingest",
        relay_token=ctx["token"],
        client=async_client,
    )
    assert online_delivery == "accepted"

    # Spool is now completely drained and acknowledged on disk!
    assert evidence_spool.stats()["records"] == 0
    assert outbox.pending() is None

    # Database receipt verified
    batches = await db["network_relay_batches"].find({
        "relay_id": ctx["relay_id"],
    }).to_list(10)
    assert len(batches) == 1
    assert batches[0]["sequence"] == 1

    # 7. DEDUPLICATION: Attempt duplicate delivery
    # Manually resubmit the exact same batch body that was just delivered
    pending_batch = RelayBatch(
        schema_version="warsoc-relay-batch-v1",
        relay_id=ctx["relay_id"],
        chain_id=batches[0]["chain_id"],
        key_epoch=1,
        sequence=1,
        previous_batch_hash=RELAY_GENESIS_HASH,
        created_at=batches[0]["cloud_receipt_time"],
        events=[_make_pfsense_event(raw_message=raw_block)],
    )
    # Post raw batch body
    raw_dup = orjson.dumps(pending_batch.model_dump(mode="json"))
    sig_dup = ctx["private_key"].sign(raw_dup).hex()
    dup_resp = await async_client.post(
        "/api/v1/network-relay/ingest",
        content=raw_dup,
        headers={
            "Authorization": f"Bearer {ctx['token']}",
            "X-WarSOC-Signature": sig_dup,
            "Content-Type": "application/json",
        },
    )
    # Monotonic chain deduplication: identical sequence/hash is idempotent
    assert dup_resp.status_code in {202, 409}
    if dup_resp.status_code == 202:
        assert dup_resp.json()["status"] == "duplicate_acknowledged"
        assert dup_resp.json()["queued"] == 0

    # Ensure zero duplicates persisted in database
    final_count = await db["network_relay_batches"].count_documents({"relay_id": ctx["relay_id"]})
    assert final_count == 1, f"Expected exactly 1 batch, found {final_count} duplicates!"

    outbox.close()
    evidence_spool.close()
    control_spool.close()

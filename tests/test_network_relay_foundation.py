import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone

import orjson
import pytest
import httpx
from pydantic import ValidationError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.network_relay.batch import build_signed_batch, relay_event_from_parsed
from app.network_relay.collector import RelayCollector, RelayDevice
from app.network_relay.outbox import RelayOutbox, deliver_once
from app.network_relay.parsers import (
    NetworkParseError,
    parse_cisco_asa,
    parse_fortinet,
    parse_mikrotik,
    parse_network_message,
    parse_pfsense,
)
from app.network_relay.spool import (
    EncryptedBoundedSpool,
    SpoolFullError,
    SpoolIntegrityError,
)
from app.routes.network_relay import (
    RELAY_GENESIS_HASH,
    RelayBatch,
    RelayEvent,
    _admit_batch,
    _queue_event,
)
from app.utils.siem_catalog import SIEM_RULES
from app.utils.siem_logic import CorrelationEngine
from app.workers.siem_worker import (
    _keyword_sources_for_event,
    _trusted_telemetry_family,
)


def _relay_event(**overrides) -> RelayEvent:
    raw_message = overrides.pop(
        "raw_message",
        "date=2026-07-27 time=10:00:00 type=traffic action=deny srcip=10.0.0.4 dstip=8.8.8.8",
    )
    values = {
        "event_uid": f"relay-event-{uuid.uuid4().hex}",
        "device_id": "branch-firewall-1",
        "vendor": "fortinet",
        "transport": "udp",
        "source_address": "10.0.0.1",
        "device_event_time": datetime.now(timezone.utc),
        "relay_receipt_time": datetime.now(timezone.utc),
        "raw_message": raw_message,
        "raw_message_hash": hashlib.sha256(raw_message.encode()).hexdigest(),
        "normalized": {
            "event_type": "network_connection_blocked",
            "action": "deny",
            "src_ip": "10.0.0.4",
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "protocol": "udp",
        },
    }
    values.update(overrides)
    return RelayEvent.model_validate(values)


def _relay_batch(sequence: int = 1, previous_hash: str = RELAY_GENESIS_HASH) -> RelayBatch:
    return RelayBatch(
        schema_version="warsoc-relay-batch-v1",
        relay_id=f"WARSOC_RELAY_{uuid.uuid4().hex}",
        chain_id=uuid.uuid4().hex,
        key_epoch=1,
        sequence=sequence,
        previous_batch_hash=previous_hash,
        created_at=datetime.now(timezone.utc),
        events=[_relay_event()],
    )


def test_fortinet_traffic_and_vpn_are_normalized_without_packet_payload():
    denied = parse_fortinet(
        '<189>1 2026-07-27T10:00:00Z fw1 fortigate - TRAFFIC - '
        'type=traffic subtype=forward action=deny srcip=10.0.0.4 srcport=52000 '
        'dstip=8.8.8.8 dstport=53 proto=17 sentbyte=120 rcvdbyte=0 policyid=7'
    )
    assert denied.device_event_time == datetime(2026, 7, 27, 10, 0, tzinfo=timezone.utc)
    assert denied.normalized["event_type"] == "network_connection_blocked"
    assert denied.normalized["src_ip"] == "10.0.0.4"
    assert denied.normalized["dst_port"] == 53
    assert "payload" not in denied.normalized

    vpn = parse_fortinet(
        'date=2026-07-27 time=10:01:00 type=event subtype=vpn '
        'action=login user="branch-admin" remip=203.0.113.7 status=success'
    )
    assert vpn.normalized["event_type"] == "vpn_authentication"
    assert vpn.normalized["action"] == "successful"
    assert vpn.normalized["user"] == "branch-admin"
    assert vpn.normalized["src_ip"] == "203.0.113.7"


def test_cisco_asa_and_mikrotik_preserve_conservative_outcomes():
    cisco = parse_cisco_asa(
        '<166>Jul 27 10:02:00 asa1 %ASA-4-106023: Deny tcp src inside:'
        '10.0.0.10/50100 dst outside:198.51.100.8/443 by access-group "inside"'
    )
    assert cisco.normalized["event_type"] == "network_connection_blocked"
    assert cisco.normalized["message_id"] == "106023"
    assert cisco.normalized["dst_port"] == 443

    mikrotik = parse_mikrotik(
        '<134>Jul 27 10:03:00 router1 firewall,info forward: in:ether2 out:ether1, '
        'connection-state:new proto TCP (SYN), 10.0.0.20:51000->198.51.100.20:443, len 60'
    )
    # RouterOS prefixes are customer-defined. Absence of an explicit drop must
    # not be relabelled as an allow event.
    assert mikrotik.normalized["event_type"] == "network_observation"
    assert mikrotik.normalized["dst_ip"] == "198.51.100.20"

    vpn = parse_cisco_asa(
        '<166>Jul 27 10:03:01 asa1 %ASA-6-113012: AAA user authentication '
        'Successful : local database : user = branch-admin'
    )
    assert vpn.normalized["event_type"] == "vpn_authentication"
    assert vpn.normalized["action"] == "successful"
    assert vpn.normalized["user"] == "branch-admin"

    rejected = parse_cisco_asa(
        '<166>Jul 27 10:03:02 asa1 %ASA-6-113005: AAA user authentication '
        'Rejected : reason = Unspecified : server = 10.0.0.2 : user = analyst '
        ': user IP = 203.0.113.44'
    )
    assert rejected.normalized["action"] == "rejected"
    assert rejected.normalized["user"] == "analyst"
    assert rejected.normalized["src_ip"] == "203.0.113.44"

    with pytest.raises(NetworkParseError):
        parse_mikrotik(
            "firewall,debug,packet PACKET: 45 00 00 34 payload-content-out-of-scope"
        )


def test_generic_and_malformed_messages_fail_or_degrade_safely():
    generic = parse_network_message(
        "generic", '<13>1 2026-07-27T10:04:00Z appliance app - MSG-1 - status changed'
    )
    assert generic.normalized["event_type"] == "network_observation"
    assert generic.normalized["message_id"] == "MSG-1"
    with pytest.raises(NetworkParseError):
        parse_fortinet('type=traffic msg="unterminated')


def test_pfsense_filterlog_ipv4_ipv6_and_fail_closed_contract():
    blocked = parse_pfsense(
        '<134>1 2026-07-27T10:05:00Z pf1 filterlog - - - '
        '5,,,1000000103,em0,match,block,in,4,0x0,,64,1234,0,DF,6,tcp,60,'
        '192.0.2.10,198.51.100.20,50100,443,0,S,123,0,65535,,mss'
    )
    assert blocked.device_event_time == datetime(2026, 7, 27, 10, 5, tzinfo=timezone.utc)
    assert blocked.normalized == {
        "event_type": "network_connection_blocked",
        "action": "block",
        "direction": "in",
        "ip_version": 4,
        "rule_id": "5",
        "tracker_id": "1000000103",
        "interface_in": "em0",
        "reason": "match",
        "protocol": "tcp",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "src_port": 50100,
        "dst_port": 443,
        "packet_length": 60,
        "data_length": 0,
        "tcp_flags": "S",
        "message": "pfSense firewall block in",
        "hostname": "pf1",
        "severity": 6,
    }

    permitted = parse_pfsense(
        '<134>Jul 27 10:05:01 pf1 filterlog: '
        '6,,,1000000104,em1,match,pass,out,6,0x00,0,64,tcp,6,60,'
        '2001:db8::1,2001:4860:4860::8888,50101,443,0,S,124,0,65535,,mss'
    )
    assert permitted.normalized["event_type"] == "network_connection_permitted"
    assert permitted.normalized["ip_version"] == 6
    assert permitted.normalized["interface_out"] == "em1"
    assert permitted.normalized["dst_ip"] == "2001:4860:4860::8888"
    assert "payload" not in permitted.normalized

    with pytest.raises(NetworkParseError):
        parse_pfsense("openvpn[123]: peer connected")
    with pytest.raises(NetworkParseError):
        parse_pfsense("filterlog: 5,,,100,em0,match,block,in,4")


def test_relay_schema_rejects_unknown_fields_and_raw_message_changes():
    event = _relay_event().model_dump(mode="json")
    event["normalized"]["packet_payload"] = "secret"
    with pytest.raises(ValidationError):
        RelayEvent.model_validate(event)

    event = _relay_event().model_dump(mode="json")
    event["raw_message"] += " altered"
    with pytest.raises(ValidationError):
        RelayEvent.model_validate(event)

    batch = _relay_batch().model_dump(mode="json")
    batch["schema_version"] = "future-unapproved-schema"
    with pytest.raises(ValidationError):
        RelayBatch.model_validate(batch)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("src_ip", "999.1.1.1"),
        ("dst_port", 70000),
        ("dropped_events", -1),
        ("spool_usage_bytes", True),
    ],
)
def test_relay_schema_rejects_malformed_normalized_values(field, value):
    event = _relay_event().model_dump(mode="json")
    event["normalized"][field] = value
    with pytest.raises(ValidationError):
        RelayEvent.model_validate(event)


def test_device_health_cannot_be_disguised_as_network_evidence():
    event = _relay_event().model_dump(mode="json")
    event["normalized"]["event_type"] = "device_health"
    with pytest.raises(ValidationError):
        RelayEvent.model_validate(event)


def test_relay_batch_builder_matches_cloud_schema_and_signature_contract():
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    parsed = parse_fortinet(
        "type=traffic action=deny srcip=10.0.0.2 dstip=198.51.100.2 dstport=443 proto=6"
    )
    event = relay_event_from_parsed(
        parsed,
        device_id="branch-firewall-1",
        transport="udp",
        source_address="10.0.0.1",
        raw_message="type=traffic action=deny srcip=10.0.0.2 dstip=198.51.100.2 dstport=443 proto=6",
        relay_receipt_time=datetime.now(timezone.utc),
        event_uid="relay-event-stable-0001",
    )
    signed = build_signed_batch(
        relay_id=f"WARSOC_RELAY_{uuid.uuid4().hex}",
        chain_id=uuid.uuid4().hex,
        key_epoch=1,
        sequence=1,
        previous_batch_hash=RELAY_GENESIS_HASH,
        events=[event],
        private_key_pem=private_pem,
    )
    validated = RelayBatch.model_validate_json(signed.body)
    assert validated.events[0].event_uid == "relay-event-stable-0001"
    assert signed.batch_hash == hashlib.sha256(signed.body).hexdigest()
    private_key.public_key().verify(bytes.fromhex(signed.signature), signed.body)


def test_encrypted_spools_are_fifo_bounded_and_independent(tmp_path):
    key = os.urandom(32)
    evidence = EncryptedBoundedSpool(
        tmp_path / "evidence.db",
        stream_name="evidence",
        encryption_key=key,
        max_payload_bytes=220,
        max_record_bytes=180,
        min_free_disk_bytes=0,
    )
    control = EncryptedBoundedSpool(
        tmp_path / "control.db",
        stream_name="control",
        encryption_key=key,
        max_payload_bytes=220,
        max_record_bytes=180,
        min_free_disk_bytes=0,
    )
    first = evidence.append({"event_uid": "event-0001", "message": "private-firewall-log-a"})
    second = evidence.append({"event_uid": "event-0002", "message": "private-firewall-log-b"})
    control.append({"state": "SATURATED", "dropped": 12})

    assert [row.sequence for row in evidence.records()] == [first.sequence, second.sequence]
    assert b"private-firewall-log-a" not in (tmp_path / "evidence.db").read_bytes()
    with pytest.raises(SpoolFullError):
        evidence.append({"event_uid": "event-0003", "message": "x" * 120})
    assert control.stats()["records"] == 1
    assert evidence.acknowledge_through(first.sequence) == 1
    assert [row.sequence for row in evidence.records()] == [second.sequence]
    evidence.verify_chain()
    evidence.close()
    control.close()


def test_spool_detects_ciphertext_tampering(tmp_path):
    path = tmp_path / "tamper.db"
    spool = EncryptedBoundedSpool(
        path,
        stream_name="evidence",
        encryption_key=os.urandom(32),
        max_payload_bytes=1024,
        max_record_bytes=512,
        min_free_disk_bytes=0,
    )
    spool.append({"event_uid": "event-tamper", "message": "sensitive"})
    spool._db.execute(
        "UPDATE spool_records SET ciphertext=? WHERE sequence=1", (b"corrupted",)
    )
    with pytest.raises(SpoolIntegrityError):
        list(spool.records())
    with pytest.raises(SpoolIntegrityError):
        spool.verify_chain()
    spool.close()


def test_collector_limits_before_parse_and_reports_loss_in_control_spool(tmp_path):
    key = os.urandom(32)
    evidence = EncryptedBoundedSpool(
        tmp_path / "collector-evidence.db",
        stream_name="evidence",
        encryption_key=key,
        max_payload_bytes=4096,
        max_record_bytes=2048,
        min_free_disk_bytes=0,
    )
    control = EncryptedBoundedSpool(
        tmp_path / "collector-control.db",
        stream_name="control",
        encryption_key=key,
        max_payload_bytes=4096,
        max_record_bytes=2048,
        min_free_disk_bytes=0,
    )
    collector = RelayCollector(
        relay_id=f"WARSOC_RELAY_{uuid.uuid4().hex}",
        devices=[
            RelayDevice(
                device_id="fw-1",
                vendor="fortinet",
                source_addresses=("10.0.0.1/32",),
                expected_eps=1,
            )
        ],
        evidence_spool=evidence,
        control_spool=control,
        max_datagram_bytes=512,
        global_eps=2,
        global_bytes_per_second=1024,
    )
    message = b"type=traffic action=deny srcip=10.0.0.2 dstip=198.51.100.2 dstport=443 proto=6"
    assert collector.accept_datagram(message, source_address="10.0.0.1").status == "accepted"
    assert collector.accept_datagram(message, source_address="10.0.0.1").status == "accepted"
    limited = collector.accept_datagram(message, source_address="10.0.0.1")
    assert limited.status == "dropped"
    assert limited.reason == "edge_rate_limit"
    unknown = collector.accept_datagram(message, source_address="10.0.0.99")
    assert unknown.reason == "unregistered_or_ambiguous_source"
    assert collector.flush_loss_summaries() == 2
    controls = list(control.records())
    assert {row.payload["normalized"]["reason"] for row in controls} == {
        "edge_rate_limit",
        "unregistered_or_ambiguous_source",
    }
    assert all(row.payload["record_class"] == "control" for row in controls)
    evidence.close()
    control.close()


def test_device_rate_limit_does_not_exhaust_shared_relay_capacity(tmp_path):
    key = os.urandom(32)
    evidence = EncryptedBoundedSpool(
        tmp_path / "fairness-evidence.db",
        stream_name="evidence",
        encryption_key=key,
        max_payload_bytes=16384,
        max_record_bytes=2048,
        min_free_disk_bytes=0,
    )
    control = EncryptedBoundedSpool(
        tmp_path / "fairness-control.db",
        stream_name="control",
        encryption_key=key,
        max_payload_bytes=4096,
        max_record_bytes=2048,
        min_free_disk_bytes=0,
    )
    collector = RelayCollector(
        relay_id=f"WARSOC_RELAY_{uuid.uuid4().hex}",
        devices=[
            RelayDevice(
                device_id="fw-noisy",
                vendor="fortinet",
                source_addresses=("10.0.0.1/32",),
                expected_eps=1,
            ),
            RelayDevice(
                device_id="fw-healthy",
                vendor="fortinet",
                source_addresses=("10.0.0.2/32",),
                expected_eps=1,
            ),
        ],
        evidence_spool=evidence,
        control_spool=control,
        global_eps=2,
        global_bytes_per_second=1024,
    )
    message = b"type=traffic action=deny srcip=10.0.0.3 dstip=198.51.100.2 dstport=443 proto=6"

    assert collector.accept_datagram(message, source_address="10.0.0.1").status == "accepted"
    assert collector.accept_datagram(message, source_address="10.0.0.1").status == "accepted"
    for _ in range(20):
        assert collector.accept_datagram(message, source_address="10.0.0.1").status == "dropped"

    assert collector.accept_datagram(message, source_address="10.0.0.2").status == "accepted"
    assert collector.accept_datagram(message, source_address="10.0.0.2").status == "accepted"
    evidence.close()
    control.close()


@pytest.mark.asyncio
async def test_outbox_retries_exact_batch_prioritizes_control_and_acks_fifo(tmp_path):
    key = os.urandom(32)
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    relay_id = f"WARSOC_RELAY_{uuid.uuid4().hex}"
    evidence = EncryptedBoundedSpool(
        tmp_path / "outbox-evidence.db",
        stream_name="evidence",
        encryption_key=key,
        max_payload_bytes=8192,
        max_record_bytes=4096,
        min_free_disk_bytes=0,
    )
    control = EncryptedBoundedSpool(
        tmp_path / "outbox-control.db",
        stream_name="control",
        encryption_key=key,
        max_payload_bytes=8192,
        max_record_bytes=4096,
        min_free_disk_bytes=0,
    )
    evidence.append(_relay_event().model_dump(mode="json"))
    control_event = _relay_event(
        record_class="control",
        device_id=relay_id,
        vendor="generic",
        transport="api",
        source_address="127.0.0.1",
        normalized={"event_type": "device_health", "state": "DEGRADED"},
    )
    control.append(control_event.model_dump(mode="json"))
    outbox = RelayOutbox(
        tmp_path / "cloud-state.db",
        relay_id=relay_id,
        private_key_pem=private_pem,
        encryption_key=key,
    )
    observed_bodies = []
    attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        observed_bodies.append(request.content)
        private_key.public_key().verify(
            bytes.fromhex(request.headers["X-WarSOC-Signature"]), request.content
        )
        if attempts == 1:
            return httpx.Response(503, json={"detail": "retry"})
        batch = RelayBatch.model_validate_json(request.content)
        return httpx.Response(
            202, json={"status": "accepted", "queued": 1, "sequence": batch.sequence}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        first = await deliver_once(
            outbox,
            control_spool=control,
            evidence_spool=evidence,
            ingest_url="https://api.example.test/api/v1/network-relay/ingest",
            relay_token="relay-token",
            client=client,
        )
        second = await deliver_once(
            outbox,
            control_spool=control,
            evidence_spool=evidence,
            ingest_url="https://api.example.test/api/v1/network-relay/ingest",
            relay_token="relay-token",
            client=client,
        )
    assert first == "retry"
    assert second == "accepted"
    assert observed_bodies[0] == observed_bodies[1]
    assert control.stats()["records"] == 0
    assert evidence.stats()["records"] == 1
    assert outbox.pending() is None
    outbox.close()
    evidence.close()
    control.close()


@pytest.mark.asyncio
async def test_redis_batch_admission_is_atomic_and_duplicate_safe(redis_client):
    batch = _relay_batch()
    relay_context = {
        "relay_id": batch.relay_id,
        "tenant_id": "WARSOC_TEST_RELAY",
        "relay": {
            "last_sequence": 0,
            "last_batch_hash": RELAY_GENESIS_HASH,
            "chain_id": None,
            "key_epoch": 1,
        },
    }
    payloads = [json.dumps({"event_uid": batch.events[0].event_uid})]
    batch_hash = hashlib.sha256(orjson.dumps(batch.model_dump(mode="json"))).hexdigest()
    assert await _admit_batch(
        redis_client,
        relay_context,
        batch,
        batch_hash,
        payloads,
        quota_bytes=1000,
        payload_bytes=100,
    ) == 1
    assert await _admit_batch(
        redis_client,
        relay_context,
        batch,
        batch_hash,
        payloads,
        quota_bytes=1000,
        payload_bytes=100,
    ) == 2
    assert await redis_client.xlen("raw_logs_queue") == 1
    quota_keys = [key async for key in redis_client.scan_iter("warsoc:ingest:bytes:*")]
    assert len(quota_keys) == 1
    assert int(await redis_client.get(quota_keys[0])) == 100

    second = _relay_batch(sequence=2, previous_hash=batch_hash)
    second = second.model_copy(update={"relay_id": batch.relay_id, "chain_id": batch.chain_id})
    second_hash = hashlib.sha256(orjson.dumps(second.model_dump(mode="json"))).hexdigest()
    assert await _admit_batch(
        redis_client,
        relay_context,
        second,
        second_hash,
        [json.dumps({"event_uid": second.events[0].event_uid})],
        quota_bytes=1000,
        payload_bytes=100,
    ) == 1
    assert await redis_client.xlen("raw_logs_queue") == 2

    wrong_epoch = _relay_batch()
    wrong_epoch = wrong_epoch.model_copy(
        update={
            "relay_id": f"WARSOC_RELAY_{uuid.uuid4().hex}",
            "key_epoch": 1,
        }
    )
    wrong_context = {
        "relay_id": wrong_epoch.relay_id,
        "tenant_id": "WARSOC_TEST_RELAY",
        "relay": {
            "last_sequence": 0,
            "last_batch_hash": RELAY_GENESIS_HASH,
            "chain_id": None,
            "key_epoch": 2,
        },
    }
    assert await _admit_batch(
        redis_client,
        wrong_context,
        wrong_epoch,
        "e" * 64,
        [json.dumps({"event_uid": wrong_epoch.events[0].event_uid})],
    ) == -2

    out_of_sequence = second.model_copy(update={"sequence": 4, "previous_batch_hash": second_hash})
    assert await _admit_batch(
        redis_client,
        relay_context,
        out_of_sequence,
        "a" * 64,
        [json.dumps({"event_uid": "must-not-queue"})],
        quota_bytes=1000,
        payload_bytes=100,
    ) == -1
    assert await redis_client.xlen("raw_logs_queue") == 2

    quota_rejected = second.model_copy(
        update={"sequence": 3, "previous_batch_hash": second_hash}
    )
    assert await _admit_batch(
        redis_client,
        relay_context,
        quota_rejected,
        "d" * 64,
        [json.dumps({"event_uid": "over-quota"})],
        quota_bytes=200,
        payload_bytes=100,
    ) == -4
    assert await redis_client.xlen("raw_logs_queue") == 2


def test_relay_events_are_source_isolated_from_legacy_keyword_rules():
    batch = _relay_batch()
    event = _queue_event(
        batch.events[0],
        {
            "tenant_id": "WARSOC_TEST_RELAY",
            "relay_id": batch.relay_id,
            "relay": {"signing_key_id": "key-1", "version": "relay-test"},
        },
        batch,
        "b" * 64,
        "c" * 128,
        datetime.now(timezone.utc),
    )
    family = _trusted_telemetry_family(
        event, event["event_id"], event["event_type"]
    )
    assert family == "network"
    assert _keyword_sources_for_event(family, event["event_id"], {}) == ()


def _network_log(event_type: str, *, action: str, src_ip: str | None, user: str):
    normalized = {
        "event_type": event_type,
        "action": action,
        "user": user,
        "dst_ip": "8.8.8.8",
        "dst_port": 443,
    }
    if src_ip:
        normalized["src_ip"] = src_ip
    return {
        "tenant_id": f"WARSOC_HYBRID_{uuid.uuid4().hex[:8]}",
        "agent_id": "WARSOC_RELAY_TEST",
        "network_device_id": "branch-firewall-1",
        "source_type": "network_device",
        "source_assurance": "relay_attested",
        "signature_verified": True,
        "telemetry_family": "network",
        "event_id": "NET-VPN-AUTH" if event_type == "vpn_authentication" else "NET-CONNECTION-ALLOW",
        "event_type": event_type,
        "event_uid": f"network-{uuid.uuid4().hex}",
        "source_ip": src_ip or "10.0.0.1",
        "user": user,
        "processed_data": normalized,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@pytest.mark.asyncio
async def test_hybrid_correlation_is_inert_when_relay_feature_is_disabled(
    redis_client, monkeypatch
):
    monkeypatch.setenv("NETWORK_RELAY_ENABLED", "false")
    engine = CorrelationEngine(redis_client, SIEM_RULES)
    tenant_id = f"WARSOC_HYBRID_{uuid.uuid4().hex[:8]}"
    event = {
        "tenant_id": tenant_id,
        "agent_id": "WARSOC_AGENT_TEST",
        "telemetry_family": "windows",
        "event_id": "1102",
        "event_type": "clear_logs",
        "event_uid": f"windows-{uuid.uuid4().hex}",
        "source_ip": "10.0.0.20",
        "user": "Administrator",
        "processed_data": {"computer": "POS-01"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    assert await engine.check_hybrid_network_correlations(
        tenant_id,
        event["source_ip"],
        event["user"],
        event["event_id"],
        event["event_type"],
        event["timestamp"],
        event,
    ) == []
    assert [key async for key in redis_client.scan_iter("warsoc:hybrid:*")] == []


@pytest.mark.asyncio
async def test_hybrid_vpn_spray_requires_remote_ip_and_five_distinct_users(
    redis_client, monkeypatch
):
    monkeypatch.setenv("NETWORK_RELAY_ENABLED", "true")
    engine = CorrelationEngine(redis_client, SIEM_RULES)
    tenant_id = f"WARSOC_HYBRID_{uuid.uuid4().hex[:8]}"

    unattributed = _network_log(
        "vpn_authentication", action="rejected", src_ip=None, user="user-0"
    )
    unattributed["tenant_id"] = tenant_id
    assert await engine.run_all(
        tenant_id, unattributed["source_ip"], "user-0", "NET-VPN-AUTH",
        event_type="vpn_authentication", log_entry=unattributed,
    ) == []

    alerts = []
    for index in range(5):
        event = _network_log(
            "vpn_authentication",
            action="rejected",
            src_ip="203.0.113.44",
            user=f"user-{index}",
        )
        event["tenant_id"] = tenant_id
        alerts = await engine.run_all(
            tenant_id,
            event["source_ip"],
            event["user"],
            event["event_id"],
            event_type=event["event_type"],
            timestamp_iso=event["timestamp"],
            log_entry=event,
        )
        if index < 4:
            assert alerts == []

    spray = [alert for alert in alerts if alert["type"] == "HYBRID_VPN_PASSWORD_SPRAY"]
    assert len(spray) == 1
    assert spray[0]["unique_targets"] == 5
    assert spray[0]["source_assurance"] == "relay_attested"


@pytest.mark.asyncio
async def test_hybrid_vpn_to_windows_logon_is_context_not_threat(
    redis_client, monkeypatch
):
    monkeypatch.setenv("NETWORK_RELAY_ENABLED", "true")
    engine = CorrelationEngine(redis_client, SIEM_RULES)
    tenant_id = f"WARSOC_HYBRID_{uuid.uuid4().hex[:8]}"
    vpn = _network_log(
        "vpn_authentication",
        action="successful",
        src_ip="203.0.113.45",
        user="branch-admin",
    )
    vpn["tenant_id"] = tenant_id
    assert await engine.run_all(
        tenant_id, vpn["source_ip"], vpn["user"], vpn["event_id"],
        event_type=vpn["event_type"], timestamp_iso=vpn["timestamp"], log_entry=vpn,
    ) == []

    windows = {
        "tenant_id": tenant_id,
        "agent_id": "WARSOC_AGENT_TEST",
        "telemetry_family": "windows",
        "event_id": "4624",
        "event_type": "successful_login",
        "event_uid": f"windows-{uuid.uuid4().hex}",
        "source_ip": "203.0.113.45",
        "user": "branch-admin",
        "processed_data": {
            "user": "branch-admin",
            "source_network_address": "203.0.113.45",
            "logon_type": "10",
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    assert await engine.run_all(
        tenant_id, windows["source_ip"], windows["user"], "4624",
        event_type="successful_login", timestamp_iso=windows["timestamp"], log_entry=windows,
    ) == []
    assert windows["hybrid_correlations"] == [
        {
            "type": "vpn_to_windows_logon",
            "outcome": "observed",
            "source_assurance": "relay_attested",
            "vpn_event_uid": vpn["event_uid"],
            "network_device_id": "branch-firewall-1",
            "remote_ip": "203.0.113.45",
        }
    ]


@pytest.mark.asyncio
async def test_hybrid_high_risk_host_event_requires_same_source_and_public_destination(
    redis_client, monkeypatch
):
    monkeypatch.setenv("NETWORK_RELAY_ENABLED", "true")
    engine = CorrelationEngine(redis_client, SIEM_RULES)
    tenant_id = f"WARSOC_HYBRID_{uuid.uuid4().hex[:8]}"
    host_event = {
        "tenant_id": tenant_id,
        "agent_id": "WARSOC_AGENT_TEST",
        "telemetry_family": "windows",
        "event_id": "1102",
        "event_type": "clear_logs",
        "event_uid": f"windows-{uuid.uuid4().hex}",
        "source_ip": "10.0.0.20",
        "user": "Administrator",
        "processed_data": {"computer": "POS-01"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    assert await engine.run_all(
        tenant_id, "10.0.0.20", "Administrator", "1102",
        event_type="clear_logs", timestamp_iso=host_event["timestamp"], log_entry=host_event,
    ) == []

    unrelated = _network_log(
        "network_connection_permitted", action="built", src_ip="10.0.0.21", user="-"
    )
    unrelated["tenant_id"] = tenant_id
    assert await engine.run_all(
        tenant_id, "10.0.0.21", "-", unrelated["event_id"],
        event_type=unrelated["event_type"], log_entry=unrelated,
    ) == []

    outbound = _network_log(
        "network_connection_permitted", action="built", src_ip="10.0.0.20", user="-"
    )
    outbound["tenant_id"] = tenant_id
    alerts = await engine.run_all(
        tenant_id, "10.0.0.20", "-", outbound["event_id"],
        event_type=outbound["event_type"], timestamp_iso=outbound["timestamp"], log_entry=outbound,
    )
    hybrid = [
        alert for alert in alerts
        if alert["type"] == "HYBRID_AUDIT_LOG_CLEARED_TO_PUBLIC_NETWORK"
    ]
    assert len(hybrid) == 1
    assert hybrid[0]["host_event_uid"] == host_event["event_uid"]
    assert hybrid[0]["destination_ip"] == "8.8.8.8"

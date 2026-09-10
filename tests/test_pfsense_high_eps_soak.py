import asyncio
import hashlib
import json
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import orjson
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.network_relay.batch import build_signed_batch
from app.network_relay.collector import RelayCollector, RelayDevice, TokenBucket
from app.network_relay.parsers import parse_pfsense
from app.network_relay.spool import EncryptedBoundedSpool
from app.routes.network_relay import (
    RELAY_GENESIS_HASH,
    RelayBatch,
    _admit_batch,
)


def _generate_pfsense_datagrams(count: int) -> list[bytes]:
    """Generate deterministic, valid pfSense filterlog datagrams spanning IPv4, IPv6, TCP, and UDP."""
    templates = [
        # IPv4 TCP Block (Inbound probe)
        (
            "<134>1 2026-09-09T12:00:00Z pf1 filterlog - - - "
            "5,,,1000000103,em0,match,block,in,4,0x0,,64,{ip_id},0,DF,6,tcp,60,"
            "198.51.100.{src_host},10.0.0.{dst_host},{src_port},443,0,S,123,0,65535,,mss"
        ),
        # IPv4 TCP Pass (Outbound HTTPS)
        (
            "<134>1 2026-09-09T12:00:01Z pf1 filterlog - - - "
            "6,,,1000000104,em1,match,pass,out,4,0x0,,64,{ip_id},0,DF,6,tcp,60,"
            "10.0.0.{src_host},198.51.100.{dst_host},{src_port},443,0,S,124,0,65535,,mss"
        ),
        # IPv4 UDP Block (DNS/NTP anomaly)
        (
            "<134>Aug  2 15:12:05 filterlog[55624]: "
            "4,,,1000000103,hn0,match,block,in,4,0x0,,128,{ip_id},0,none,17,udp,78,"
            "192.168.1.{src_host},10.0.0.{dst_host},{src_port},53,58"
        ),
        # IPv6 TCP Pass (Dual-stack egress)
        (
            "<134>Jul 27 10:05:01 pf1 filterlog: "
            "6,,,1000000104,em1,match,pass,out,6,0x00,0,64,tcp,6,60,"
            "2001:db8::{src_host},2001:4860:4860::{dst_host},{src_port},443,0,S,125,0,65535,,mss"
        ),
    ]

    datagrams = []
    for i in range(count):
        template = templates[i % len(templates)]
        msg = template.format(
            ip_id=(1000 + (i % 50000)),
            src_host=(i % 250 + 1),
            dst_host=((i // 250) % 250 + 1),
            src_port=(10000 + (i % 50000)),
        )
        datagrams.append(msg.encode("utf-8"))
    return datagrams


class SimulatedClock:
    """A deterministic monotonic clock that increments smoothly with each query."""
    def __init__(self, start_time: float = 1000.0, step_per_call: float = 0.0005):
        self._time = start_time
        self._step = step_per_call

    def __call__(self) -> float:
        current = self._time
        self._time += self._step
        return current


def test_token_bucket_burst_and_recovery():
    """Verify TokenBucket correctly permits bursts up to capacity and refills at exact rate."""
    clock = 100.0
    bucket = TokenBucket(rate=1000.0, capacity=2000.0, now=clock)

    # Exhaust capacity (2000 tokens)
    for _ in range(2000):
        assert bucket.consume(now=clock) is True

    # 2001st consume must fail (empty bucket)
    assert bucket.consume(now=clock) is False

    # Advance clock by 0.5s -> 500 tokens regenerated
    clock += 0.5
    for _ in range(500):
        assert bucket.consume(now=clock) is True
    assert bucket.consume(now=clock) is False


def test_pfsense_collector_edge_rate_limiting(tmp_path: Path):
    """Verify RelayCollector drops datagrams when edge burst limits are exceeded and records loss in control spool."""
    spool_key = os.urandom(32)
    evidence_spool = EncryptedBoundedSpool(
        tmp_path / "edge_limit_evidence.db",
        stream_name="evidence",
        encryption_key=spool_key,
        max_payload_bytes=10 * 1024 * 1024,
        max_record_bytes=64 * 1024,
        min_free_disk_bytes=0,
    )
    control_spool = EncryptedBoundedSpool(
        tmp_path / "edge_limit_control.db",
        stream_name="control",
        encryption_key=spool_key,
        max_payload_bytes=5 * 1024 * 1024,
        max_record_bytes=64 * 1024,
        min_free_disk_bytes=0,
    )

    fixed_now = 500.0
    collector = RelayCollector(
        relay_id="WARSOC_RELAY_LIMIT_TEST",
        devices=[
            RelayDevice(
                device_id="pfsense-branch-1",
                vendor="pfsense",
                source_addresses=("192.168.1.0/24",),
                expected_eps=100,  # Capacity = 200 tokens
            )
        ],
        evidence_spool=evidence_spool,
        control_spool=control_spool,
        global_eps=500,
        clock=lambda: fixed_now,
    )

    datagrams = _generate_pfsense_datagrams(300)
    accepted = 0
    dropped = 0

    for dg in datagrams:
        res = collector.accept_datagram(dg, source_address="192.168.1.50")
        if res.status == "accepted":
            accepted += 1
        elif res.status == "dropped" and res.reason == "edge_rate_limit":
            dropped += 1

    # Capacity is 200 (expected_eps * 2)
    assert accepted == 200
    assert dropped == 100

    # Flush losses to control spool
    flushed = collector.flush_loss_summaries()
    assert flushed == 1
    control_records = list(control_spool.records())
    assert len(control_records) == 1
    assert control_records[0].payload["normalized"]["reason"] == "edge_rate_limit"
    assert control_records[0].payload["normalized"]["dropped_events"] == 100

    evidence_spool.close()
    control_spool.close()


def test_pfsense_collector_10k_events_high_eps_soak(tmp_path: Path):
    """
    Soak test: Ingest 10,000 pfSense filterlog datagrams through RelayCollector at 2,000 EPS.
    Verifies:
      - 100% acceptance (zero packet drops under budget)
      - AES-GCM encryption in evidence spool
      - Full hash chain verification
      - Zero memory or file corruption
    """
    total_events = 10000
    target_eps = 2000

    datagrams = _generate_pfsense_datagrams(total_events)
    assert len(datagrams) == total_events

    spool_key = os.urandom(32)
    db_path = tmp_path / "soak_evidence.db"
    evidence_spool = EncryptedBoundedSpool(
        db_path,
        stream_name="evidence",
        encryption_key=spool_key,
        max_payload_bytes=50 * 1024 * 1024,
        max_record_bytes=64 * 1024,
        min_free_disk_bytes=0,
    )
    control_spool = EncryptedBoundedSpool(
        tmp_path / "soak_control.db",
        stream_name="control",
        encryption_key=spool_key,
        max_payload_bytes=5 * 1024 * 1024,
        max_record_bytes=64 * 1024,
        min_free_disk_bytes=0,
    )

    # Simulated clock advancing by 1.0 / target_eps (0.0005s = 2000 EPS)
    sim_clock = SimulatedClock(start_time=1000.0, step_per_call=1.0 / target_eps)

    collector = RelayCollector(
        relay_id="WARSOC_RELAY_SOAK_01",
        devices=[
            RelayDevice(
                device_id="pfsense-core-fw",
                vendor="pfsense",
                source_addresses=("192.168.1.0/24", "10.0.0.0/8", "172.19.224.0/20"),
                expected_eps=5000,
            )
        ],
        evidence_spool=evidence_spool,
        control_spool=control_spool,
        global_eps=5000,
        global_bytes_per_second=20 * 1024 * 1024,
        clock=sim_clock,
    )

    t0 = time.perf_counter()
    accepted_count = 0
    for idx, dg in enumerate(datagrams):
        # Rotate source addresses to simulate multi-interface pfSense cluster
        src_ip = "192.168.1.1" if (idx % 2 == 0) else "10.0.0.1"
        res = collector.accept_datagram(dg, source_address=src_ip)
        assert res.status == "accepted", f"Event {idx} was not accepted: {res.reason}"
        accepted_count += 1
    t1 = time.perf_counter()

    elapsed = t1 - t0
    actual_eps = total_events / elapsed if elapsed > 0 else 0
    print(f"\n[SOAK METRIC] 10,000 pfSense events ingested in {elapsed:.3f}s ({actual_eps:.1f} EPS)")

    assert accepted_count == total_events
    stats = evidence_spool.stats()
    assert stats["records"] == total_events

    # Verify cryptographic hash chain across all 10,000 stored records
    evidence_spool.verify_chain()

    # Direct SQLite verification: Ensure payloads are stored as authenticated AES-GCM ciphertext
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM spool_records")
    row_count = cursor.fetchone()["cnt"]
    assert row_count == total_events

    # Verify ciphertext rows are non-empty blobs and plaintext is not leaked
    cursor.execute("SELECT sequence, nonce, ciphertext, record_hash FROM spool_records LIMIT 20")
    sample_rows = cursor.fetchall()
    for row in sample_rows:
        assert len(row["nonce"]) == 12
        assert len(row["ciphertext"]) > 100
        # Ensure raw pfSense message is not stored unencrypted in sqlite
        assert b"filterlog" not in row["ciphertext"]
        assert b"match,block" not in row["ciphertext"]
    conn.close()

    # Read back decrypted records and ensure event normalization integrity
    sample_records = list(evidence_spool.records(limit=50))
    for rec in sample_records:
        assert "event_uid" in rec.payload
        assert rec.payload["vendor"] == "pfsense"
        assert rec.payload["normalized"]["event_type"] in (
            "network_connection_blocked",
            "network_connection_permitted",
        )
        assert "src_ip" in rec.payload["normalized"]
        assert "dst_ip" in rec.payload["normalized"]

    evidence_spool.close()
    control_spool.close()


@pytest.mark.asyncio
async def test_pfsense_batch_assembly_signing_and_redis_admission_soak(
    redis_client, tmp_path: Path
):
    """
    End-to-end soak test:
      1. Generates 10,000 pfSense events into an EncryptedBoundedSpool.
      2. Assembles 100 signed batches of 100 events each in FIFO order.
      3. Verifies Ed25519 signatures, hash continuity, and sequence numbers.
      4. Admits all 100 batches into Redis via _admit_batch Lua script.
      5. Validates:
         - Exact sequence progression (1..100)
         - Idempotent duplicate replay rejection (status == 2)
         - Out-of-order / replay attack rejection (status == -1)
         - Cryptographic hash-chain continuity from RELAY_GENESIS_HASH
         - Clean FIFO spool drain to 0 records via acknowledge_through
    """
    total_events = 10000
    batch_size = 100
    expected_batches = total_events // batch_size

    spool_key = os.urandom(32)
    evidence_spool = EncryptedBoundedSpool(
        tmp_path / "batch_soak_evidence.db",
        stream_name="evidence",
        encryption_key=spool_key,
        max_payload_bytes=50 * 1024 * 1024,
        max_record_bytes=64 * 1024,
        min_free_disk_bytes=0,
    )
    control_spool = EncryptedBoundedSpool(
        tmp_path / "batch_soak_control.db",
        stream_name="control",
        encryption_key=spool_key,
        max_payload_bytes=5 * 1024 * 1024,
        max_record_bytes=64 * 1024,
        min_free_disk_bytes=0,
    )

    # Ingest 10,000 pfSense events
    collector = RelayCollector(
        relay_id="WARSOC_RELAY_SOAK_BATCH",
        devices=[
            RelayDevice(
                device_id="pfsense-core",
                vendor="pfsense",
                source_addresses=("192.168.1.0/24",),
                expected_eps=5000,
            )
        ],
        evidence_spool=evidence_spool,
        control_spool=control_spool,
        global_eps=5000,
        clock=SimulatedClock(100.0, 0.0001),
    )
    datagrams = _generate_pfsense_datagrams(total_events)
    for dg in datagrams:
        collector.accept_datagram(dg, source_address="192.168.1.1")

    assert evidence_spool.stats()["records"] == total_events

    # Generate relay Ed25519 signing keypair
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()

    relay_id = f"WARSOC_RELAY_{uuid.uuid4().hex}"
    chain_id = uuid.uuid4().hex
    tenant_id = f"TENANT_SOAK_{uuid.uuid4().hex[:8]}"

    relay_context = {
        "relay_id": relay_id,
        "tenant_id": tenant_id,
        "relay": {
            "last_sequence": 0,
            "last_batch_hash": RELAY_GENESIS_HASH,
            "chain_id": None,
            "key_epoch": 1,
        },
    }

    batches = []
    previous_hash = RELAY_GENESIS_HASH
    last_acked_sample_payload = None

    t_batch_start = time.perf_counter()
    for b_idx in range(expected_batches):
        # Spool records are retrieved in batches of batch_size (100)
        chunk = list(evidence_spool.records(limit=batch_size))
        assert len(chunk) == batch_size, f"Expected {batch_size} records in batch {b_idx}, got {len(chunk)}"
        event_payloads = [rec.payload for rec in chunk]
        last_acked_sample_payload = event_payloads[0]

        signed_batch = build_signed_batch(
            relay_id=relay_id,
            chain_id=chain_id,
            key_epoch=1,
            sequence=b_idx + 1,
            previous_batch_hash=previous_hash,
            events=event_payloads,
            private_key_pem=private_pem,
        )

        # Cryptographic verification of Ed25519 signature
        public_key.verify(bytes.fromhex(signed_batch.signature), signed_batch.body)

        batch_model = RelayBatch.model_validate_json(signed_batch.body)
        assert batch_model.sequence == b_idx + 1
        assert batch_model.previous_batch_hash == previous_hash

        batches.append((batch_model, signed_batch.batch_hash, signed_batch.body))
        previous_hash = signed_batch.batch_hash

        # Acknowledge through the chunk's last sequence (exact behavior of RelayOutbox)
        evidence_spool.acknowledge_through(chunk[-1].sequence)

    t_batch_end = time.perf_counter()

    # After processing all 10,000 events, evidence spool must be cleanly drained to 0
    assert evidence_spool.stats()["records"] == 0
    print(
        f"\n[SOAK METRIC] 100 Signed batches built, signature verified, and spool drained to 0 in "
        f"{t_batch_end - t_batch_start:.3f}s"
    )

    # Ingest batches sequentially into Redis admission engine
    t_admit_start = time.perf_counter()
    for seq_idx, (batch_model, b_hash, b_body) in enumerate(batches):
        payloads = [json.dumps({"event_uid": ev.event_uid}) for ev in batch_model.events]
        code = await _admit_batch(
            redis_client,
            relay_context,
            batch_model,
            b_hash,
            payloads,
            quota_bytes=500 * 1024 * 1024,
            payload_bytes=len(b_body),
        )
        assert code == 1, f"Batch sequence {batch_model.sequence} admission failed with code {code}"

        # Test Idempotent Duplicate Replay: Resending the exact same batch must return 2
        dup_code = await _admit_batch(
            redis_client,
            relay_context,
            batch_model,
            b_hash,
            payloads,
            quota_bytes=500 * 1024 * 1024,
            payload_bytes=len(b_body),
        )
        assert dup_code == 2, f"Batch sequence {batch_model.sequence} replay did not return 2"

    t_admit_end = time.perf_counter()
    print(
        f"[SOAK METRIC] 100 Batches (10,000 events) admitted to Redis in "
        f"{t_admit_end - t_admit_start:.3f}s"
    )

    # Verify chain break rejection: Attempting to admit an out-of-order sequence (e.g. 105 instead of 101)
    bad_batch = RelayBatch(
        schema_version="warsoc-relay-batch-v1",
        relay_id=relay_id,
        chain_id=chain_id,
        key_epoch=1,
        sequence=105,  # Broken sequence gap
        previous_batch_hash=previous_hash,
        created_at=datetime.now(timezone.utc),
        events=[last_acked_sample_payload],
    )
    bad_hash = hashlib.sha256(orjson.dumps(bad_batch.model_dump(mode="json"))).hexdigest()
    bad_code = await _admit_batch(
        redis_client,
        relay_context,
        bad_batch,
        bad_hash,
        [json.dumps({"event_uid": "gap"})],
        quota_bytes=500 * 1024 * 1024,
        payload_bytes=100,
    )
    assert bad_code == -1, f"Expected sequence gap to return -1, got {bad_code}"

    # Verify epoch mismatch rejection
    wrong_epoch_batch = bad_batch.model_copy(update={"sequence": 101, "key_epoch": 99})
    wrong_epoch_hash = hashlib.sha256(orjson.dumps(wrong_epoch_batch.model_dump(mode="json"))).hexdigest()
    epoch_code = await _admit_batch(
        redis_client,
        relay_context,
        wrong_epoch_batch,
        wrong_epoch_hash,
        [json.dumps({"event_uid": "wrong_epoch"})],
        quota_bytes=500 * 1024 * 1024,
        payload_bytes=100,
    )
    assert epoch_code == -2, f"Expected epoch mismatch to return -2, got {epoch_code}"

    evidence_spool.close()
    control_spool.close()

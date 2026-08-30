import asyncio
import hashlib
import json
import os
import socket
import types
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import ValidationError
from starlette.requests import Request

from app.network_relay.collector import RelayCollector, RelayDevice
from app.network_relay.identity import (
    RelayIdentityError,
    RelayIdentityStore,
    new_pending_identity,
)
from app.network_relay.runtime import (
    LifecycleJournal,
    RelayRuntime,
    RelayRuntimeConfig,
    RelayRuntimeError,
    _read_syslog_frame,
    prepare_dead_key_recovery,
)
from app.network_relay.spool import EncryptedBoundedSpool
from app.routes.network_relay import (
    RELAY_GENESIS_HASH,
    RelayActivationRequest,
    RelayBatch,
    RelayDeviceSpec,
    RelayEvent,
    RelayListenerSpec,
    RelayRecoverRequest,
    RelayRegisterRequest,
    RelayRevokeRequest,
    _admit_batch,
    _claim_one_time_secret,
    _consume_claimed_secret,
    _persist_batch_receipt,
    _reject_future_time,
    generate_relay_activation,
    list_relay_status,
    recover_relay_key,
    register_relay,
    revoke_relay,
    settings as relay_settings,
)


class AesTestProtector:
    def __init__(self, key: bytes):
        self.cipher = AESGCM(key)

    def protect(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self.cipher.encrypt(nonce, plaintext, b"test-relay-identity")

    def unprotect(self, ciphertext: bytes) -> bytes:
        return self.cipher.decrypt(
            ciphertext[:12], ciphertext[12:], b"test-relay-identity"
        )


def _config(tmp_path, **overrides) -> RelayRuntimeConfig:
    values = {
        "backend_url": "https://api.example.test",
        "data_directory": str(tmp_path),
        "devices": [
            {
                "device_id": "branch-pfsense",
                "vendor": "pfsense",
                "source_addresses": ["10.0.0.1/32"],
                "transport": "udp",
                "expected_eps": 100,
            }
        ],
        "listeners": [
            {"transport": "udp", "bind_host": "10.0.0.10", "port": 5514}
        ],
        "evidence_spool_bytes": 64 * 1024**2,
        "control_spool_bytes": 8 * 1024**2,
        "minimum_free_disk_bytes": 256 * 1024**2,
    }
    values.update(overrides)
    return RelayRuntimeConfig.model_validate(values)


def _request(redis, *, host="127.0.0.1"):
    app = types.SimpleNamespace(state=types.SimpleNamespace(redis=redis))
    return Request(
        {
            "type": "http",
            "app": app,
            "method": "POST",
            "path": "/api/v1/network-relay/test",
            "headers": [],
            "client": (host, 5514),
            "server": ("testserver", 80),
            "scheme": "http",
            "query_string": b"",
        }
    )


def _free_local_port(sock_type: int) -> int:
    with socket.socket(socket.AF_INET, sock_type) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_runtime_config_rejects_wildcard_ambiguous_and_unused_listeners(tmp_path):
    with pytest.raises(ValidationError):
        _config(
            tmp_path,
            listeners=[{"transport": "udp", "bind_host": "0.0.0.0", "port": 5514}],
        )
    with pytest.raises(ValidationError):
        _config(
            tmp_path,
            devices=[
                {
                    "device_id": "fw-a",
                    "vendor": "pfsense",
                    "source_addresses": ["10.0.0.0/24"],
                    "transport": "udp",
                },
                {
                    "device_id": "fw-b",
                    "vendor": "fortinet",
                    "source_addresses": ["10.0.0.1/32"],
                    "transport": "udp",
                },
            ],
        )
    with pytest.raises(ValidationError):
        _config(
            tmp_path,
            listeners=[
                {"transport": "udp", "bind_host": "10.0.0.10", "port": 5514},
                {"transport": "tcp", "bind_host": "10.0.0.10", "port": 6514},
            ],
        )


def test_activation_contract_rejects_unsafe_or_unmatched_listeners():
    device = RelayDeviceSpec(
        device_id="branch-pfsense",
        vendor="pfsense",
        source_addresses=["10.0.0.1/32"],
        transport="udp",
    )
    with pytest.raises(ValidationError, match="explicit unicast"):
        RelayActivationRequest(
            relay_name="Branch Relay",
            devices=[device],
            listeners=[
                RelayListenerSpec(transport="udp", bind_host="0.0.0.0", port=5514)
            ],
        )
    with pytest.raises(ValidationError, match="exactly one relay listener"):
        RelayActivationRequest(
            relay_name="Branch Relay",
            devices=[device],
            listeners=[
                RelayListenerSpec(transport="tcp", bind_host="10.0.0.10", port=5514)
            ],
        )


def test_identity_store_is_protected_atomic_and_tamper_detecting(tmp_path):
    path = tmp_path / "identity.dpapi"
    store = RelayIdentityStore(path, protector=AesTestProtector(os.urandom(32)))
    pending = new_pending_identity()
    store.save(pending)
    raw = path.read_bytes()
    assert pending.private_key_pem() not in raw
    assert pending.registration_nonce.encode() not in raw
    loaded = store.load()
    assert loaded.registration_nonce == pending.registration_nonce
    assert loaded.public_key_pem() == pending.public_key_pem()

    registered = pending.with_registration(
        relay_id="WARSOC_RELAY_" + "a" * 32,
        tenant_id="WARSOC_TEST",
        relay_token="secret-relay-token",
        key_epoch=2,
    )
    store.save(registered)
    assert store.load().registered is True
    tampered = bytearray(path.read_bytes())
    tampered[-1] ^= 1
    path.write_bytes(bytes(tampered))
    with pytest.raises(RelayIdentityError):
        store.load()


@pytest.mark.asyncio
async def test_registration_is_persisted_before_activation_secret_is_removed(tmp_path):
    config = _config(tmp_path)
    activation = tmp_path / config.activation_file
    activation.write_text("WARSOC-RELAY-activation-code-123456", encoding="utf-8")
    store = RelayIdentityStore(
        tmp_path / config.identity_file,
        protector=AesTestProtector(os.urandom(32)),
    )
    calls = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        payload = __import__("json").loads(request.content)
        assert payload["registration_nonce"]
        assert "PRIVATE KEY" not in payload["public_key"]
        return httpx.Response(
            200,
            json={
                "relay_id": "WARSOC_RELAY_" + "b" * 32,
                "tenant_id": "WARSOC_TEST",
                "relay_token": "relay-token",
                "key_epoch": 1,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        runtime = RelayRuntime(config, identity_store=store, client=client)
        identity = await runtime._ensure_identity()
    assert identity.registered is True
    assert store.load().relay_token == "relay-token"
    assert not activation.exists()
    assert len(calls) == 1


def test_dead_key_recovery_preserves_every_local_evidence_file(tmp_path):
    config = _config(tmp_path)
    store = RelayIdentityStore(
        tmp_path / config.identity_file,
        protector=AesTestProtector(os.urandom(32)),
    )
    store.save(new_pending_identity())
    (tmp_path / config.activation_file).write_text(
        "WARSOC-RELAY-RECOVERY-authorized-code-123", encoding="utf-8"
    )
    for name in ("evidence-spool.db", "control-spool.db", "cloud-outbox.db"):
        (tmp_path / name).write_bytes(b"retained-evidence")
    LifecycleJournal(tmp_path / "lifecycle.json").write("STOPPED")

    archive = prepare_dead_key_recovery(config, identity_store=store)
    assert (archive / "evidence-spool.db").read_bytes() == b"retained-evidence"
    assert (archive / "control-spool.db").read_bytes() == b"retained-evidence"
    assert (archive / "cloud-outbox.db").read_bytes() == b"retained-evidence"
    assert (archive / "evidence-gap.json").is_file()
    assert store.load().registered is False
    assert LifecycleJournal(tmp_path / "lifecycle.json").read()["state"] == "KEY_RECOVERY_PENDING"


@pytest.mark.asyncio
async def test_tcp_framing_is_bounded_and_supports_rfc6587_and_newline():
    octet_reader = asyncio.StreamReader()
    octet_reader.feed_data(b"5 hello")
    octet_reader.feed_eof()
    assert await _read_syslog_frame(octet_reader, 64) == b"hello"

    line_reader = asyncio.StreamReader()
    line_reader.feed_data(b"<13>filterlog: record\r\n")
    line_reader.feed_eof()
    assert await _read_syslog_frame(line_reader, 64) == b"<13>filterlog: record"

    oversize = asyncio.StreamReader()
    oversize.feed_data(b"999 ")
    oversize.feed_eof()
    with pytest.raises(RelayRuntimeError):
        await _read_syslog_frame(oversize, 64)


def test_collector_refuses_transport_contract_mismatch(tmp_path):
    key = os.urandom(32)
    evidence = EncryptedBoundedSpool(
        tmp_path / "evidence.db",
        stream_name="evidence",
        encryption_key=key,
        max_payload_bytes=4096,
        max_record_bytes=2048,
        min_free_disk_bytes=0,
    )
    control = EncryptedBoundedSpool(
        tmp_path / "control.db",
        stream_name="control",
        encryption_key=key,
        max_payload_bytes=4096,
        max_record_bytes=2048,
        min_free_disk_bytes=0,
    )
    collector = RelayCollector(
        relay_id="WARSOC_RELAY_" + "c" * 32,
        devices=[
            RelayDevice(
                device_id="fw",
                vendor="pfsense",
                source_addresses=("10.0.0.1/32",),
                transport="tls",
            )
        ],
        evidence_spool=evidence,
        control_spool=control,
    )
    result = collector.accept_message(
        b"filterlog: 5,,,100,em0,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,10.0.0.2,8.8.8.8,5000,443,0,S",
        source_address="10.0.0.1",
        transport="udp",
    )
    assert result.status == "dropped"
    assert result.reason == "unregistered_or_ambiguous_source"
    evidence.close()
    control.close()


@pytest.mark.asyncio
async def test_runtime_udp_and_tcp_listeners_reach_encrypted_spool(tmp_path):
    udp_port = _free_local_port(socket.SOCK_DGRAM)
    tcp_port = _free_local_port(socket.SOCK_STREAM)
    config = _config(
        tmp_path,
        devices=[
            {
                "device_id": "pfsense-udp",
                "vendor": "pfsense",
                "source_addresses": ["127.0.0.1/32"],
                "transport": "udp",
            },
            {
                "device_id": "pfsense-tcp",
                "vendor": "pfsense",
                "source_addresses": ["127.0.0.1/32"],
                "transport": "tcp",
            },
        ],
        listeners=[
            {"transport": "udp", "bind_host": "127.0.0.1", "port": udp_port},
            {"transport": "tcp", "bind_host": "127.0.0.1", "port": tcp_port},
        ],
    )
    pending = new_pending_identity()
    identity = pending.with_registration(
        relay_id="WARSOC_RELAY_" + "d" * 32,
        tenant_id="WARSOC_TEST",
        relay_token="test-token",
        key_epoch=1,
    )
    store = RelayIdentityStore(
        tmp_path / config.identity_file,
        protector=AesTestProtector(os.urandom(32)),
    )
    store.save(identity)
    runtime = RelayRuntime(config, identity_store=store)
    runtime.identity = identity
    runtime._initialize_storage(identity)
    await runtime._start_listeners()
    message = (
        b"filterlog: 5,,,100,em0,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,"
        b"10.0.0.2,8.8.8.8,5000,443,0,S"
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(message, ("127.0.0.1", udp_port))
        reader, writer = await asyncio.open_connection("127.0.0.1", tcp_port)
        del reader
        writer.write(message + b"\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        for _ in range(20):
            if runtime.evidence_spool.stats()["records"] == 2:
                break
            await asyncio.sleep(0.05)
        assert runtime.evidence_spool.stats()["records"] == 2
        runtime.evidence_spool.verify_chain()
    finally:
        for transport in runtime._udp_transports:
            transport.close()
        for server in runtime._servers:
            server.close()
            await server.wait_closed()
        runtime.outbox.close()
        runtime.evidence_spool.close()
        runtime.control_spool.close()


def test_old_relay_times_survive_outage_but_future_times_fail():
    now = datetime.now(timezone.utc)
    _reject_future_time(now - timedelta(days=14), now)
    with pytest.raises(ValueError):
        _reject_future_time(now + timedelta(minutes=6), now)


@pytest.mark.asyncio
async def test_one_time_relay_secret_is_claimed_before_commit(redis_client):
    secret_key = "warsoc:test:relay-one-time-secret"
    await redis_client.set(secret_key, "protected-value", ex=60)
    raw, claim_key = await _claim_one_time_secret(
        redis_client,
        secret_key=secret_key,
        claimant="a" * 32,
        invalid_detail="invalid",
    )
    assert raw == "protected-value"
    assert await redis_client.exists(secret_key) == 1
    with pytest.raises(Exception) as conflict:
        await _claim_one_time_secret(
            redis_client,
            secret_key=secret_key,
            claimant="b" * 32,
            invalid_detail="invalid",
        )
    assert getattr(conflict.value, "status_code", None) == 409
    await _consume_claimed_secret(
        redis_client,
        secret_key=secret_key,
        claim_key=claim_key,
        claimant="a" * 32,
    )
    assert await redis_client.exists(secret_key, claim_key) == 0


@pytest.mark.asyncio
async def test_cloud_registration_status_revocation_and_dead_key_recovery(
    db, redis_client, monkeypatch
):
    monkeypatch.setattr(relay_settings, "network_relay_enabled", True)
    tenant_id = "WARSOC_RELAY_LIFECYCLE"
    admin = {
        "tenant_id": tenant_id,
        "username": "relay-admin",
        "email": "relay-admin@example.com",
    }
    await db["tenants"].insert_one(
        {
            "tenant_id": tenant_id,
            "status": "active",
            "active": True,
            "has_active_plan": True,
            "max_network_relays": 2,
        }
    )
    request = _request(redis_client)
    activation = await generate_relay_activation(
        request=request,
        body=RelayActivationRequest(
            relay_name="Branch Relay",
            devices=[
                RelayDeviceSpec(
                    device_id="branch-pfsense",
                    vendor="pfsense",
                    source_addresses=["10.0.0.1/32"],
                    transport="udp",
                )
            ],
            listeners=[
                RelayListenerSpec(
                    transport="udp",
                    bind_host="10.0.0.10",
                    port=5514,
                )
            ],
        ),
        current_user=admin,
        _="admin",
        db=db,
    )
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    registration = RelayRegisterRequest(
        activation_code=activation["activation_code"],
        registration_nonce="a" * 32,
        public_key=public_key,
        hostname="RELAY-01",
        version="1.0.0",
    )
    first = await register_relay(request=request, body=registration, db=db)
    second = await register_relay(request=request, body=registration, db=db)
    assert second["relay_id"] == first["relay_id"]
    assert second["registration_recovered"] is True
    assert await db["network_relays"].count_documents({"tenant_id": tenant_id}) == 1

    status = await list_relay_status(
        request=request, current_user=admin, _="admin", db=db
    )
    assert status["relays"][0]["devices"][0]["vendor"] == "pfsense"
    assert status["relays"][0]["health"] == "OFFLINE"

    revoked = await revoke_relay(
        relay_id=first["relay_id"],
        body=RelayRevokeRequest(reason="Tenant requested controlled relay replacement"),
        request=request,
        current_user=admin,
        _="admin",
        db=db,
    )
    assert revoked["status"] == "revoked"
    assert await redis_client.exists(f"warsoc:relay_revoked:{first['relay_id']}") == 1

    recovery_code = "WARSOC-RELAY-RECOVERY-test-authorized-code"
    old = await db["network_relays"].find_one({"relay_id": first["relay_id"]})
    authorization = {
        "purpose": "network_relay_key_recovery",
        "tenant_id": tenant_id,
        "relay_id": first["relay_id"],
        "authorized_by": "relay-admin",
        "reason": "Local DPAPI identity was lost",
        "previous_chain_id": old.get("chain_id"),
        "previous_key_epoch": 1,
        "previous_sequence": 0,
        "previous_batch_hash": RELAY_GENESIS_HASH,
        "authorized_at": datetime.now(timezone.utc).isoformat(),
    }
    await redis_client.set(
        f"warsoc:relay_recovery:{recovery_code}",
        json.dumps(authorization),
        ex=3600,
    )
    new_private = ed25519.Ed25519PrivateKey.generate()
    new_public = new_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    recovered = await recover_relay_key(
        request=request,
        body=RelayRecoverRequest(
            activation_code=recovery_code,
            registration_nonce="b" * 32,
            public_key=new_public,
            hostname="RELAY-01",
            version="1.0.1",
        ),
        db=db,
    )
    assert recovered["relay_id"] == first["relay_id"]
    assert recovered["key_epoch"] == 2
    assert recovered["previous_chain_closed"] is True
    row = await db["network_relays"].find_one({"relay_id": first["relay_id"]})
    assert row["status"] == "active"
    assert row["key_epoch"] == 2
    assert row["last_sequence"] == 0
    assert await db["network_relay_chain_resets"].count_documents(
        {"relay_id": first["relay_id"]}
    ) == 1
    chain = await redis_client.hgetall(f"warsoc:relay_chain:{first['relay_id']}")
    assert int(chain[b"key_epoch"] if b"key_epoch" in chain else chain["key_epoch"]) == 2


@pytest.mark.asyncio
async def test_relay_status_tracks_device_events_losses_and_silence(
    db, redis_client, monkeypatch
):
    monkeypatch.setattr(relay_settings, "network_relay_enabled", True)
    request = _request(redis_client)
    tenant_id = "WARSOC_RELAY_DEVICE_STATUS"
    relay_id = f"WARSOC_RELAY_{'a' * 32}"
    now = datetime.now(timezone.utc)
    device = {
        "device_id": "branch-pfsense",
        "vendor": "pfsense",
        "model": "CE-2.8.1",
        "source_addresses": ["192.0.2.1/32"],
        "transport": "udp",
        "timezone": "UTC",
        "expected_eps": 100,
    }
    relay = {
        "tenant_id": tenant_id,
        "relay_id": relay_id,
        "relay_name": "Branch Relay",
        "hostname": "RELAY-01",
        "version": "1.0.0",
        "status": "active",
        "key_epoch": 1,
        "last_sequence": 0,
        "devices": [device],
        "created_at": now,
    }
    await db["network_relays"].insert_one(relay)
    raw_message = (
        "<134>Aug  2 15:12:05 filterlog[55624]: "
        "4,,,1000000103,hn0,match,block,in,4,0x0,,128,49872,0,none,17,udp,78,"
        "172.19.224.1,172.19.239.255,137,137,58"
    )
    evidence = RelayEvent(
        event_uid="relay-device-status-evidence-0001",
        record_class="evidence",
        device_id=device["device_id"],
        vendor="pfsense",
        transport="udp",
        source_address="192.0.2.1",
        device_event_time=now,
        relay_receipt_time=now,
        raw_message=raw_message,
        raw_message_hash=hashlib.sha256(raw_message.encode("utf-8")).hexdigest(),
        normalized={
            "event_type": "network_connection_blocked",
            "action": "block",
            "src_ip": "172.19.224.1",
            "dst_ip": "172.19.239.255",
            "src_port": 137,
            "dst_port": 137,
            "protocol": "udp",
        },
    )
    first_batch = RelayBatch(
        schema_version="warsoc-relay-batch-v1",
        relay_id=relay_id,
        chain_id="b" * 32,
        key_epoch=1,
        sequence=1,
        previous_batch_hash=RELAY_GENESIS_HASH,
        created_at=now,
        events=[evidence],
    )
    context = {"tenant_id": tenant_id, "relay_id": relay_id, "relay": relay}
    await _persist_batch_receipt(db, context, first_batch, "c" * 64, now)

    status = await list_relay_status(
        request=request, current_user={"tenant_id": tenant_id}, _="admin", db=db
    )
    assert status["relays"][0]["health"] == "ACTIVE"
    assert status["relays"][0]["devices"][0]["health"] == "ACTIVE"
    assert status["relays"][0]["devices"][0]["time_confidence"] == "high"

    failure_data = {
        "event_type": "device_health",
        "state": "DEGRADED",
        "reason": "parser_rejected",
        "affected_device_id": device["device_id"],
        "dropped_events": 4,
        "dropped_bytes": 400,
    }
    failure_raw = json.dumps(failure_data, sort_keys=True, separators=(",", ":"))
    failure_time = now + timedelta(seconds=1)
    failure = RelayEvent(
        event_uid="relay-device-status-control-0001",
        record_class="control",
        device_id=relay_id,
        vendor="generic",
        transport="api",
        source_address="127.0.0.1",
        device_event_time=None,
        relay_receipt_time=failure_time,
        raw_message=failure_raw,
        raw_message_hash=hashlib.sha256(failure_raw.encode("utf-8")).hexdigest(),
        normalized=failure_data,
    )
    second_batch = RelayBatch(
        schema_version="warsoc-relay-batch-v1",
        relay_id=relay_id,
        chain_id="b" * 32,
        key_epoch=1,
        sequence=2,
        previous_batch_hash="c" * 64,
        created_at=failure_time,
        events=[failure],
    )
    await _persist_batch_receipt(db, context, second_batch, "d" * 64, failure_time)

    status = await list_relay_status(
        request=request, current_user={"tenant_id": tenant_id}, _="admin", db=db
    )
    device_status = status["relays"][0]["devices"][0]
    assert device_status["health"] == "DEGRADED"
    assert device_status["last_failure_reason"] == "parser_rejected"
    assert device_status["last_reported_drops"] == 4

    await db["network_relay_device_status"].update_one(
        {"tenant_id": tenant_id, "relay_id": relay_id, "device_id": device["device_id"]},
        {"$set": {"last_event_at": now - timedelta(seconds=901)}},
    )
    status = await list_relay_status(
        request=request, current_user={"tenant_id": tenant_id}, _="admin", db=db
    )
    assert status["relays"][0]["devices"][0]["health"] == "SILENT"

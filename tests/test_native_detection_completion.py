import asyncio
import base64
import importlib.util
import json
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import HTTPException
from pydantic import ValidationError

from app.routes.ingest_pulse import _consume_agent_ingest_envelope
from app.routes.agent_orchestration import _sanitize_sensor_status
from app.routes.pos import PosAuditEvent
from app.utils.agent_crypto import verify_event_signature
from app.utils.siem_catalog import SIEM_RULES
from app.workers import email_daemon
from app.workers.fbr_worker import (
    FBR_ENCRYPTED_FIELDS,
    FIM_CLAIM_TTL_SECONDS,
    FIMCorrelationUnavailable,
    _clock_integrity_verdict,
    _encrypt_fbr_fields,
    _normalize_native_fim_event,
)
from app.workers.peca_worker import _should_alert_directly
from scripts.migrate_fbr_encryption import encrypt_if_needed


ROOT = Path(__file__).resolve().parents[1]


class FakeRedis:
    def __init__(self, *, fail=False):
        self.data = {}
        self.ttls = {}
        self.fail = fail

    async def setex(self, key, ttl, value):
        if self.fail:
            raise RuntimeError("redis unavailable")
        self.data[key] = value
        self.ttls[key] = ttl

    async def getdel(self, key):
        if self.fail:
            raise RuntimeError("redis unavailable")
        return self.data.pop(key, None)

    async def incr(self, key):
        self.data[key] = int(self.data.get(key, 0)) + 1
        return self.data[key]

    async def set(self, key, value, nx=False, ex=None):
        if self.fail:
            raise RuntimeError("redis unavailable")
        if nx and key in self.data:
            return False
        self.data[key] = value
        if ex is not None:
            self.ttls[key] = int(ex)
        return True

    async def eval(self, script, numkeys, correlation_key, claim_key, claim_ttl):
        if self.fail:
            raise RuntimeError("redis unavailable")
        value = self.data.get(correlation_key)
        if value is None:
            value = self.data.get(claim_key)
        if value is not None:
            self.data[claim_key] = value
            self.ttls[claim_key] = int(claim_ttl)
            self.data.pop(correlation_key, None)
        return value


class FakeEmailPipeline:
    def __init__(self, redis):
        self.redis = redis
        self.operations = []

    def lrem(self, key, count, value):
        self.operations.append(("lrem", key, count, value))
        return self

    def lpush(self, key, value):
        self.operations.append(("lpush", key, value))
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def execute(self):
        results = []
        for operation, key, *args in self.operations:
            if operation == "lrem":
                count, value = args
                removed = 0
                retained = []
                for item in self.redis.lists.get(key, []):
                    if item == value and removed < count:
                        removed += 1
                    else:
                        retained.append(item)
                self.redis.lists[key] = retained
                results.append(removed)
            elif operation == "lpush":
                (value,) = args
                self.redis.lists.setdefault(key, []).insert(0, value)
                results.append(len(self.redis.lists[key]))
        return results


class FakeEmailRedis:
    def __init__(self):
        self.lists = {}
        self.counters = {}

    def pipeline(self, transaction=True):
        return FakeEmailPipeline(self)

    async def lrem(self, key, count, value):
        pipeline = FakeEmailPipeline(self)
        pipeline.lrem(key, count, value)
        return (await pipeline.execute())[0]

    async def incr(self, key):
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]


def _native_event(event_id, *, access_mask=None, object_name=None, handle_id="0x44"):
    processed = {"handle_id": handle_id}
    if access_mask is not None:
        processed["access_mask"] = access_mask
    if object_name is not None:
        processed["object_name"] = object_name
    return {
        "tenant_id": "TENANT-A",
        "agent_id": "AGENT-A",
        "event_id": event_id,
        "event_uid": f"Security:{event_id}:{handle_id}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": "10.0.0.5",
        "processed_data": processed,
    }


@pytest.mark.asyncio
async def test_redis_fim_delete_correlation_is_shared_and_atomic():
    redis = FakeRedis()
    intent = _native_event(
        "4663",
        access_mask="0x10000",
        object_name=r"C:\POS\data\sales.mdf",
    )
    action, normalized, claim_key = await _normalize_native_fim_event(redis, intent, "4663")
    assert action == "context"
    assert normalized is None
    assert claim_key is None
    key = "warsoc:fim_correlate:TENANT-A:AGENT-A:0x44"
    assert redis.data[key] == r"C:\POS\data\sales.mdf"
    assert redis.ttls[key] == 60

    action, normalized, claim_key = await _normalize_native_fim_event(
        redis,
        _native_event("4660"),
        "4660",
    )
    assert action == "emit"
    assert normalized["event_id"] == "FIM-DB-MOD"
    assert normalized["source_event_id"] == "4660"
    assert normalized["processed_data"]["tamper_action"] == "file_deleted"
    assert key not in redis.data
    assert redis.data[claim_key] == r"C:\POS\data\sales.mdf"
    assert redis.ttls[claim_key] == FIM_CLAIM_TTL_SECONDS

    # Persistence success consumes the retry claim. A later duplicate then misses.
    redis.data.pop(claim_key)
    action, normalized, claim_key = await _normalize_native_fim_event(
        redis,
        _native_event("4660"),
        "4660",
    )
    assert action == "unmatched"
    assert normalized is None
    assert claim_key is None


@pytest.mark.asyncio
async def test_real_redis_fim_claim_survives_retry_until_persistence(redis_client):
    event_uid = "Security:4660:durable-claim"
    intent = _native_event(
        "4663",
        access_mask="0x10000",
        object_name=r"C:\POS\data\durable.sqlite3",
        handle_id="0x99",
    )
    intent["event_uid"] = "Security:4663:durable-claim"
    deletion = _native_event("4660", handle_id="0x99")
    deletion["event_uid"] = event_uid

    await _normalize_native_fim_event(redis_client, intent, "4663")
    action, normalized, claim_key = await _normalize_native_fim_event(
        redis_client,
        deletion,
        "4660",
    )
    assert action == "emit"
    assert normalized["processed_data"]["object_name"].endswith("durable.sqlite3")
    assert await redis_client.get(claim_key) == r"C:\POS\data\durable.sqlite3"
    assert 0 < await redis_client.ttl(claim_key) <= FIM_CLAIM_TTL_SECONDS

    retry_action, retry_normalized, retry_claim_key = await _normalize_native_fim_event(
        redis_client,
        deletion,
        "4660",
    )
    assert retry_action == "emit"
    assert retry_normalized["event_uid"] == normalized["event_uid"]
    assert retry_claim_key == claim_key

    await redis_client.delete(claim_key)
    final_action, _, _ = await _normalize_native_fim_event(
        redis_client,
        deletion,
        "4660",
    )
    assert final_action == "unmatched"


@pytest.mark.asyncio
async def test_expired_fim_context_does_not_create_tamper_evidence():
    redis = FakeRedis()
    intent = _native_event(
        "4663",
        access_mask="0x10000",
        object_name=r"C:\POS\data\sales.db3",
    )
    await _normalize_native_fim_event(redis, intent, "4663")
    redis.data.clear()

    action, normalized, claim_key = await _normalize_native_fim_event(
        redis,
        _native_event("4660"),
        "4660",
    )
    assert action == "unmatched"
    assert normalized is None
    assert claim_key is None


@pytest.mark.asyncio
async def test_fim_ignores_normal_database_writes_and_preserves_redis_failures():
    redis = FakeRedis()
    write_event = _native_event(
        "4663",
        access_mask="0x2",
        object_name=r"C:\POS\data\sales.sqlite",
    )
    action, normalized, claim_key = await _normalize_native_fim_event(redis, write_event, "4663")
    assert action == "ignore"
    assert normalized is None
    assert claim_key is None
    assert not any(key.startswith("warsoc:fim_correlate:") for key in redis.data)

    with pytest.raises(FIMCorrelationUnavailable):
        await _normalize_native_fim_event(
            FakeRedis(fail=True),
            _native_event(
                "4663",
                access_mask="0x10000",
                object_name=r"C:\POS\data\sales.db",
            ),
            "4663",
        )


@pytest.mark.asyncio
async def test_fim_permission_change_requires_database_path():
    redis = FakeRedis()
    action, normalized, claim_key = await _normalize_native_fim_event(
        redis,
        _native_event("4670", object_name=r"C:\POS\data\sales.ldf"),
        "4670",
    )
    assert action == "emit"
    assert normalized["processed_data"]["tamper_action"] == "permissions_changed"
    assert claim_key is None

    action, normalized, claim_key = await _normalize_native_fim_event(
        redis,
        _native_event("4670", object_name=r"C:\POS\data\readme.txt"),
        "4670",
    )
    assert action == "unmatched"
    assert normalized is None
    assert claim_key is None


@pytest.mark.asyncio
async def test_agent_ingest_requires_and_atomically_consumes_nonce_envelope():
    redis = FakeRedis()
    with pytest.raises(HTTPException) as raw_list_error:
        await _consume_agent_ingest_envelope([], "AGENT-A", redis)
    assert raw_list_error.value.status_code == 422

    envelope = {
        "nonce": "0123456789abcdef0123456789abcdef",
        "timestamp": int(datetime.now(timezone.utc).timestamp()),
        "payload": [{"event_id": "4688"}],
    }
    assert await _consume_agent_ingest_envelope(envelope, "AGENT-A", redis) == envelope["payload"]
    with pytest.raises(HTTPException) as replay_error:
        await _consume_agent_ingest_envelope(envelope, "AGENT-A", redis)
    assert replay_error.value.status_code == 409


@pytest.mark.asyncio
async def test_email_jobs_are_retried_durably_then_acknowledged(monkeypatch):
    monkeypatch.setattr(email_daemon.settings, "enable_security_alert_emails", True)
    redis = FakeEmailRedis()
    raw_payload = json.dumps(
        {
            "type": "security_alert_email",
            "recipient": "analyst@example.com",
            "tenant_id": "TENANT-A",
            "payload": {"severity": "HIGH", "name": "Native detection"},
        }
    )
    redis.lists[email_daemon.EMAIL_PROCESSING_QUEUE] = [raw_payload]

    async def no_wait(_seconds):
        return None

    monkeypatch.setattr(email_daemon.asyncio, "sleep", no_wait)
    monkeypatch.setattr(email_daemon, "MAX_DELIVERY_ATTEMPTS", 3)
    monkeypatch.setattr(
        email_daemon,
        "_send_email",
        lambda _message: (_ for _ in ()).throw(TimeoutError("smtp timeout")),
    )

    await email_daemon._process_job(raw_payload, redis, asyncio.Semaphore(1))

    assert redis.lists[email_daemon.EMAIL_PROCESSING_QUEUE] == []
    assert len(redis.lists[email_daemon.EMAIL_QUEUE]) == 1
    retry_payload = redis.lists[email_daemon.EMAIL_QUEUE].pop()
    retry_job = json.loads(retry_payload)
    assert retry_job["_delivery_attempt"] == 1
    assert redis.counters["warsoc_email_retries_total"] == 1

    redis.lists[email_daemon.EMAIL_PROCESSING_QUEUE] = [retry_payload]
    monkeypatch.setattr(email_daemon, "_send_email", lambda _message: None)
    await email_daemon._process_job(retry_payload, redis, asyncio.Semaphore(1))

    assert redis.lists[email_daemon.EMAIL_PROCESSING_QUEUE] == []
    assert redis.counters["warsoc_email_delivered_total"] == 1


def test_pos_api_schema_is_strict_and_rejects_fim():
    valid = {
        "event_id": "FBR-INV-MOD",
        "event_uid": "pos-event-0001",
        "invoice_id": "INV-100",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": "cashier-1",
        "source_system": "pos-a",
        "before_hash": "a" * 64,
        "after_hash": "b" * 64,
    }
    assert PosAuditEvent.model_validate(valid).event_id == "FBR-INV-MOD"
    with pytest.raises(ValidationError):
        PosAuditEvent.model_validate({**valid, "event_id": "FIM-DB-MOD"})
    with pytest.raises(ValidationError):
        PosAuditEvent.model_validate({**valid, "unexpected": True})


def test_manual_sales_model_has_no_payment_provider_runtime_surface():
    config_source = (ROOT / "app" / "config" / "config.py").read_text(encoding="utf-8").lower()
    sales_source = (ROOT / "app" / "routes" / "sales.py").read_text(encoding="utf-8").lower()
    assert "safepay" not in config_source
    assert "safepay" not in sales_source


def test_legacy_fbr_fields_are_encrypted_idempotently():
    fernet = Fernet(Fernet.generate_key())
    encrypted, changed = encrypt_if_needed(fernet, {"secret": "invoice-data"})
    assert changed
    assert json.loads(fernet.decrypt(encrypted.encode()).decode()) == {"secret": "invoice-data"}
    encrypted_again, changed_again = encrypt_if_needed(fernet, encrypted)
    assert encrypted_again == encrypted
    assert not changed_again


def test_fbr_worker_encrypts_every_sensitive_field():
    fernet = Fernet(Fernet.generate_key())
    document = {
        "message": "invoice changed",
        "raw_event": {"source": "native"},
        "raw_data": ["a", "b"],
        "raw_event_data": {"event_data": {"ObjectName": r"C:\POS\sales.db"}},
        "processed_data": {"invoice_id": "INV-42"},
    }
    _encrypt_fbr_fields(document, fernet)
    assert document["encryption_version"] == "fernet-v1"
    for field in FBR_ENCRYPTED_FIELDS:
        plaintext = fernet.decrypt(document[field].encode()).decode()
        assert plaintext


def test_fbr_clock_guard_accepts_durable_backlog_but_rejects_future_events():
    old_timestamp = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()
    verdict, age_seconds = _clock_integrity_verdict(old_timestamp, {})
    assert verdict == "delayed"
    assert age_seconds > 300

    future_timestamp = datetime(2099, 1, 1, tzinfo=timezone.utc).isoformat()
    verdict, age_seconds = _clock_integrity_verdict(future_timestamp, {})
    assert verdict == "drop"
    assert age_seconds < -300


def test_agent_health_sanitizer_preserves_degraded_spool_state():
    sanitized = _sanitize_sensor_status(
        {
            "channels": {"Security": {"status": "degraded", "last_error": "disk full"}},
            "counters": {"spool_write_failures": 3},
        }
    )
    assert sanitized["channels"]["Security"]["status"] == "degraded"
    assert sanitized["counters"]["spool_write_failures"] == 3


def test_peca_direct_alert_policy_excludes_context_events():
    for event_id in {"4624", "4625", "4672", "4688"}:
        assert not _should_alert_directly(event_id)
    for event_id in {"1100", "1102", "7045"}:
        assert _should_alert_directly(event_id)


def test_native_catalog_has_no_sysmon_dependency_and_contextual_alerts():
    event_map = SIEM_RULES["event_id_map"]
    for removed_id in {"1", "3", "7", "8", "9", "10", "11", "13", "17", "18"}:
        assert removed_id not in event_map
    assert event_map["1100"]["alert_on_event"] is True
    assert event_map["7045"]["severity"] == "CRITICAL"

    assert event_map["5156"]["event_type"] == "network_connection_permitted"
    assert event_map["5156"]["alert_on_event"] is False
    assert event_map["5156"]["frameworks"] == []
    assert event_map["5157"]["event_type"] == "network_connection_blocked"
    for evidence_only in {"4624", "4625", "4672", "4688"}:
        assert event_map[evidence_only]["alert_on_event"] is False


def _load_windows_agent_with_stubs(monkeypatch, tmp_path):
    win32evtlog = types.ModuleType("win32evtlog")
    win32evtlogutil = types.ModuleType("win32evtlogutil")
    win32security = types.ModuleType("win32security")
    monkeypatch.setitem(sys.modules, "win32evtlog", win32evtlog)
    monkeypatch.setitem(sys.modules, "win32evtlogutil", win32evtlogutil)
    monkeypatch.setitem(sys.modules, "win32security", win32security)
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path))
    spec = importlib.util.spec_from_file_location(
        "warsoc_windows_agent_test",
        ROOT / "agent" / "windows_agent.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_enrolled_agent_id_wins_over_installer_bootstrap_placeholder(monkeypatch, tmp_path):
    agent = _load_windows_agent_with_stubs(monkeypatch, tmp_path)

    assert agent._select_agent_id("WARSOC_AGENT_REAL", "auto", "provision") == "WARSOC_AGENT_REAL"
    assert agent._select_agent_id("", "WARSOC_AGENT_CONFIGURED", "provision") == "WARSOC_AGENT_CONFIGURED"
    assert agent._select_agent_id("", "auto", "WARSOC_TENANT") == "WARSOC_TENANT"


def test_windows_dpapi_return_shapes_are_normalized(monkeypatch, tmp_path):
    agent = _load_windows_agent_with_stubs(monkeypatch, tmp_path)

    class NativePywin32Shape:
        @staticmethod
        def CryptProtectData(*_args):
            return b"protected"

        @staticmethod
        def CryptUnprotectData(*_args):
            return ("WarSOC Ed25519 Agent Key", b"plaintext")

    monkeypatch.setattr(agent, "win32crypt", NativePywin32Shape)
    assert agent._dpapi_protect(b"plaintext") == b"protected"
    assert agent._dpapi_unprotect(b"protected") == b"plaintext"

    class CompatibleTupleShape(NativePywin32Shape):
        @staticmethod
        def CryptProtectData(*_args):
            return ("WarSOC Ed25519 Agent Key", b"protected-tuple")

    monkeypatch.setattr(agent, "win32crypt", CompatibleTupleShape)
    assert agent._dpapi_protect(b"plaintext") == b"protected-tuple"


def test_native_xml_and_jsonl_parsers(monkeypatch, tmp_path):
    agent = _load_windows_agent_with_stubs(monkeypatch, tmp_path)
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/>
        <EventID>4625</EventID><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>
        <Keywords>0x8010000000000000</Keywords>
        <TimeCreated SystemTime="2026-06-27T10:00:00.0000000Z"/>
        <EventRecordID>1234</EventRecordID><Channel>Security</Channel>
        <Computer>POS-01</Computer><Security UserID="S-1-5-18"/>
      </System>
      <EventData>
        <Data Name="TargetUserName">admin</Data>
        <Data Name="IpAddress">203.0.113.10</Data>
        <Data Name="LogonType">10</Data>
      </EventData>
    </Event>"""
    parsed = agent.parse_windows_event_xml(xml)
    assert parsed["event_id"] == "4625"
    assert parsed["source_ip"] == "203.0.113.10"
    assert parsed["processed_data"]["target_user"] == "admin"
    assert parsed["event_uid"] == "Security:1234"

    with pytest.raises(ValueError, match="DTD or entity"):
        agent.parse_windows_event_xml(
            '<!DOCTYPE Event [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>'
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><EventID>4625</EventID></System><EventData>&xxe;</EventData></Event>'
        )
    with pytest.raises(ValueError, match="1 MiB"):
        agent.parse_windows_event_xml("<Event>" + ("x" * (1024 * 1024)) + "</Event>")

    def xml_event(event_id, channel, fields):
        data = "".join(
            f'<Data Name="{name}">{value}</Data>'
            for name, value in fields.items()
        )
        return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Security-Auditing"/>
            <EventID>{event_id}</EventID><Level>0</Level><Task>0</Task><Opcode>0</Opcode>
            <Keywords>0x0</Keywords>
            <TimeCreated SystemTime="2026-06-27T10:00:00Z"/>
            <EventRecordID>{event_id}</EventRecordID><Channel>{channel}</Channel>
            <Computer>POS-01</Computer><Security UserID="S-1-5-18"/>
          </System>
          <EventData>{data}</EventData>
        </Event>"""

    native_cases = [
        ("4688", "Security", {"NewProcessName": r"C:\Windows\cmd.exe", "CommandLine": "cmd /c whoami"}, "command_line"),
        ("4672", "Security", {"SubjectUserName": "admin", "PrivilegeList": "SeDebugPrivilege"}, "privilege_list"),
        ("4616", "Security", {"SubjectUserName": "admin", "PreviousTime": "old", "NewTime": "new", "ProcessName": r"C:\Windows\System32\svchost.exe"}, "new_time"),
        ("4648", "Security", {"SubjectUserName": "admin", "TargetUserName": "service-user", "TargetServerName": "POS-SERVER", "IpAddress": "10.0.0.8"}, "target_server"),
        ("4720", "Security", {"SubjectUserName": "admin", "TargetUserName": "new-user"}, "target_user"),
        ("4726", "Security", {"SubjectUserName": "admin", "TargetUserName": "old-user"}, "target_user"),
        ("4732", "Security", {"SubjectUserName": "admin", "TargetUserName": "Administrators", "MemberName": "new-user"}, "member_name"),
        ("4697", "Security", {"ServiceName": "BadSvc", "ServiceFileName": r"C:\Temp\bad.exe"}, "service_name"),
        ("4663", "Security", {"ObjectName": r"C:\POS\sales.mdf", "HandleId": "0x44", "AccessMask": "0x10000"}, "object_name"),
        ("4660", "Security", {"HandleId": "0x44", "ProcessName": r"C:\POS\pos.exe"}, "handle_id"),
        ("4670", "Security", {"ObjectName": r"C:\POS\sales.db", "OldSd": "OLD", "NewSd": "NEW"}, "new_security_descriptor"),
        ("7045", "System", {"ServiceName": "BadSvc", "ImagePath": r"C:\Temp\bad.exe"}, "service_name"),
        ("4768", "Security", {"TargetUserName": "alice", "IpAddress": "10.0.0.9", "Status": "0x0"}, "source_network_address"),
        ("4769", "Security", {"TargetUserName": "alice", "ServiceName": "cifs/POS-SERVER", "IpAddress": "10.0.0.9"}, "service_name"),
        ("4776", "Security", {"TargetUserName": "alice", "Workstation": "POS-02", "Status": "0xC000006A"}, "workstation"),
        ("5140", "Security", {"SubjectUserName": "alice", "IpAddress": "10.0.0.9", "ShareName": r"\\*\POS"}, "share_name"),
        ("5156", "Security", {"Application": r"C:\POS\pos.exe", "SourceAddress": "10.0.0.9", "DestAddress": "10.0.0.10", "DestPort": "443"}, "destination_address"),
        ("5157", "Security", {"Application": r"C:\Temp\unknown.exe", "SourceAddress": "10.0.0.9", "DestAddress": "10.0.0.10", "DestPort": "445"}, "destination_address"),
    ]
    for event_id, channel, fields, expected_field in native_cases:
        native = agent.parse_windows_event_xml(xml_event(event_id, channel, fields))
        assert native["event_id"] == event_id
        assert native["processed_data"][expected_field]
        assert native["raw_event_data"]["system"]["channel"] == channel
        assert "{" not in agent.build_windows_event_message(native)

    failed_login = agent.parse_windows_event_xml(
        xml_event(
            "4625",
            "Security",
            {"TargetUserName": "alice", "IpAddress": "203.0.113.8", "LogonType": "10", "Status": "0xC000006D"},
        )
    )
    failed_login_message = agent.build_windows_event_message(failed_login)
    assert failed_login["user"] == "alice"
    assert failed_login_message.startswith("Failed sign-in for alice from 203.0.113.8")
    assert "TargetUserName" not in failed_login_message

    line = json.dumps(
        {
            "event_id": "FBR-INV-DEL",
            "event_uid": "audit-event-123",
            "invoice_id": "INV-123",
            "timestamp": "2026-06-27T10:00:00Z",
            "actor": "manager",
            "source_system": "pos-a",
        }
    )
    assert agent.parse_pos_audit_line(line)["event_id"] == "FBR-INV-DEL"
    with pytest.raises(ValueError):
        agent.parse_pos_audit_line('{"event_id":"FIM-DB-MOD"}')


def test_native_spool_failure_cannot_advance_watermark(monkeypatch, tmp_path):
    agent = _load_windows_agent_with_stubs(monkeypatch, tmp_path)
    spooler = agent.DiskSpooler(tmp_path / "durable-spool")
    fsync_calls = []
    monkeypatch.setattr(agent.os, "fsync", lambda descriptor: fsync_calls.append(descriptor))

    assert spooler.append({"event_id": "4688", "event_uid": "Security:100"})
    assert fsync_calls
    assert spooler.pending_file.read_text(encoding="utf-8").strip()

    previous_watermark = 99

    def fail_enqueue(_payload):
        raise agent.SpoolWriteError("disk full")

    monkeypatch.setattr(agent, "enqueue_payload", fail_enqueue)
    with pytest.raises(agent.SpoolWriteError):
        agent._durably_enqueue_native_event(
            {"event_id": "4688"},
            100,
            previous_watermark,
        )
    assert previous_watermark == 99


def test_native_watermark_resets_when_windows_channel_is_cleared(monkeypatch, tmp_path):
    agent = _load_windows_agent_with_stubs(monkeypatch, tmp_path)

    assert agent._watermark_after_channel_probe(1469039, 1) == 0
    assert agent._watermark_after_channel_probe(1469039, 1469040) == 1469039
    assert agent._watermark_after_channel_probe(0, 0) == 0
    assert agent._latest_record_id_from_log_bounds(58493, 40251) == 98743
    assert agent._latest_record_id_from_log_bounds(0, 0) == 0


def test_agent_v2_signature_covers_native_channel_epoch_and_sequence(monkeypatch, tmp_path):
    agent = _load_windows_agent_with_stubs(monkeypatch, tmp_path)
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    event = {
        "event_id": "4688",
        "event_uid": "Security:9001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_collection_time": datetime.now(timezone.utc).isoformat(),
        "collection_protocol_version": agent.COLLECTION_PROTOCOL_VERSION,
        "source_channel": "Security",
        "source_channel_epoch": "epoch-security-001",
        "source_sequence": 9001,
        "source_ip": "192.0.2.10",
        "user": "Operator",
        "message": "process created",
        "event_type": "process_create",
        "processed_data": {},
        "raw_event_data": {},
        "agent_version": agent.AGENT_VERSION,
    }
    signed = agent._sign_event_for_delivery(event, private_key)

    verified = verify_event_signature(
        signed,
        agent_id=agent.AGENT_ID,
        public_key_pem=public_pem,
    )
    assert verified["signature_version"] == "ed25519-v2"
    assert verified["signature_verified"] is True

    signed["source_channel_epoch"] = "tampered-epoch"
    with pytest.raises(Exception, match="hash mismatch"):
        verify_event_signature(
            signed,
            agent_id=agent.AGENT_ID,
            public_key_pem=public_pem,
        )


def test_native_spool_hard_limit_blocks_without_deleting_unacknowledged_data(monkeypatch, tmp_path):
    agent = _load_windows_agent_with_stubs(monkeypatch, tmp_path)
    spooler = agent.DiskSpooler(
        tmp_path / "bounded-spool",
        max_bytes=180,
        resume_bytes=80,
        min_free_bytes=0,
    )
    first = {"event_id": "4688", "event_uid": "Security:100", "message": "x" * 60}
    second = {"event_id": "4688", "event_uid": "Security:101", "message": "y" * 60}

    assert spooler.append(first)
    original = spooler.pending_file.read_text(encoding="utf-8")
    with pytest.raises(agent.SpoolWriteError):
        spooler.append(second)

    assert spooler.pending_file.read_text(encoding="utf-8") == original
    status = spooler.status()
    assert status["blocked"] is True
    assert status["usage_bytes"] <= status["max_bytes"]


def test_historical_spool_replay_is_rate_limited_after_success(monkeypatch, tmp_path):
    agent = _load_windows_agent_with_stubs(monkeypatch, tmp_path)
    monkeypatch.setattr(agent, "REPLAY_AGE_SECONDS", 300.0)
    monkeypatch.setattr(agent, "REPLAY_MAX_EVENTS_PER_SECOND", 10.0)
    monkeypatch.setattr(agent, "OUTBOUND_BATCH_WAIT_SECONDS", 0.25)
    now = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)
    historical = [
        {"timestamp": "2026-08-04T11:00:00+00:00"}
        for _ in range(25)
    ]

    assert agent._successful_delivery_delay_seconds(historical, now=now) == 2.5


def test_current_telemetry_keeps_normal_sender_latency(monkeypatch, tmp_path):
    agent = _load_windows_agent_with_stubs(monkeypatch, tmp_path)
    monkeypatch.setattr(agent, "REPLAY_AGE_SECONDS", 300.0)
    monkeypatch.setattr(agent, "REPLAY_MAX_EVENTS_PER_SECOND", 10.0)
    monkeypatch.setattr(agent, "OUTBOUND_BATCH_WAIT_SECONDS", 0.25)
    now = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)
    current = [
        {"timestamp": "2026-08-04T11:59:30+00:00"}
        for _ in range(25)
    ]

    assert agent._successful_delivery_delay_seconds(current, now=now) == 0.25


def test_malformed_spool_lines_are_quarantined_before_processing_file_cleanup(monkeypatch, tmp_path):
    agent = _load_windows_agent_with_stubs(monkeypatch, tmp_path)
    spooler = agent.DiskSpooler(tmp_path / "durable-spool")
    processing_file = spooler.spool_dir / "processing_1.jsonl"
    processing_file.write_text(
        '{"event_id":"4688","event_uid":"Security:100"}\nnot-json\n',
        encoding="utf-8",
    )

    logs, filename = spooler.consume_batch()

    assert filename == str(processing_file)
    assert logs == [{"event_id": "4688", "event_uid": "Security:100"}]
    quarantined = spooler.dead_letter_file.read_text(encoding="utf-8")
    assert "not-json" in quarantined
    assert "malformed_spool_json" in quarantined

def test_pos_quarantine_is_durable_and_fails_closed(monkeypatch, tmp_path):
    agent = _load_windows_agent_with_stubs(monkeypatch, tmp_path)
    fsync_calls = []
    monkeypatch.setattr(agent.os, "fsync", lambda descriptor: fsync_calls.append(descriptor))

    agent.quarantine_pos_audit_line("not-json", "invalid JSON", "pos_audit.log")

    assert fsync_calls
    quarantined = agent.POS_AUDIT_QUARANTINE_PATH.read_text(encoding="utf-8")
    assert "not-json" in quarantined
    assert "invalid JSON" in quarantined

    def fail_fsync(_descriptor):
        raise OSError("disk full")

    monkeypatch.setattr(agent.os, "fsync", fail_fsync)
    with pytest.raises(agent.SpoolWriteError):
        agent.quarantine_pos_audit_line("still-bad", "invalid JSON", "pos_audit.log")


def test_shipped_runtime_contains_no_sysmon_references():
    paths = [ROOT / "installer.iss", ROOT / "build_agent.bat"]
    for runtime_root in (ROOT / "agent", ROOT / "app", ROOT / "deploy"):
        for path in runtime_root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".py", ".json", ".ps1", ".iss"}:
                continue
            if any(part.lower() in {"build", "dist", "spool", "__pycache__"} for part in path.parts):
                continue
            paths.append(path)
    combined = "\n".join(path.read_text(encoding="utf-8") for path in paths).lower()
    assert "sysmon" not in combined


def test_installer_configures_native_telemetry_before_nssm_run_entries():
    installer = (ROOT / "installer.iss").read_text(encoding="utf-8")
    agent_source = (ROOT / "agent" / "windows_agent.py").read_text(encoding="utf-8")
    assert "AfterInstall: ConfigureTelemetryAndAgent" in installer
    assert "procedure ConfigureTelemetryAndAgent;" in installer
    assert "Native Windows telemetry configuration failed" in installer
    assert installer.index("AfterInstall: ConfigureTelemetryAndAgent") < installer.index("[Run]")
    assert '"{app}\\config.json"' not in installer
    assert "/inheritance:r" in installer
    assert "JWT_TOKEN_PATH = PROGRAM_DATA_DIR" in agent_source
    assert "PRIVATE_KEY_PATH = PROGRAM_DATA_DIR" in agent_source
    assert 'DiskSpooler(PROGRAM_DATA_DIR / "spool")' in agent_source
    assert 'Path(_AGENT_DIR) / "spool"' not in agent_source
    assert "_consume_activation_secret()" in agent_source
    assert "while not JWT_TOKEN:" in agent_source
    assert "retry_delay = min(retry_delay * 2, 60)" in agent_source

    telemetry = (ROOT / "agent" / "deploy_warsoc_telemetry.ps1").read_text(encoding="utf-8")
    assert "added_rights" in telemetry
    assert "Set-AuditSddl" not in telemetry

    build_script = (ROOT / "build_agent.bat").read_text(encoding="utf-8")
    assert "--console" in build_script
    assert "--noconsole" not in build_script


def test_agent_does_not_monitor_its_own_service_logs(monkeypatch, tmp_path):
    agent = _load_windows_agent_with_stubs(monkeypatch, tmp_path)
    agent_dir = tmp_path / "WarSOC"
    own_logs = agent_dir / "logs"
    own_logs.mkdir(parents=True)
    own_log = own_logs / "warsoc_agent.out.log"
    own_log.write_text("[FAIL] Agent enrollment failed\n", encoding="utf-8")

    app_log = agent_dir / "access.log"
    app_log.write_text("GET /index.html 200\n", encoding="utf-8")

    monkeypatch.setattr(agent, "_AGENT_DIR", agent_dir)
    monkeypatch.setattr(agent, "WEB_LOG_PATHS", [str(own_logs / "*.log"), str(app_log)])

    resolved = {Path(path).resolve() for path in agent.resolve_web_log_files()}
    assert app_log.resolve() in resolved
    assert own_log.resolve() not in resolved

    policy = json.loads((ROOT / "agent" / "tenant_policy.json").read_text(encoding="utf-8"))
    assert "logs/*.log" not in policy["monitoring"]["web_log_paths"]

    deploy_policy = json.loads((ROOT / "deploy" / "tenant_policy.json").read_text(encoding="utf-8"))
    assert "logs/*.log" not in deploy_policy["monitoring"]["web_log_paths"]

    runtime_config = json.loads((ROOT / "app" / "config" / "config.json").read_text(encoding="utf-8"))
    assert "logs/*.log" not in runtime_config["monitoring"]["web_log_paths"]

    sync_source = (ROOT / "app" / "utils" / "sync_ssot.py").read_text(encoding="utf-8")
    assert '"logs/*.log"' not in sync_source

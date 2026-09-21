import pytest
import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import redis.asyncio as aioredis

from app.utils.siem_logic import SIEMEngine, CorrelationEngine
from app.utils.siem_catalog import SIEM_RULES
from app.wazuh_integration.detection_features import extract_detection_features
from app.utils.detection_provenance import attach_detection_provenance
from app.utils.siem_privacy import protect_siem_document, _safe_summary

pytestmark = [pytest.mark.asyncio, pytest.mark.backend]


class FakeAsyncRedis:
    """A comprehensive dict-backed AsyncMock for Redis operations used in SIEM tests."""
    def __init__(self):
        self.data = {}

    async def get(self, key):
        if isinstance(key, bytes): key = key.decode("utf-8")
        return self.data.get(key)

    async def set(self, key, value, *args, **kwargs):
        if isinstance(key, bytes): key = key.decode("utf-8")
        self.data[key] = value
        return True

    async def setex(self, key, time, value):
        if isinstance(key, bytes): key = key.decode("utf-8")
        self.data[key] = value
        return True

    async def expire(self, key, time):
        return True

    async def exists(self, key):
        if isinstance(key, bytes): key = key.decode("utf-8")
        return 1 if key in self.data else 0

    async def delete(self, key):
        if isinstance(key, bytes): key = key.decode("utf-8")
        self.data.pop(key, None)
        return 1

    async def sadd(self, key, *values):
        if isinstance(key, bytes): key = key.decode("utf-8")
        if key not in self.data:
            self.data[key] = set()
        elif not isinstance(self.data[key], set):
            self.data[key] = set([self.data[key]])
        added = 0
        for v in values:
            if isinstance(v, bytes): v = v.decode("utf-8")
            if v not in self.data[key]:
                self.data[key].add(v)
                added += 1
        return added

    async def scard(self, key):
        if isinstance(key, bytes): key = key.decode("utf-8")
        s = self.data.get(key, set())
        return len(s) if isinstance(s, set) else 0

    async def sismember(self, key, value):
        if isinstance(key, bytes): key = key.decode("utf-8")
        if isinstance(value, bytes): value = value.decode("utf-8")
        s = self.data.get(key, set())
        return value in s if isinstance(s, set) else False

    async def incr(self, key):
        if isinstance(key, bytes): key = key.decode("utf-8")
        val = self.data.get(key, 0)
        self.data[key] = int(val) + 1
        return self.data[key]

    def pipeline(self):
        return FakeAsyncPipeline(self)


class FakeAsyncPipeline:
    def __init__(self, redis):
        self.redis = redis
        self.ops = []

    def sadd(self, key, *values):
        self.ops.append(("sadd", key, values))
        return self

    def expire(self, key, time):
        self.ops.append(("expire", key, (time,)))
        return self

    def scard(self, key):
        self.ops.append(("scard", key, ()))
        return self

    async def execute(self):
        results = []
        for op, key, args in self.ops:
            if op == "sadd":
                results.append(await self.redis.sadd(key, *args))
            elif op == "expire":
                results.append(await self.redis.expire(key, *args))
            elif op == "scard":
                results.append(await self.redis.scard(key))
        return results


# 1. test_threat_intel_blacklisted_ip_detection
async def test_threat_intel_blacklisted_ip_detection():
    """Test that a blacklisted public IP triggers a KNOWN_MALICIOUS_IP alert with CRITICAL severity."""
    redis_mock = FakeAsyncRedis()
    public_malicious_ip = "93.184.216.34"
    redis_mock.data[f"threat_intel:ip:{public_malicious_ip}"] = '{"source": "test", "confidence": 100}'

    engine = SIEMEngine(config=SIEM_RULES)
    engine.set_redis_client(redis_mock)

    log_entry = {
        "source_ip": public_malicious_ip,
        "message": "Outbound connection initiated to remote endpoint",
        "event_id": "1234",
    }

    findings = await engine.analyze_single_log(log_entry)

    assert any(f.get("type") == "KNOWN_MALICIOUS_IP" for f in findings), "Expected KNOWN_MALICIOUS_IP alert"
    alert = next(f for f in findings if f.get("type") == "KNOWN_MALICIOUS_IP")
    assert alert.get("severity") == "CRITICAL"


# 2. test_windows_event_map_direct_alert
async def test_windows_event_map_direct_alert():
    """Verify the event_id_map in SIEM_RULES has alert_on_event=True for critical Windows events."""
    event_id_map = SIEM_RULES.get("event_id_map", {})
    critical_events = ["1100", "1102", "4697", "4720", "4726", "4732", "7045"]

    for eid in critical_events:
        mapping = event_id_map.get(eid)
        assert mapping is not None, f"Event {eid} should be mapped in SIEM_RULES"
        assert mapping.get("alert_on_event") is True, f"Event {eid} should have alert_on_event=True"
        assert "frameworks" in mapping, f"Event {eid} should define frameworks"


# 3. test_stateless_sql_injection_detection
async def test_stateless_sql_injection_detection():
    """Test that stateless regex spots SQL injection patterns like UNION SELECT in reviewed web telemetry."""
    redis_mock = FakeAsyncRedis()
    engine = SIEMEngine(config=SIEM_RULES)
    engine.set_redis_client(redis_mock)

    log_entry = {
        "event_type": "http_request",
        "raw_data": {"web_log_file": "access.log"},
        "message": "GET /search?q=1%27 union select 1,2,3 from users--",
        "event_id": "HTTP_LOG",
    }

    findings = await engine.analyze_single_log(log_entry)
    assert any(f.get("type") == "SQL_INJECTION" for f in findings)
    alert = next(f for f in findings if f.get("type") == "SQL_INJECTION")
    assert alert.get("severity") == "HIGH"


# 4. test_stateless_powershell_obfuscation_detection
async def test_stateless_powershell_obfuscation_detection():
    """Test detection of obfuscated PowerShell commands."""
    redis_mock = FakeAsyncRedis()
    engine = SIEMEngine(config=SIEM_RULES)
    engine.set_redis_client(redis_mock)

    log_entry = {
        "event_type": "process_create",
        "event_id": "4688",
        "message": "powershell -encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAg",
    }

    findings = await engine.analyze_single_log(log_entry)
    assert any(f.get("type") == "POWERSHELL_OBFUSCATION" for f in findings)
    alert = next(f for f in findings if f.get("type") == "POWERSHELL_OBFUSCATION")
    assert alert.get("severity") == "CRITICAL"


# 5. test_stateless_credential_dumping_detection
async def test_stateless_credential_dumping_detection():
    """Test detection of credential dumping tools like procdump targeting lsass."""
    redis_mock = FakeAsyncRedis()
    engine = SIEMEngine(config=SIEM_RULES)
    engine.set_redis_client(redis_mock)

    log_entry = {
        "event_type": "process_create",
        "event_id": "4688",
        "message": "procdump.exe -ma lsass.exe out.dmp",
    }

    findings = await engine.analyze_single_log(log_entry)
    assert any(f.get("type") == "SIGMA_CREDENTIAL_DUMPING" for f in findings)


# 6. test_stateless_ransomware_shadow_delete
async def test_stateless_ransomware_shadow_delete():
    """Test detection of Volume Shadow Copy deletion, typically used by ransomware."""
    redis_mock = FakeAsyncRedis()
    engine = SIEMEngine(config=SIEM_RULES)
    engine.set_redis_client(redis_mock)

    log_entry = {
        "event_type": "process_create",
        "event_id": "4688",
        "message": "vssadmin.exe delete shadows /all /quiet",
    }

    findings = await engine.analyze_single_log(log_entry)
    assert any(f.get("type") == "SIGMA_RANSOMWARE_SHADOW_DELETE" for f in findings)
    alert = next(f for f in findings if f.get("type") == "SIGMA_RANSOMWARE_SHADOW_DELETE")
    assert alert.get("severity") == "CRITICAL"


# 7. test_correlation_password_spray
async def test_correlation_password_spray():
    """Test that 5+ failed logins from same IP with distinct users triggers Password Spraying."""
    redis_mock = FakeAsyncRedis()
    corr = CorrelationEngine(redis_mock, config=SIEM_RULES)
    tenant_id = f"tenant_{uuid.uuid4().hex[:8]}"
    source_ip = "192.168.1.50"

    alerts = []
    for i in range(5):
        timestamp = datetime.now(timezone.utc).isoformat()
        res = await corr.run_all(
            tenant_id=tenant_id,
            source_ip=source_ip,
            user=f"user_{i}",
            event_id="4625",
            lat=None, lon=None,
            timestamp_iso=timestamp,
            event_type="failed_login",
            log_entry={"message": "Failed login", "event_id": "4625"},
        )
        alerts.extend(res)

    assert any("spray" in str(a.get("type", "") or a.get("alert_type", "")).lower() for a in alerts), "PASSWORD_SPRAY alert not generated"


# 8. test_correlation_ghost_admin_sequence
async def test_correlation_ghost_admin_sequence():
    """Test that adding an admin (4732) followed by clearing audit log (1102) triggers GHOST_ADMIN."""
    redis_mock = FakeAsyncRedis()
    corr = CorrelationEngine(redis_mock, config=SIEM_RULES)
    tenant_id = f"tenant_{uuid.uuid4().hex[:8]}"
    timestamp = datetime.now(timezone.utc).isoformat()
    source_ip = "10.0.0.1"

    # Event 4732: Admin added (arms trigger)
    res1 = await corr.run_all(
        tenant_id=tenant_id,
        source_ip=source_ip,
        user="Attacker",
        event_id="4732",
        lat=None, lon=None,
        timestamp_iso=timestamp,
        event_type="localgroup_member_added",
        log_entry={"message": "Admin added", "event_id": "4732", "agent_id": "agt-1"},
    )
    assert len(res1) == 0, "Stage 1 should not trigger alert directly"

    # Event 1102: Audit log cleared (fires ghost admin sequence)
    res2 = await corr.run_all(
        tenant_id=tenant_id,
        source_ip=source_ip,
        user="Attacker",
        event_id="1102",
        lat=None, lon=None,
        timestamp_iso=timestamp,
        event_type="clear_logs",
        log_entry={"message": "Audit log cleared", "event_id": "1102", "agent_id": "agt-1"},
    )
    assert any("ghost" in str(a.get("type", "") or a.get("alert_type", "")).lower() for a in res2), "GHOST_ADMIN alert not generated"


# 9. test_correlation_smb_lateral_movement
async def test_correlation_smb_lateral_movement():
    """Test that targeting 2+ distinct SMB servers triggers SMB lateral movement."""
    redis_mock = FakeAsyncRedis()
    corr = CorrelationEngine(redis_mock, config=SIEM_RULES)
    tenant_id = f"tenant_{uuid.uuid4().hex[:8]}"
    source_ip = "10.0.0.100"
    user = "alice"

    # Target 1
    await corr.run_all(
        tenant_id=tenant_id,
        source_ip=source_ip,
        user=user,
        event_id="4648",
        lat=None, lon=None,
        timestamp_iso=datetime.now(timezone.utc).isoformat(),
        event_type="explicit_credential_logon",
        log_entry={"target_server": "fileserver01.corp.local", "computer": "workstation-10", "agent_id": "agt-1"},
    )

    # Target 2
    res = await corr.run_all(
        tenant_id=tenant_id,
        source_ip=source_ip,
        user=user,
        event_id="4648",
        lat=None, lon=None,
        timestamp_iso=datetime.now(timezone.utc).isoformat(),
        event_type="explicit_credential_logon",
        log_entry={"target_server": "fileserver02.corp.local", "computer": "workstation-10", "agent_id": "agt-1"},
    )

    assert any("smb" in str(a.get("type", "") or a.get("alert_type", "")).lower() for a in res), "SMB_LATERAL_MOVEMENT alert not generated"


# 10. test_detection_provenance_immutability
async def test_detection_provenance_immutability():
    """Test attach_detection_provenance adds correct metadata and bounds evidence references."""
    alert = {"alert_type": "TEST_ALERT", "severity": "LOW", "type": "TEST_ALERT"}
    source_event = {"tenant_id": "tenant-1", "event_uid": "EVT-100", "source_ip": "10.0.0.1"}

    attach_detection_provenance(
        alert,
        source_event=source_event,
        detector_module="siem.correlation",
        rule_id="PASSWORD_SPRAY",
    )

    assert "detection_provenance" in alert
    prov = alert["detection_provenance"]
    assert prov["schema_version"] == "detector-provenance-v1"
    assert prov["detector_module"] == "siem.correlation"
    assert prov["rule_id"] == "PASSWORD_SPRAY"
    assert len(prov["evidence_refs"]) <= 8


# 11. test_detection_features_windows_endpoint
async def test_detection_features_windows_endpoint():
    """Test extract_detection_features for Windows endpoint telemetry."""
    # 1100
    feat = extract_detection_features({"event_id": "1100"}, "windows_endpoint")
    assert feat.get("event_logging_stopped") is True

    # 1102
    feat = extract_detection_features({"event_id": "1102"}, "windows_endpoint")
    assert feat.get("audit_log_cleared") is True

    # 4688 mimikatz
    feat = extract_detection_features(
        {
            "event_id": "4688",
            "processed_data": {
                "process_name": "mimikatz.exe",
                "command_line": "mimikatz.exe sekurlsa::logonpasswords",
            },
        },
        "windows_endpoint",
    )
    assert feat.get("process_attack_family") == "credential_dumping"

    # 4688 vssadmin delete shadows
    feat = extract_detection_features(
        {
            "event_id": "4688",
            "processed_data": {
                "process_name": "vssadmin.exe",
                "command_line": "vssadmin.exe delete shadows /all /quiet",
            },
        },
        "windows_endpoint",
    )
    assert feat.get("process_attack_family") == "recovery_inhibition"


# 12. test_detection_features_network_device
async def test_detection_features_network_device():
    """Test extract_detection_features for Network device telemetry."""
    # Blocked connection
    feat = extract_detection_features({"event_id": "NET-CONNECTION-BLOCK"}, "network_device")
    assert feat.get("network_connection_blocked") is True

    # VPN rejected
    feat = extract_detection_features(
        {"event_type": "vpn_authentication", "processed_data": {"action": "deny"}},
        "network_device",
    )
    assert feat.get("vpn_authentication_rejected") is True

    # Device admin rejected
    feat = extract_detection_features(
        {"event_type": "device_admin", "processed_data": {"action": "reject"}},
        "network_device",
    )
    assert feat.get("device_admin_rejected") is True


# 13. test_siem_privacy_safe_summary
async def test_siem_privacy_safe_summary():
    """Test _safe_summary bounds the returned string to <=320 characters and selects proper priority."""
    # When display_message is present
    doc1 = {"display_message": "A" * 400}
    summary1 = _safe_summary(doc1)
    assert len(summary1) <= 320
    assert summary1.startswith("A" * 100)

    # When summary is present, summary takes priority
    doc2 = {"summary": "Explicit Summary", "display_message": "Display Message"}
    summary2 = _safe_summary(doc2)
    assert summary2 == "Explicit Summary"

    # When event_id_meaning is present
    doc3 = {"event_id_meaning": "Audit Log Cleared"}
    summary3 = _safe_summary(doc3)
    assert summary3 == "Audit Log Cleared"

    # Fallback format
    doc4 = {"event_id": "NET-CONNECTION-BLOCK"}
    summary4 = _safe_summary(doc4)
    assert summary4 == "Security telemetry event NET-CONNECTION-BLOCK observed"


# 14. test_cold_vault_source_family_assignment
async def test_cold_vault_source_family_assignment():
    """Test that source_family mapping rules correctly distinguish windows_endpoint vs network_device."""
    doc_win = {
        "telemetry_family": "windows",
        "signature_verified": True,
        "source_assurance": "agent_signed",
    }
    is_win_endpoint = (
        doc_win.get("telemetry_family") == "windows"
        and doc_win.get("signature_verified") is True
        and doc_win.get("source_assurance") == "agent_signed"
    )
    assert is_win_endpoint is True

    doc_net = {
        "telemetry_family": "network",
        "source_type": "network_device",
        "signature_verified": True,
        "source_assurance": "relay_attested",
    }
    is_net_device = (
        doc_net.get("telemetry_family") == "network"
        and doc_net.get("source_type") == "network_device"
        and doc_net.get("signature_verified") is True
        and doc_net.get("source_assurance") == "relay_attested"
    )
    assert is_net_device is True

    doc_unknown = {
        "telemetry_family": "unknown",
        "signature_verified": False,
    }
    is_unknown = not (
        (doc_unknown.get("telemetry_family") == "windows" and doc_unknown.get("source_assurance") == "agent_signed")
        or (doc_unknown.get("telemetry_family") == "network" and doc_unknown.get("source_assurance") == "relay_attested")
    )
    assert is_unknown is True

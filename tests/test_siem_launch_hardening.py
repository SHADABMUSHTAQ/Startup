import pytest

from app.utils.siem_catalog import SIEM_RULES
from app.utils.siem_logic import SIEMEngine
from app.workers.siem_worker import (
    _extract_tenant_id_from_raw_payload,
    _is_whitelisted_source,
    _should_persist_alert_under_bouncer,
)


class FakeRedis:
    def __init__(self):
        self.store = {}
        self.members = {}

    async def get(self, key):
        return self.store.get(key)

    async def setex(self, key, seconds, value):
        self.store[key] = value
        return True

    async def exists(self, key):
        return 1 if key in self.store else 0

    async def sismember(self, key, value):
        return value in self.members.get(key, set())


@pytest.mark.asyncio
async def test_regex_cooldown_is_scoped_to_same_payload():
    config = {
        "detection": {
            "fp_controls": {
                "max_alerts_per_log": 5,
                "rule_cooldown_seconds": 60,
            },
            "rules": {
                "CUSTOM_ATTACK": {
                    "regex": "(?i)attack",
                    "sev": "HIGH",
                    "mitre": "T0000",
                    "min_message_length": 1,
                }
            },
        }
    }
    redis = FakeRedis()
    engine = SIEMEngine(config)
    engine.set_redis_client(redis)

    first = await engine.analyze_single_log(
        {"tenant_id": "TENANT-A", "source_ip": "10.0.0.9", "event_type": "command_line", "message": "attack probe"}
    )
    duplicate = await engine.analyze_single_log(
        {"tenant_id": "TENANT-A", "source_ip": "10.0.0.9", "event_type": "command_line", "message": "attack probe"}
    )
    changed_payload = await engine.analyze_single_log(
        {"tenant_id": "TENANT-A", "source_ip": "10.0.0.9", "event_type": "command_line", "message": "attack destructive payload"}
    )

    assert [finding["type"] for finding in first] == ["CUSTOM_ATTACK"]
    assert duplicate == []
    assert [finding["type"] for finding in changed_payload] == ["CUSTOM_ATTACK"]
    assert len(redis.store) == 2


def test_bouncer_only_suppresses_low_and_medium_alerts():
    assert _should_persist_alert_under_bouncer(False, "MEDIUM") is True
    assert _should_persist_alert_under_bouncer(True, "INFO") is False
    assert _should_persist_alert_under_bouncer(True, "MEDIUM") is False
    assert _should_persist_alert_under_bouncer(True, "HIGH") is True
    assert _should_persist_alert_under_bouncer(True, "CRITICAL") is True


@pytest.mark.asyncio
async def test_worker_whitelist_helper_checks_soar_and_static_lists():
    redis = FakeRedis()
    redis.members["warsoc:soar_whitelist:TENANT-A"] = {"10.0.0.8"}
    engine = SIEMEngine(
        {
            "whitelist": {
                "ips": ["10.0.0.10"],
                "service_accounts": ["svc_backup"],
            },
            "detection": {"rules": {}},
        }
    )

    assert await _is_whitelisted_source(redis, "TENANT-A", "10.0.0.8", "normal_user", engine) is True
    assert await _is_whitelisted_source(redis, "TENANT-A", "10.0.0.10", "normal_user", engine) is True
    assert await _is_whitelisted_source(redis, "TENANT-A", "10.0.0.11", "svc_backup", engine) is True
    assert await _is_whitelisted_source(redis, "TENANT-A", "10.0.0.11", "normal_user", engine) is False


def test_dlq_tenant_extraction_handles_malformed_payload():
    raw_payload = """{"tenant_id": "TENANT-A", "message": "mimikatz payload", broken"""
    assert _extract_tenant_id_from_raw_payload(raw_payload) == "TENANT-A"
    assert _extract_tenant_id_from_raw_payload("no tenant here") is None


@pytest.mark.asyncio
async def test_full_token_powershell_creates_a_precise_elevation_alert():
    engine = SIEMEngine(SIEM_RULES)
    findings = await engine.analyze_single_log(
        {
            "tenant_id": "TENANT-ELEVATION",
            "agent_id": "AGENT-1",
            "event_id": "4688",
            "event_type": "process_create",
            "source_ip": "192.168.1.10",
            "user": "alice",
            "message": r"Process started by alice: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "processed_data": {
                "new_process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "token_elevation_type": "%%1937",
            },
        }
    )

    alert = next(finding for finding in findings if finding["type"] == "WINDOWS_ELEVATED_POWERSHELL")
    assert alert["summary"] == "Elevated PowerShell launched"
    assert alert["severity"] == "MEDIUM"
    assert alert["mitre"] == "T1059.001"


@pytest.mark.asyncio
async def test_limited_token_powershell_is_evidence_not_an_elevation_alert():
    engine = SIEMEngine(SIEM_RULES)
    findings = await engine.analyze_single_log(
        {
            "tenant_id": "TENANT-ELEVATION",
            "agent_id": "AGENT-1",
            "event_id": "4688",
            "event_type": "process_create",
            "source_ip": "192.168.1.10",
            "user": "alice",
            "message": r"Process started by alice: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "processed_data": {
                "new_process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "token_elevation_type": "%%1938",
            },
        }
    )

    assert not any(finding["type"] == "WINDOWS_ELEVATED_POWERSHELL" for finding in findings)


@pytest.mark.asyncio
async def test_native_process_telemetry_cannot_be_labelled_as_phishing_by_itself():
    engine = SIEMEngine(SIEM_RULES)
    findings = await engine.analyze_single_log(
        {
            "tenant_id": "TENANT-PHISH",
            "agent_id": "AGENT-1",
            "event_id": "4688",
            "event_type": "process_create",
            "source_ip": "192.168.1.10",
            "user": "alice",
            "message": "powershell.exe Invoke-WebRequest https://example.test/tool.ps1",
        }
    )

    assert not any(finding["type"] == "PHISHING_PATTERN" for finding in findings)


@pytest.mark.asyncio
async def test_native_command_line_does_not_fire_web_command_injection_rule():
    engine = SIEMEngine(SIEM_RULES)
    findings = await engine.analyze_single_log(
        {
            "tenant_id": "TENANT-COMMAND",
            "agent_id": "AGENT-1",
            "event_id": "4688",
            "event_type": "command_line",
            "source_ip": "192.168.1.10",
            "user": "alice",
            "message": "input=ok; whoami",
        }
    )

    assert not any(finding["type"] == "COMMAND_INJECTION" for finding in findings)
    assert any(finding["type"] == "RECON_COMMANDS" for finding in findings)


@pytest.mark.asyncio
async def test_untrusted_http_label_cannot_activate_web_or_phishing_rules():
    engine = SIEMEngine(SIEM_RULES)
    findings = await engine.analyze_single_log(
        {
            "tenant_id": "TENANT-WEB",
            "agent_id": "AGENT-1",
            "event_type": "http_request",
            "source_ip": "192.168.1.10",
            "user": "alice",
            "message": "verify your account at http://198.51.100.5/?id=1' union select password from users --",
            "raw_data": {},
        }
    )

    assert not any(finding["type"] in {"SQL_INJECTION", "PHISHING_PATTERN"} for finding in findings)

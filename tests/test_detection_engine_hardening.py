from copy import deepcopy

import pytest

from app.utils.siem_catalog import SIEM_RULES
from app.utils.siem_logic import SIEMEngine
from app.utils.threat_intel import ThreatIntelligenceManager


class _ThreatIntelRedis:
    async def sismember(self, *_args, **_kwargs):
        return False

    async def exists(self, key):
        return key in {
            "threat_intel:ip:10.0.0.200",
            "threat_intel:ip:93.184.216.34",
        }

    async def get(self, *_args, **_kwargs):
        return None

    async def set(self, *_args, **_kwargs):
        return True


@pytest.mark.asyncio
async def test_private_or_trusted_threat_intel_indicators_do_not_alert():
    config = deepcopy(SIEM_RULES)
    config["threat_intelligence"]["ips"] = ["10.0.0.200"]
    engine = SIEMEngine(config)
    engine.set_redis_client(_ThreatIntelRedis())

    findings = await engine.analyze_single_log(
        {
            "tenant_id": "TENANT-A",
            "source_ip": "10.0.0.200",
            "user": "analyst",
            "event_type": "network",
            "message": "Outbound connection observed",
        }
    )

    assert "10.0.0.200" not in engine.blacklisted_ips
    assert not any(finding["type"] == "KNOWN_MALICIOUS_IP" for finding in findings)


@pytest.mark.asyncio
async def test_public_threat_intel_indicator_remains_actionable():
    config = deepcopy(SIEM_RULES)
    config["threat_intelligence"]["ips"] = ["93.184.216.34"]
    engine = SIEMEngine(config)
    engine.set_redis_client(_ThreatIntelRedis())

    findings = await engine.analyze_single_log(
        {
            "tenant_id": "TENANT-A",
            "source_ip": "93.184.216.34",
            "user": "analyst",
            "event_type": "network",
            "message": "Outbound connection observed",
        }
    )

    assert "93.184.216.34" in engine.blacklisted_ips
    assert any(finding["type"] == "KNOWN_MALICIOUS_IP" for finding in findings)


@pytest.mark.asyncio
async def test_shared_threat_intel_rejects_control_and_private_ips_unless_approved():
    manager = ThreatIntelligenceManager(
        {
            "threat_intelligence": {
                "ips": ["127.0.0.1", "10.0.0.8", "93.184.216.34"],
                "options": {
                    "ignore_private_ips": True,
                    "private_ip_allowlist": ["10.0.0.8"],
                },
            }
        }
    )

    assert await manager.check_reputation("127.0.0.1") == (
        False,
        "Non-actionable IP ignored",
    )
    assert (await manager.check_reputation("10.0.0.8"))[0] is True
    assert (await manager.check_reputation("10.0.0.9"))[0] is False
    assert (await manager.check_reputation("93.184.216.34"))[0] is True


@pytest.mark.asyncio
async def test_large_clock_change_is_detected_but_small_adjustment_is_not():
    engine = SIEMEngine()
    base = {
        "event_id": "4616",
        "event_type": "system_time_changed",
        "source_ip": "192.168.10.4",
        "user": "operator",
        "message": "System clock changed",
    }

    large = await engine.analyze_single_log(
        {
            **base,
            "processed_data": {
                "previous_time": "2026-09-07T10:00:00Z",
                "new_time": "2026-09-07T10:10:00Z",
            },
        }
    )
    small = await engine.analyze_single_log(
        {
            **base,
            "processed_data": {
                "previous_time": "2026-09-07T10:00:00Z",
                "new_time": "2026-09-07T10:00:30Z",
            },
        }
    )

    alert = next(finding for finding in large if finding["type"] == "WINDOWS_LARGE_CLOCK_CHANGE")
    assert alert["severity"] == "HIGH"
    assert alert["mitre"] == "T1070.006"
    assert not any(finding["type"] == "WINDOWS_LARGE_CLOCK_CHANGE" for finding in small)


@pytest.mark.asyncio
async def test_suspicious_scheduled_task_is_detected_without_flagging_normal_task():
    engine = SIEMEngine()
    base = {
        "event_id": "4698",
        "event_type": "scheduled_task_created",
        "source_ip": "192.168.10.4",
        "user": "operator",
        "message": "Scheduled task created",
    }

    suspicious = await engine.analyze_single_log(
        {
            **base,
            "processed_data": {
                "task_name": "Updater",
                "task_content": r"powershell.exe -EncodedCommand SQBFAFgA",
            },
        }
    )
    normal = await engine.analyze_single_log(
        {
            **base,
            "processed_data": {
                "task_name": r"\Microsoft\Windows\Defrag\ScheduledDefrag",
                "task_content": r"C:\Windows\System32\defrag.exe -c -h -o",
            },
        }
    )

    alert = next(finding for finding in suspicious if finding["type"] == "WINDOWS_SUSPICIOUS_SCHEDULED_TASK")
    assert alert["severity"] == "CRITICAL"
    assert alert["mitre"] == "T1053.005"
    assert not any(finding["type"] == "WINDOWS_SUSPICIOUS_SCHEDULED_TASK" for finding in normal)


@pytest.mark.asyncio
async def test_task_xml_metadata_is_not_an_execution_indicator():
    engine = SIEMEngine()
    template = '''<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <RegistrationInfo><Description>PowerShell -EncodedCommand usage guide</Description></RegistrationInfo>
      <Actions><Exec><Command>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Command>
      <Arguments>{arguments}</Arguments></Exec></Actions></Task>'''
    base = {"event_id": "4698", "message": "Scheduled task created", "user": "operator"}
    normal = await engine.analyze_single_log({
        **base, "processed_data": {"task_content": template.format(arguments="-File C:\\Ops\\backup.ps1")}
    })
    suspicious = await engine.analyze_single_log({
        **base, "processed_data": {"task_content": template.format(arguments="-EncodedCommand VwBhAHIAUwBPAEMA")}
    })
    assert not any(row["type"] == "WINDOWS_SUSPICIOUS_SCHEDULED_TASK" for row in normal)
    assert any(row["type"] == "WINDOWS_SUSPICIOUS_SCHEDULED_TASK" for row in suspicious)


@pytest.mark.asyncio
@pytest.mark.parametrize("task_content", ["<Task>", '<!DOCTYPE Task [<!ENTITY x "text">]><Task>&x;</Task>'])
async def test_invalid_task_xml_does_not_crash_detection(task_content):
    findings = await SIEMEngine().analyze_single_log({
        "event_id": "4698", "message": "Scheduled task created",
        "processed_data": {"task_content": task_content},
    })
    assert not any(row["type"] == "WINDOWS_SUSPICIOUS_SCHEDULED_TASK" for row in findings)

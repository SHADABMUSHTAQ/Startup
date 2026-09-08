"""Bounded, privacy-preserving features for the governed Wazuh projection.

The extractor deliberately emits booleans, bounded numbers, and one attack
family label. Raw command lines, registry paths, task XML, identities, and IP
addresses remain in WarSOC's canonical evidence store.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any


MAX_COMMAND_TEXT = 16_384
MAX_TASK_XML = 262_144
MAX_CLOCK_DELTA_SECONDS = 31_536_000


def _text(value: Any, *, limit: int = MAX_COMMAND_TEXT) -> str:
    return str(value or "").strip()[:limit]


def _lower(value: Any, *, limit: int = MAX_COMMAND_TEXT) -> str:
    return _text(value, limit=limit).lower()


def _basename(value: Any) -> str:
    return _lower(value).replace("/", "\\").rsplit("\\", 1)[-1]


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, (str, datetime)):
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except (AttributeError, ValueError):
            return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _contains_all(value: str, *markers: str) -> bool:
    return all(marker in value for marker in markers)


def _contains_any(value: str, markers: tuple[str, ...]) -> bool:
    return any(marker in value for marker in markers)


def _process_attack_family(process_name: Any, command_line: Any) -> str | None:
    process = _basename(process_name)
    command = _lower(command_line)
    if not process and not command:
        return None
    powershell = process in {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}

    if (
        (re.fullmatch(r"procdump(?:64)?\.exe", process) and "lsass" in command)
        or (
            process == "rundll32.exe"
            and _contains_all(command, "comsvcs", "minidump")
        )
        or (powershell and "sekurlsa::logonpasswords" in command)
        or process in {"mimikatz", "mimikatz.exe"}
    ):
        return "credential_dumping"

    if powershell and _contains_any(
        command,
        (
            "invoke-reflectivepeinjection",
            "invoke-dllinjection",
            "createremotethread",
            "ntcreatethreadex",
            "virtualallocex",
            "writeprocessmemory",
        ),
    ):
        return "process_injection"

    if (
        (process == "vssadmin.exe" and _contains_all(command, "delete", "shadows"))
        or (process == "wmic.exe" and _contains_all(command, "shadowcopy", "delete"))
        or (process == "wbadmin.exe" and _contains_all(command, "delete", "catalog"))
        or (
            process == "bcdedit.exe"
            and (
                _contains_all(command, "recoveryenabled", "no")
                or _contains_all(command, "bootstatuspolicy", "ignoreallfailures")
            )
        )
    ):
        return "recovery_inhibition"

    if (
        (
            powershell
            and bool(
                re.search(
                    r"\bset-mppreference\b[^\r\n]{0,240}"
                    r"-disablerealtimemonitoring\s+(?:\$?true|1)\b",
                    command,
                )
            )
        )
        or (powershell and _contains_all(command, "add-mppreference", "-exclusionpath"))
        or (
            process in {"sc.exe", "net.exe"}
            and re.search(r"\b(?:stop|config)\s+windefend\b", command)
        )
    ):
        return "defense_impairment"

    if (
        (
            powershell
            and _contains_all(command, "system.net.sockets.tcpclient", "getstream")
        )
        or (
            powershell
            and _contains_all(
                command, "new-object", "net.sockets.tcpclient", "invoke-expression"
            )
        )
        or (
            process in {"nc", "nc.exe", "ncat", "ncat.exe"}
            and re.search(r"(?:^|\s)-e\s+(?:cmd|powershell)(?:\.exe)?\b", command)
        )
        or (
            powershell
            and "powercat" in command
            and " -c " in command
            and (" -e " in command or "-ep" in command)
        )
    ):
        return "reverse_shell"

    if powershell and (
        re.search(
            r"(?i)(?:^|\s)-(?:e|enc|encodedcommand)\s+[a-z0-9+/=]{16,}",
            command,
        )
        or "frombase64string" in command
        or (
            re.search(r"(?i)-(?:w|windowstyle)\s+hidden\b", command)
            and _contains_any(
                command,
                (
                    "downloadstring",
                    "invoke-webrequest",
                    "invoke-expression",
                    "http://",
                    "https://",
                ),
            )
        )
    ):
        return "powershell_obfuscation"

    if (
        (
            process == "wmic.exe"
            and _contains_all(command, "/node:", "process", "call", "create")
        )
        or (process == "winrs.exe" and re.search(r"(?:^|\s)-r:", command))
        or (powershell and _contains_all(command, "enter-pssession", "-computername"))
        or (powershell and _contains_all(command, "invoke-command", "-computername"))
        or (process in {"psexec.exe", "psexec64.exe"} and "\\\\" in command)
        or (
            process == "net.exe"
            and re.search(r"(?:^|\s)use\s+\\\\", command)
            and re.search(r"\\(?:admin\$|c\$)(?:\s|$)", command)
        )
    ):
        return "lateral_movement"

    if (
        (
            process == "net.exe"
            and re.search(
                r"(?:^|\s)localgroup\s+administrators\b[^\r\n]{0,240}/add\b",
                command,
            )
        )
        or (
            powershell
            and _contains_all(command, "add-localgroupmember", "administrators")
        )
    ):
        return "privileged_group_change"

    if (
        (
            process == "certutil.exe"
            and "-urlcache" in command
            and _contains_any(command, ("http://", "https://", "-split", " -f "))
        )
        or (
            process == "bitsadmin.exe"
            and "/transfer" in command
            and _contains_any(command, ("http://", "https://"))
        )
        or (
            process in {"mshta.exe", "mshta"}
            and _contains_any(command, ("http://", "https://", "javascript:"))
        )
        or (
            process == "regsvr32.exe"
            and "/i:http" in command
            and "scrobj" in command
        )
        or (
            process == "rundll32.exe"
            and _contains_all(command, "javascript:", "mshtml")
        )
    ):
        return "lolbin_transfer_or_execution"

    if process in {
        "rubeus.exe",
        "sharphound.exe",
        "lazagne.exe",
        "bloodhound.exe",
        "seatbelt.exe",
        "meterpreter.exe",
    }:
        return "known_attack_tool_execution"

    return None


def _scheduled_task_action(task_content: Any) -> str:
    content = _text(task_content, limit=MAX_TASK_XML)
    if not content:
        return ""
    if not content.startswith("<"):
        return content
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", content, re.IGNORECASE):
        return ""
    try:
        root = ET.fromstring(content)  # nosec B314 - DTD/entity input is rejected above.
    except ET.ParseError:
        return ""
    actions: list[str] = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "Actions":
            continue
        for action in element:
            if action.tag.rsplit("}", 1)[-1] != "Exec":
                continue
            actions.extend(
                _text(field.text, limit=4096)
                for field in action
                if field.tag.rsplit("}", 1)[-1]
                in {"Command", "Arguments", "WorkingDirectory"}
            )
    return " ".join(actions)[:MAX_COMMAND_TEXT]


def _suspicious_service(image_path: Any) -> bool:
    image = _lower(image_path)
    if not image:
        return False
    interpreter = _contains_any(
        image,
        ("powershell", "pwsh", "cmd.exe /c", "wscript", "cscript", "mshta", "rundll32", "regsvr32"),
    )
    risky_location = _contains_any(
        image,
        ("\\appdata\\", "\\temp\\", "\\users\\public\\", "%temp%", "\\downloads\\"),
    )
    remote_or_obfuscated = _contains_any(
        image,
        ("http://", "https://", " -enc ", "-encodedcommand", "javascript:", "\\\\"),
    )
    return risky_location or remote_or_obfuscated or interpreter


def _registry_persistence(processed: dict[str, Any]) -> bool:
    path = _lower(processed.get("object_name"))
    value_name = _lower(processed.get("object_value_name"), limit=512)
    combined = f"{path}\\{value_name}"
    return _contains_any(
        combined,
        (
            "\\software\\microsoft\\windows\\currentversion\\run\\",
            "\\software\\microsoft\\windows\\currentversion\\runonce\\",
            "\\software\\microsoft\\windows nt\\currentversion\\winlogon\\shell",
            "\\software\\microsoft\\windows nt\\currentversion\\winlogon\\userinit",
            "\\image file execution options\\",
            "\\windows\\appinit_dlls",
            "\\startupapproved\\",
        ),
    )


def _privileged_group(value: Any) -> bool:
    group = _lower(value, limit=512).strip("{} ")
    short_name = group.rsplit("\\", 1)[-1]
    return (
        short_name in {"administrators", "remote desktop users", "backup operators"}
        or group.endswith("-544")
        or group.endswith("-551")
        or group.endswith("-555")
    )


def _authentication_failure(event_id: str, processed: dict[str, Any]) -> bool:
    if event_id == "4625":
        return True
    if event_id not in {"4768", "4769", "4776"}:
        return False
    status = _lower(processed.get("status"), limit=128)
    return bool(status and status not in {"0", "0x0", "success", "successful"})


def extract_detection_features(
    document: dict[str, Any], source_family: str
) -> dict[str, str | int | bool]:
    """Return only reviewed, bounded values suitable for Wazuh JSON rules."""

    event_id = _text(document.get("event_id"), limit=128)
    event_type = _lower(document.get("event_type"), limit=128)
    processed = document.get("processed_data")
    if not isinstance(processed, dict):
        processed = {}
    features: dict[str, str | int | bool] = {}

    if source_family == "windows_endpoint":
        if event_id == "1100":
            features["event_logging_stopped"] = True
        elif event_id == "1102":
            features["audit_log_cleared"] = True
        elif event_id == "4616":
            previous = _parse_utc(processed.get("previous_time"))
            current = _parse_utc(processed.get("new_time"))
            if previous and current:
                delta = min(
                    MAX_CLOCK_DELTA_SECONDS,
                    int(abs((current - previous).total_seconds())),
                )
                if delta >= 300:
                    features["large_clock_change"] = True
                    features["clock_change_seconds"] = delta
        elif event_id == "4719":
            changes = _lower(processed.get("audit_policy_changes"), limit=2048)
            if _contains_any(
                changes,
                ("%%8448", "%%8450", "success removed", "failure removed"),
            ):
                features["audit_policy_weakened"] = True
        elif event_id == "4732" and _privileged_group(processed.get("group_name")):
            features["privileged_group_membership"] = True
        elif event_id == "4657" and _registry_persistence(processed):
            features["registry_persistence"] = True
        elif event_id in {"4697", "7045"} and _suspicious_service(
            processed.get("image_path")
        ):
            features["suspicious_service_install"] = True
        elif event_id == "4698":
            action = _scheduled_task_action(processed.get("task_content"))
            family = _process_attack_family("", action)
            lowered_action = _lower(action)
            interpreter = _contains_any(
                lowered_action,
                (
                    "powershell",
                    "pwsh",
                    "cmd.exe",
                    "wscript",
                    "cscript",
                    "mshta",
                    "rundll32",
                    "regsvr32",
                ),
            )
            delivery = _contains_any(
                lowered_action,
                ("http://", "https://", "\\appdata\\", "\\temp\\", "javascript:"),
            )
            encoded = bool(
                re.search(
                    r"(?:^|\s)-(?:e|enc|encodedcommand)\s+[a-z0-9+/=]{16,}",
                    lowered_action,
                )
            ) or "frombase64string" in lowered_action
            if family or (interpreter and (delivery or encoded)):
                features["suspicious_scheduled_task"] = True
        elif event_id == "4688":
            family = _process_attack_family(
                processed.get("new_process_name") or processed.get("process_name"),
                processed.get("command_line"),
            )
            if family:
                features["process_attack_family"] = family

        if _authentication_failure(event_id, processed):
            features["authentication_failure"] = True

    elif source_family == "network_device":
        action = _lower(processed.get("action") or processed.get("outcome"), limit=128)
        if event_id == "NET-CONNECTION-BLOCK" or event_type == "network_connection_blocked":
            features["network_connection_blocked"] = True
        if event_type == "vpn_authentication" and action in {
            "deny",
            "denied",
            "fail",
            "failed",
            "reject",
            "rejected",
            "error",
        }:
            features["vpn_authentication_rejected"] = True
        if event_type == "device_admin" and action in {
            "deny",
            "denied",
            "fail",
            "failed",
            "reject",
            "rejected",
            "error",
        }:
            features["device_admin_rejected"] = True

    return features

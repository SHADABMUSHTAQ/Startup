from __future__ import annotations

import csv
import ipaddress
import re
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


_PRI_PREFIX = re.compile(r"^<(?P<pri>\d{1,3})>")
_RFC5424 = re.compile(
    r"^(?P<version>\d+)\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+"
    r"(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<structured>(?:-|\[.*?\]))(?:\s+(?P<message>.*))?$"
)
_RFC3164 = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+(?P<message>.*)$"
)
_KEY_VALUE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*=")
_CISCO_ID = re.compile(r"%ASA-(?P<severity>[0-7])-(?P<message_id>\d{6}):\s*(?P<body>.*)")
_CISCO_DENY = re.compile(
    r"Deny\s+(?P<protocol>\w+)\s+src\s+[^:]+:(?P<src_ip>[0-9a-fA-F:.]+)/(?P<src_port>\d+)\s+"
    r"dst\s+[^:]+:(?P<dst_ip>[0-9a-fA-F:.]+)/(?P<dst_port>\d+)",
    re.IGNORECASE,
)
_CISCO_BUILT = re.compile(
    r"Built\s+\w+\s+(?P<protocol>\w+)\s+connection.*?for\s+[^:]+:"
    r"(?P<src_ip>[0-9a-fA-F:.]+)/(?P<src_port>\d+).*?to\s+[^:]+:"
    r"(?P<dst_ip>[0-9a-fA-F:.]+)/(?P<dst_port>\d+)",
    re.IGNORECASE,
)
_MIKROTIK_FLOW = re.compile(
    r"proto\s+(?P<protocol>[A-Za-z0-9]+).*?"
    r"(?P<src_ip>[0-9a-fA-F:.]+):(?P<src_port>\d+)->"
    r"(?P<dst_ip>[0-9a-fA-F:.]+):(?P<dst_port>\d+)",
    re.IGNORECASE,
)
_PFSENSE_FILTERLOG = re.compile(r"(?:^|\s)filterlog(?:\[\d+\])?:\s*(?P<data>.*)$", re.IGNORECASE)
_PFSENSE_BSD_NO_HOST = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"filterlog(?:\[\d+\])?:\s*(?P<data>.*)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ParsedNetworkEvent:
    vendor: str
    device_event_time: datetime | None
    normalized: dict[str, Any]


class NetworkParseError(ValueError):
    """The source log cannot be represented by the strict relay contract."""


def _clean_ip(value: Any) -> str | None:
    candidate = str(value or "").strip().strip("[]")
    if not candidate:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _port(value: Any) -> int | None:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if 0 <= parsed <= 65535 else None


def _integer(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _parse_iso_timestamp(value: str) -> datetime | None:
    candidate = str(value or "").strip()
    if not candidate or candidate == "-":
        return None
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _strip_syslog_envelope(raw_message: str) -> tuple[str, dict[str, Any], datetime | None]:
    message = raw_message.strip("\x00\r\n ")
    if not message:
        raise NetworkParseError("empty syslog message")
    envelope: dict[str, Any] = {}
    priority_match = _PRI_PREFIX.match(message)
    if priority_match:
        priority = int(priority_match.group("pri"))
        if priority > 191:
            raise NetworkParseError("invalid syslog priority")
        envelope["syslog_facility"] = priority // 8
        envelope["syslog_severity"] = priority % 8
        message = message[priority_match.end() :]

    rfc5424 = _RFC5424.match(message)
    if rfc5424:
        fields = rfc5424.groupdict()
        envelope.update(
            {
                "hostname": fields["hostname"] if fields["hostname"] != "-" else None,
                "app_name": fields["app"] if fields["app"] != "-" else None,
                "message_id": fields["msgid"] if fields["msgid"] != "-" else None,
            }
        )
        return fields.get("message") or "", envelope, _parse_iso_timestamp(fields["timestamp"])

    rfc3164 = _RFC3164.match(message)
    if rfc3164:
        fields = rfc3164.groupdict()
        envelope["hostname"] = fields["hostname"]
        # RFC 3164 has no year or timezone. Preserve it only in the raw record;
        # relay receipt time remains authoritative for cross-source correlation.
        return fields["message"], envelope, None
    return message, envelope, None


def _parse_key_values(message: str) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        tokens = shlex.split(message, posix=True)
    except ValueError as exc:
        raise NetworkParseError("malformed quoted key/value log") from exc
    for token in tokens:
        if not _KEY_VALUE.match(token):
            continue
        key, value = token.split("=", 1)
        values[key.lower()] = value
    return values


def _with_common_fields(normalized: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
    result = {key: value for key, value in normalized.items() if value is not None and value != ""}
    if envelope.get("hostname") and "hostname" not in result:
        result["hostname"] = str(envelope["hostname"])[:255]
    if envelope.get("message_id") and "message_id" not in result:
        result["message_id"] = str(envelope["message_id"])[:100]
    if envelope.get("syslog_severity") is not None and "severity" not in result:
        result["severity"] = int(envelope["syslog_severity"])
    return result


def parse_fortinet(raw_message: str) -> ParsedNetworkEvent:
    message, envelope, envelope_time = _strip_syslog_envelope(raw_message)
    values = _parse_key_values(message)
    if not values or not ({"type", "subtype", "srcip", "dstip"} & set(values)):
        raise NetworkParseError("not a Fortinet key/value event")

    device_action = str(values.get("action") or "").lower()
    device_status = str(values.get("status") or "").lower()
    action = device_action or device_status
    log_type = str(values.get("type") or "").lower()
    subtype = str(values.get("subtype") or "").lower()
    if "vpn" in {log_type, subtype}:
        event_type = "vpn_authentication" if any(
            marker in f"{device_action} {device_status}"
            for marker in ("login", "auth", "success", "fail", "reject")
        ) else "vpn_session"
        outcome = f"{device_action} {device_status}"
        if any(marker in outcome for marker in ("fail", "reject", "deny", "error")):
            action = "rejected"
        elif any(marker in outcome for marker in ("success", "accept", "allow")):
            action = "successful"
    elif action in {"deny", "denied", "block", "blocked", "drop", "dropped", "reject", "rejected"}:
        event_type = "network_connection_blocked"
    elif action in {"accept", "accepted", "allow", "allowed", "pass", "passed", "start", "close"}:
        event_type = "network_connection_permitted"
    else:
        event_type = "network_observation"

    device_time = envelope_time
    eventtime = str(values.get("eventtime") or "")
    if eventtime.isdigit():
        epoch = int(eventtime)
        if epoch > 10**15:
            epoch /= 1_000_000_000
        elif epoch > 10**12:
            epoch /= 1000
        try:
            device_time = datetime.fromtimestamp(epoch, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            pass

    normalized = _with_common_fields(
        {
            "event_type": event_type,
            "action": action or None,
            "src_ip": _clean_ip(values.get("srcip") or values.get("remip")),
            "dst_ip": _clean_ip(values.get("dstip") or values.get("locip")),
            "src_port": _port(values.get("srcport")),
            "dst_port": _port(values.get("dstport")),
            "protocol": values.get("proto") or values.get("service"),
            "user": values.get("user") or values.get("xauthuser"),
            "bytes_sent": _integer(values.get("sentbyte")),
            "bytes_received": _integer(values.get("rcvdbyte")),
            "policy_id": values.get("policyid"),
            "session_id": values.get("sessionid"),
            "interface_in": values.get("srcintf"),
            "interface_out": values.get("dstintf"),
            "vpn_tunnel": values.get("tunnelid") or values.get("tunneltype"),
            "hostname": values.get("devname") or values.get("hostname"),
            "severity": values.get("level"),
            "message": (
                f"Fortinet {event_type.replace('_', ' ')} "
                f"{action or 'observed'}"
            )[:1000],
        },
        envelope,
    )
    return ParsedNetworkEvent("fortinet", device_time, normalized)


def parse_cisco_asa(raw_message: str) -> ParsedNetworkEvent:
    message, envelope, device_time = _strip_syslog_envelope(raw_message)
    matched = _CISCO_ID.search(message)
    if not matched:
        raise NetworkParseError("not a Cisco ASA event")
    body = matched.group("body")
    message_id = matched.group("message_id")
    normalized: dict[str, Any] = {
        "event_type": "network_observation",
        "severity": int(matched.group("severity")),
        "message_id": message_id,
        "message": f"Cisco ASA event {message_id} observed",
    }
    denied = _CISCO_DENY.search(body)
    built = _CISCO_BUILT.search(body)
    if denied:
        normalized.update(denied.groupdict())
        normalized["event_type"] = "network_connection_blocked"
        normalized["action"] = "deny"
    elif built:
        normalized.update(built.groupdict())
        normalized["event_type"] = "network_connection_permitted"
        normalized["action"] = "built"
    elif message_id in {"113004", "113012"}:
        normalized["event_type"] = "vpn_authentication"
        normalized["action"] = "successful"
        user_match = re.search(r"\buser\s*=\s*<?([^,:>\s]+)>?", body, re.IGNORECASE)
        if user_match:
            normalized["user"] = user_match.group(1)
    elif message_id in {"113005", "113015", "113016", "113017", "716039"}:
        normalized["event_type"] = "vpn_authentication"
        normalized["action"] = "rejected"
        user_match = re.search(r"\buser\s*=\s*<?([^,:>\s]+)>?", body, re.IGNORECASE)
        if not user_match:
            user_match = re.search(r"\bUser\s+<([^>]+)>", body)
        if user_match:
            normalized["user"] = user_match.group(1)
    elif message_id == "113039":
        normalized["event_type"] = "vpn_session"
        normalized["action"] = "started"
        user_match = re.search(r"\bUser\s+<?([^,>\s]+)", body)
        if user_match:
            normalized["user"] = user_match.group(1)

    remote_ip_match = re.search(
        r"\buser\s+IP\s*=\s*<?([0-9a-fA-F:.]+)>?",
        body,
        re.IGNORECASE,
    )
    if not remote_ip_match:
        remote_ip_match = re.search(r"\bIP\s+<([0-9a-fA-F:.]+)>", body)
    if remote_ip_match:
        normalized["src_ip"] = remote_ip_match.group(1)

    normalized["message"] = (
        f"Cisco ASA {normalized['event_type'].replace('_', ' ')} "
        f"event {message_id}"
    )[:1000]

    for key in ("src_port", "dst_port"):
        if key in normalized:
            normalized[key] = _port(normalized[key])
    for key in ("src_ip", "dst_ip"):
        if key in normalized:
            normalized[key] = _clean_ip(normalized[key])
    return ParsedNetworkEvent("cisco_asa", device_time, _with_common_fields(normalized, envelope))


def parse_mikrotik(raw_message: str) -> ParsedNetworkEvent:
    message, envelope, device_time = _strip_syslog_envelope(raw_message)
    lower = message.lower()
    if any(marker in lower for marker in (",packet", ",raw", " packet:", " raw:")):
        raise NetworkParseError("MikroTik packet/raw content is outside relay metadata scope")
    if "firewall" not in lower and "->" not in message:
        raise NetworkParseError("not a MikroTik firewall event")
    event_type = "network_observation"
    action = None
    if any(marker in lower for marker in (" drop", "drop:", "blocked", "reject")):
        event_type = "network_connection_blocked"
        action = "drop"
    flow = _MIKROTIK_FLOW.search(message)
    normalized: dict[str, Any] = {
        "event_type": event_type,
        "action": action,
        "message": f"MikroTik firewall {action or 'observation'}",
    }
    if flow:
        normalized.update(flow.groupdict())
        normalized["src_ip"] = _clean_ip(normalized.get("src_ip"))
        normalized["dst_ip"] = _clean_ip(normalized.get("dst_ip"))
        normalized["src_port"] = _port(normalized.get("src_port"))
        normalized["dst_port"] = _port(normalized.get("dst_port"))
    return ParsedNetworkEvent("mikrotik", device_time, _with_common_fields(normalized, envelope))


def _csv_integer(fields: list[str], index: int) -> int | None:
    return _integer(fields[index]) if index < len(fields) else None


def _csv_text(fields: list[str], index: int) -> str | None:
    if index >= len(fields):
        return None
    value = fields[index].strip()
    return value or None


def parse_pfsense(raw_message: str) -> ParsedNetworkEvent:
    """Parse the documented pfSense ``filterlog`` CSV metadata contract.

    Other pfSense programs (OpenVPN, IPsec, Unbound, DHCP, and system logs)
    intentionally fail this parser. They require separate message contracts and
    must never be guessed from free-form text.
    """

    # pfSense's default BSD remote-syslog format intentionally omits the
    # hostname: ``<PRI>Mon DD HH:MM:SS filterlog[pid]: CSV``. Handle that
    # documented appliance-specific envelope before generic RFC 3164 parsing,
    # which would otherwise mistake ``filterlog[pid]:`` for the hostname.
    no_host = _PFSENSE_BSD_NO_HOST.match(raw_message.strip("\x00\r\n "))
    if no_host:
        priority_text = no_host.group("pri")
        envelope = {"app_name": "filterlog"}
        if priority_text is not None:
            priority = int(priority_text)
            if priority > 191:
                raise NetworkParseError("invalid syslog priority")
            envelope["syslog_facility"] = priority // 8
            envelope["syslog_severity"] = priority % 8
        csv_data = no_host.group("data")
        # BSD syslog has no year or timezone, so relay receipt time remains
        # authoritative rather than guessing a device timestamp.
        device_time = None
    else:
        message, envelope, device_time = _strip_syslog_envelope(raw_message)
        matched = _PFSENSE_FILTERLOG.search(message)
        if matched:
            csv_data = matched.group("data")
        elif str(envelope.get("app_name") or "").lower() == "filterlog":
            csv_data = message
        else:
            raise NetworkParseError("not a pfSense filterlog event")
    try:
        rows = list(csv.reader([csv_data], strict=True))
    except csv.Error as exc:
        raise NetworkParseError("malformed pfSense filterlog CSV") from exc
    if len(rows) != 1:
        raise NetworkParseError("malformed pfSense filterlog record")
    fields = rows[0]
    if len(fields) < 9:
        raise NetworkParseError("truncated pfSense filterlog common fields")

    action = fields[6].strip().lower()
    direction = fields[7].strip().lower()
    ip_version = fields[8].strip()
    if action not in {"pass", "block"}:
        event_type = "network_observation"
    elif action == "pass":
        event_type = "network_connection_permitted"
    else:
        event_type = "network_connection_blocked"
    if direction not in {"in", "out"}:
        direction = "unknown"

    if ip_version == "4":
        if len(fields) < 20:
            raise NetworkParseError("truncated pfSense IPv4 filterlog event")
        protocol = _csv_text(fields, 16)
        protocol_id = _csv_integer(fields, 15)
        packet_length = _csv_integer(fields, 17)
        src_ip = _clean_ip(_csv_text(fields, 18))
        dst_ip = _clean_ip(_csv_text(fields, 19))
        protocol_start = 20
    elif ip_version == "6":
        if len(fields) < 17:
            raise NetworkParseError("truncated pfSense IPv6 filterlog event")
        protocol = _csv_text(fields, 12)
        protocol_id = _csv_integer(fields, 13)
        packet_length = _csv_integer(fields, 14)
        src_ip = _clean_ip(_csv_text(fields, 15))
        dst_ip = _clean_ip(_csv_text(fields, 16))
        protocol_start = 17
    else:
        raise NetworkParseError("unsupported pfSense filterlog IP version")
    if src_ip is None or dst_ip is None:
        raise NetworkParseError("pfSense filterlog contains an invalid IP address")

    protocol_name = str(protocol or "").lower()
    src_port = dst_port = data_length = None
    tcp_flags = icmp_type = None
    if protocol_name in {"tcp", "udp"} or protocol_id in {6, 17}:
        if len(fields) < protocol_start + 3:
            raise NetworkParseError("truncated pfSense TCP/UDP filterlog event")
        src_port = _port(_csv_text(fields, protocol_start))
        dst_port = _port(_csv_text(fields, protocol_start + 1))
        data_length = _csv_integer(fields, protocol_start + 2)
        if src_port is None or dst_port is None:
            raise NetworkParseError("pfSense filterlog contains an invalid port")
        if protocol_name == "tcp" or protocol_id == 6:
            tcp_flags = _csv_text(fields, protocol_start + 3)
    elif protocol_name in {"icmp", "icmp6", "ipv6-icmp"} or protocol_id in {1, 58}:
        icmp_type = _csv_text(fields, protocol_start)

    normalized = _with_common_fields(
        {
            "event_type": event_type,
            "action": action,
            "direction": direction,
            "ip_version": int(ip_version),
            "rule_id": _csv_text(fields, 0),
            "tracker_id": _csv_text(fields, 3),
            "interface_in": _csv_text(fields, 4) if direction == "in" else None,
            "interface_out": _csv_text(fields, 4) if direction == "out" else None,
            "reason": _csv_text(fields, 5),
            "protocol": protocol or (str(protocol_id) if protocol_id is not None else None),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_length": packet_length,
            "data_length": data_length,
            "tcp_flags": tcp_flags,
            "icmp_type": icmp_type,
            "message": f"pfSense firewall {action or 'observation'} {direction}",
        },
        envelope,
    )
    return ParsedNetworkEvent("pfsense", device_time, normalized)


def parse_network_message(vendor: str, raw_message: str) -> ParsedNetworkEvent:
    parser = {
        "fortinet": parse_fortinet,
        "cisco_asa": parse_cisco_asa,
        "mikrotik": parse_mikrotik,
        "pfsense": parse_pfsense,
    }.get(str(vendor or "").strip().lower())
    if parser is None and str(vendor or "").strip().lower() == "generic":
        message, envelope, device_time = _strip_syslog_envelope(raw_message)
        return ParsedNetworkEvent(
            "generic",
            device_time,
            _with_common_fields(
                {"event_type": "network_observation", "message": message[:1000]},
                envelope,
            ),
        )
    if parser is None:
        raise NetworkParseError("unsupported network-device vendor")
    return parser(raw_message)

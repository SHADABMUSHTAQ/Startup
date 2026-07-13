"""Operator-safe alert presentation and incident aggregation helpers.

Raw SIEM and compliance evidence remains immutable and event-granular. These
helpers only shape the operational alert view so repeated observations appear
as one incident with an occurrence count.
"""

from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from datetime import datetime, timezone
from typing import Iterable

from app.utils.siem_catalog import SIEM_RULES


_SEVERITY_RANK = {
    "INFO": 0,
    "INFORMATIONAL": 0,
    "LOW": 1,
    "WARNING": 2,
    "MEDIUM": 2,
    "HIGH": 3,
    "ALERT": 3,
    "CRITICAL": 4,
}

_GENERIC_ALERT_PATTERNS = (
    re.compile(r"^WIN_EVENT_\d+_DETECTED$", re.IGNORECASE),
    re.compile(r"^EVENT_ID_\d+_", re.IGNORECASE),
    re.compile(r".*_KEYWORD_MATCH$", re.IGNORECASE),
)


def _text(value, default: str = "") -> str:
    return str(value if value is not None else default).strip()


def _normalized(value) -> str:
    return " ".join(_text(value).lower().split())


def _parse_timestamp(value) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            parsed = datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _event_metadata(event_id) -> dict:
    return SIEM_RULES.get("event_id_map", {}).get(_text(event_id), {}) or {}


def _operator_severity(value) -> str:
    severity = _text(value or "MEDIUM").upper()
    aliases = {
        "INFO": "LOW",
        "INFORMATIONAL": "LOW",
        "WARNING": "MEDIUM",
        "ALERT": "HIGH",
    }
    normalized = aliases.get(severity, severity)
    return normalized if normalized in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "MEDIUM"


def _event_family(alert: dict) -> str:
    alert_type = _text(alert.get("type") or alert.get("rule_id") or alert.get("matched_rule_id"))
    metadata = _event_metadata(alert.get("event_id"))
    event_type = _text(metadata.get("event_type"))
    is_generic = not alert_type or any(pattern.match(alert_type) for pattern in _GENERIC_ALERT_PATTERNS)
    if is_generic and event_type:
        return f"event:{event_type.lower()}"
    return f"rule:{_normalized(alert_type or event_type or alert.get('event_id') or 'security_event')}"


def _is_generic_interpretation(alert: dict) -> bool:
    alert_type = _text(alert.get("type"))
    return bool(alert_type and any(pattern.match(alert_type) for pattern in _GENERIC_ALERT_PATTERNS))


def _processed(alert: dict) -> dict:
    value = alert.get("processed_data")
    return value if isinstance(value, dict) else {}


def _incident_target(alert: dict) -> str:
    processed = _processed(alert)
    for key in (
        "target_fingerprint",
        "service_name",
        "object_name",
        "file_path",
        "registry_key",
        "task_name",
        "share_name",
        "target_server",
        "target_user",
        "member_name",
        "destination_address",
        "new_process_name",
    ):
        value = alert.get(key) or processed.get(key)
        if value:
            return _normalized(value)
    return ""


def build_incident_key(alert: dict) -> str:
    """Build a tenant-local identity for repeated instances of one incident."""
    status = _text(alert.get("status") or "NEW").upper()
    pack = _normalized(alert.get("pack") or alert.get("compliance_pack") or "siem")
    source = _normalized(alert.get("source_ip") or alert.get("ip") or "unknown")
    asset = _normalized(alert.get("agent_id") or alert.get("computer") or "unknown")
    user = _normalized(alert.get("user") or _processed(alert).get("user") or "unknown")
    identity = "|".join(
        (pack, status, _event_family(alert), source, asset, user, _incident_target(alert))
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


def operator_message(alert: dict) -> str:
    """Return concise operator text while keeping raw evidence out of list views."""
    explicit = _text(alert.get("display_message") or alert.get("operator_message"))
    if explicit:
        return explicit[:320]

    summary = _text(alert.get("summary"))
    raw_message = _text(alert.get("message"))
    event_meaning = _text(alert.get("event_id_meaning"))

    if summary and summary.lower() not in {"unknown event", "security event"}:
        return summary[:320]

    if raw_message.lower().startswith("windows event ") and ": {" in raw_message:
        label = event_meaning or f"Windows event {_text(alert.get('event_id') or 'unknown')}"
        asset = _text(alert.get("computer") or alert.get("agent_id"))
        return f"{label}{f' on {asset}' if asset else ''}"[:320]

    return (raw_message or event_meaning or "Security event detected")[:320]


def _alert_reference(alert: dict) -> str | None:
    value = alert.get("_id") or alert.get("alert_id")
    return _text(value) or None


def _prefer_alert(current: dict, candidate: dict) -> dict:
    current_rank = _SEVERITY_RANK.get(_text(current.get("severity")).upper(), 2)
    candidate_rank = _SEVERITY_RANK.get(_text(candidate.get("severity")).upper(), 2)
    if candidate_rank > current_rank:
        return candidate
    if candidate_rank == current_rank and _parse_timestamp(candidate.get("timestamp")) > _parse_timestamp(current.get("timestamp")):
        return candidate
    return current


def _remove_redundant_interpretations(alerts: list[dict]) -> list[dict]:
    """Drop coarse interpretations only when the same event has a specific finding."""
    by_event_uid: dict[str, list[dict]] = {}
    without_uid: list[dict] = []
    for alert in alerts:
        event_uid = _text(alert.get("event_uid"))
        if event_uid:
            by_event_uid.setdefault(event_uid, []).append(alert)
        else:
            without_uid.append(alert)

    selected = list(without_uid)
    for event_alerts in by_event_uid.values():
        specific = [alert for alert in event_alerts if not _is_generic_interpretation(alert)]
        if specific:
            redundant_ids = [
                reference
                for alert in event_alerts
                if _is_generic_interpretation(alert)
                for reference in [_alert_reference(alert)]
                if reference
            ]
            for alert in specific:
                alert["_redundant_alert_ids"] = redundant_ids
            selected.extend(specific)
        else:
            selected.extend(event_alerts)
    return selected


def aggregate_security_alerts(alerts: Iterable[dict]) -> list[dict]:
    """Aggregate operational alerts without modifying event-level evidence."""
    copied = [deepcopy(alert) for alert in alerts]
    copied.sort(
        key=lambda alert: _parse_timestamp(alert.get("timestamp") or alert.get("ingested_at")),
        reverse=True,
    )
    copied = _remove_redundant_interpretations(copied)

    grouped: dict[str, dict] = {}
    occurrence_tokens: dict[str, set[str]] = {}
    occurrence_weights: dict[str, dict[str, int]] = {}

    for index, alert in enumerate(copied):
        incident_key = build_incident_key(alert)
        event_uid = _text(alert.get("event_uid"))
        occurrence_token = event_uid or f"document:{_alert_reference(alert) or index}"
        try:
            weight = max(1, int(alert.get("occurrences") or 1))
        except (TypeError, ValueError):
            weight = 1

        reference = _alert_reference(alert)
        timestamp = alert.get("timestamp") or alert.get("ingested_at")
        if incident_key not in grouped:
            representative = deepcopy(alert)
            representative["incident_key"] = incident_key
            representative["severity"] = _operator_severity(representative.get("severity"))
            representative["message"] = operator_message(alert)
            representative["display_message"] = representative["message"]
            representative["first_seen"] = timestamp
            representative["last_seen"] = timestamp
            representative["occurrences"] = weight
            representative["related_alert_ids"] = list(
                dict.fromkeys(
                    ([reference] if reference else [])
                    + list(representative.pop("_redundant_alert_ids", []))
                )
            )
            representative["event_ids"] = [_text(alert.get("event_id"))] if alert.get("event_id") is not None else []
            grouped[incident_key] = representative
            occurrence_tokens[incident_key] = {occurrence_token}
            occurrence_weights[incident_key] = {occurrence_token: weight}
            continue

        current = grouped[incident_key]
        preferred = _prefer_alert(current, alert)
        if preferred is alert:
            preserved = {
                "incident_key": current["incident_key"],
                "first_seen": current["first_seen"],
                "last_seen": current["last_seen"],
                "occurrences": current["occurrences"],
                "related_alert_ids": current["related_alert_ids"],
                "event_ids": current["event_ids"],
            }
            current.clear()
            current.update(deepcopy(alert))
            current.update(preserved)
            current["severity"] = _operator_severity(current.get("severity"))
            current["message"] = operator_message(alert)
            current["display_message"] = current["message"]

        if occurrence_token not in occurrence_tokens[incident_key]:
            occurrence_tokens[incident_key].add(occurrence_token)
            occurrence_weights[incident_key][occurrence_token] = weight
        else:
            occurrence_weights[incident_key][occurrence_token] = max(
                occurrence_weights[incident_key][occurrence_token], weight
            )
        current["occurrences"] = sum(occurrence_weights[incident_key].values())

        if reference and reference not in current["related_alert_ids"]:
            current["related_alert_ids"].append(reference)
        for redundant_id in alert.pop("_redundant_alert_ids", []):
            if redundant_id not in current["related_alert_ids"]:
                current["related_alert_ids"].append(redundant_id)
        current.pop("_redundant_alert_ids", None)
        event_id = _text(alert.get("event_id"))
        if event_id and event_id not in current["event_ids"]:
            current["event_ids"].append(event_id)

        if _parse_timestamp(timestamp) < _parse_timestamp(current.get("first_seen")):
            current["first_seen"] = timestamp
        if _parse_timestamp(timestamp) > _parse_timestamp(current.get("last_seen")):
            current["last_seen"] = timestamp

    return sorted(
        grouped.values(),
        key=lambda alert: _parse_timestamp(alert.get("last_seen") or alert.get("timestamp")),
        reverse=True,
    )

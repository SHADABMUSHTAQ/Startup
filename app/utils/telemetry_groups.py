"""Bounded presentation grouping for repetitive endpoint telemetry."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from app.utils.alert_context import build_alert_context


def _text(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        except (TypeError, ValueError):
            parsed = datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _identity(event: Mapping[str, Any]) -> str:
    observed = _timestamp(event.get("timestamp") or event.get("ingested_at"))
    minute = observed.replace(second=0, microsecond=0).isoformat()
    context = build_alert_context(event)
    fields = (
        minute,
        _text(event.get("event_id")),
        _text(context.get("endpoint") or event.get("computer") or event.get("agent_id")),
        _text(context.get("actor") or context.get("user") or event.get("user")),
        _text(context.get("target_user") or context.get("target")),
        _text(context.get("process_name")),
        _text(context.get("parent_process")),
        _text(context.get("command_line")),
        _text(context.get("source_address") or event.get("source_ip")),
        _text(context.get("destination_address")),
        _text(context.get("destination_port")),
        _text(context.get("protected_object")),
        _text(event.get("event_id_meaning") or event.get("summary") or event.get("message")),
    )
    return hashlib.sha256("|".join(fields).encode("utf-8")).hexdigest()[:24]


def aggregate_endpoint_events(events: Iterable[Mapping[str, Any]]) -> list[dict]:
    """Group identical endpoint observations within one UTC minute.

    The source documents are never changed. Context differences keep events
    separate, preventing unrelated processes, users, or targets from merging.
    """
    ordered = sorted(
        (deepcopy(dict(event)) for event in events),
        key=lambda event: _timestamp(event.get("timestamp") or event.get("ingested_at")),
        reverse=True,
    )
    groups: dict[str, dict] = {}
    seen_occurrences: dict[str, set[str]] = {}
    for index, event in enumerate(ordered):
        group_key = _identity(event)
        observed = event.get("timestamp") or event.get("ingested_at")
        occurrence_uid = str(event.get("event_uid") or event.get("_id") or f"row:{index}")
        try:
            weight = max(1, int(event.get("occurrences") or 1))
        except (TypeError, ValueError):
            weight = 1

        if group_key not in groups:
            event["group_key"] = group_key
            event["record_type"] = "endpoint_event_group"
            event["first_seen"] = observed
            event["last_seen"] = observed
            event["occurrences"] = weight
            event["context"] = build_alert_context(event)
            event["event_uids"] = [event.get("event_uid")] if event.get("event_uid") else []
            groups[group_key] = event
            seen_occurrences[group_key] = {occurrence_uid}
            continue

        current = groups[group_key]
        if occurrence_uid in seen_occurrences[group_key]:
            continue
        seen_occurrences[group_key].add(occurrence_uid)
        current["occurrences"] += weight
        current["first_seen"] = min(
            (current.get("first_seen"), observed),
            key=_timestamp,
        )
        current["last_seen"] = max(
            (current.get("last_seen"), observed),
            key=_timestamp,
        )
        if event.get("event_uid") and len(current["event_uids"]) < 100:
            current["event_uids"].append(event["event_uid"])

    return sorted(
        groups.values(),
        key=lambda event: _timestamp(event.get("last_seen")),
        reverse=True,
    )

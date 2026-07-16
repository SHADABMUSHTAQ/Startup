"""Safe operator context for alert list and WebSocket responses."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from app.utils.alert_incidents import operator_message


_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|api[_-]?key|account[_-]?key|client[_-]?secret|secret|access[_-]?token|refresh[_-]?token|connection[_-]?string)\b\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s;,]+)"
)
_SECRET_ARGUMENT = re.compile(
    r"(?i)((?:--|/|-)(?:password|passwd|api[_-]?key|account[_-]?key|client[_-]?secret|secret|access[_-]?token|refresh[_-]?token)(?:\s+|:|=))(?:\"[^\"]*\"|'[^']*'|[^\s;,]+)"
)
_BEARER_TOKEN = re.compile(r"(?i)(authorization\s*:\s*bearer\s+)([^\s;,]+)")
_COMMAND_FROM_MESSAGE = re.compile(r"(?is)(?:^|;\s*)command\s*:\s*(.+)$")


def redact_sensitive_text(value: Any, *, limit: int = 600) -> str:
    text = " ".join(str(value or "").split())
    if not text:
        return ""
    text = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", text)
    text = _SECRET_ARGUMENT.sub(r"\1[REDACTED]", text)
    text = _BEARER_TOKEN.sub(r"\1[REDACTED]", text)
    return text[:limit]


def _mapping_layers(payloads: Iterable[Mapping[str, Any] | None]) -> list[Mapping[str, Any]]:
    layers: list[Mapping[str, Any]] = []
    queue = [payload for payload in payloads if isinstance(payload, Mapping)]
    seen: set[int] = set()
    while queue:
        current = queue.pop(0)
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        layers.append(current)
        if len(layers) >= 24:
            break
        for key in ("context", "processed_data", "raw_data", "raw_event_data", "event_data", "data"):
            nested = current.get(key)
            if isinstance(nested, Mapping):
                queue.append(nested)
    return layers


def _first(layers: list[Mapping[str, Any]], *field_names: str) -> Any:
    for layer in layers:
        for field_name in field_names:
            value = layer.get(field_name)
            if value not in (None, "", [], {}):
                return value
    return None


def _command_from_raw_message(raw_message: Any) -> str:
    match = _COMMAND_FROM_MESSAGE.search(str(raw_message or ""))
    return match.group(1).strip() if match else ""


def build_alert_context(alert: Mapping[str, Any], source_event: Mapping[str, Any] | None = None) -> dict:
    """Build bounded context without returning raw evidence objects."""
    layers = _mapping_layers((alert, source_event))
    command_line = _first(layers, "command_line", "process_command_line", "CommandLine")
    if not command_line:
        command_line = _command_from_raw_message(_first(layers, "raw_message"))

    context = {
        "rule_id": _first(layers, "rule_id", "matched_rule_id", "type"),
        "event_id": _first(layers, "event_id"),
        "event_uid": _first(layers, "event_uid"),
        "mitre": _first(layers, "mitre", "mitre_id"),
        "endpoint": _first(layers, "computer", "hostname", "agent_id"),
        "agent_id": _first(layers, "agent_id"),
        "user": _first(layers, "user", "target_user", "subject_user_name", "actor"),
        "process_name": _first(
            layers,
            "new_process_name",
            "process_name",
            "source_image",
            "image",
            "application",
            "Application",
            "NewProcessName",
        ),
        "parent_process": _first(
            layers,
            "parent_process_name",
            "parent_image",
            "creator_process_name",
            "CreatorProcessName",
        ),
        "command_line": redact_sensitive_text(command_line),
        "source_address": _first(layers, "source_network_address", "source_address", "source_ip"),
        "source_port": _first(layers, "source_port"),
        "destination_address": _first(layers, "destination_address", "dest_address"),
        "destination_port": _first(layers, "destination_port", "dest_port"),
        "target": _first(layers, "target", "object_name", "file_path", "registry_key"),
    }
    return {key: value for key, value in context.items() if value not in (None, "")}


def operator_alert_document(
    alert: Mapping[str, Any],
    source_event: Mapping[str, Any] | None = None,
) -> dict:
    """Return an alert safe for list/WebSocket presentation."""
    result = dict(alert)
    result["context"] = build_alert_context(result, source_event)
    result["message"] = operator_message(result)
    for field in (
        "raw_message",
        "raw_event_data",
        "raw_event",
        "raw_data",
        "processed_data",
        "_retention_ts",
        "_expire_at",
    ):
        result.pop(field, None)
    return result

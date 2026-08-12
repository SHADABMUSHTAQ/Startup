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
        for key in (
            "context",
            "processed_data",
            "raw_data",
            "raw_event_data",
            "event_data",
            "system",
            "data",
        ):
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


def _event_outcome(layers: list[Mapping[str, Any]]) -> Any:
    explicit = _first(layers, "outcome", "result")
    if explicit not in (None, ""):
        return explicit
    workflow_states = {"NEW", "ACKNOWLEDGED", "CLOSED", "FALSE_POSITIVE"}
    for layer in layers:
        value = layer.get("status")
        if value not in (None, "") and str(value).strip().upper() not in workflow_states:
            return value
    return None


def build_alert_context(alert: Mapping[str, Any], source_event: Mapping[str, Any] | None = None) -> dict:
    """Build bounded context without returning raw evidence objects."""
    layers = _mapping_layers((alert, source_event))
    command_line = _first(layers, "command_line", "process_command_line", "CommandLine")
    if not command_line:
        command_line = _command_from_raw_message(_first(layers, "raw_message"))

    actor = _first(
        layers,
        "actor",
        "subject_user_name",
        "SubjectUserName",
        "account_name",
        "user",
    )
    target_user = _first(
        layers,
        "target_user",
        "target_user_name",
        "TargetUserName",
        "member_name",
        "MemberName",
    )
    protected_object = _first(
        layers,
        "object_name",
        "ObjectName",
        "file_path",
        "registry_key",
        "service_name",
        "ServiceName",
        "task_name",
        "share_name",
        "target_fingerprint",
    )

    context = {
        "schema_version": "operator-context-v1",
        "rule_id": _first(layers, "rule_id", "matched_rule_id", "type"),
        "event_id": _first(layers, "event_id"),
        "event_uid": _first(layers, "event_uid"),
        "mitre": _first(layers, "mitre", "mitre_id"),
        "endpoint": _first(layers, "computer", "hostname", "agent_id"),
        "agent_id": _first(layers, "agent_id"),
        "actor": actor,
        "actor_sid": _first(layers, "subject_user_sid", "SubjectUserSid"),
        "actor_domain": _first(layers, "subject_domain_name", "SubjectDomainName"),
        "target_user": target_user,
        "target_sid": _first(layers, "target_user_sid", "TargetUserSid", "target_sid"),
        # Backward-compatible list-view field. New UI should prefer actor and
        # target_user so successful logons do not conflate both identities.
        "user": actor or target_user,
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
        "process_id": _first(layers, "process_id", "ProcessId", "new_process_id", "NewProcessId"),
        "parent_process": _first(
            layers,
            "parent_process_name",
            "parent_image",
            "creator_process_name",
            "CreatorProcessName",
        ),
        "parent_process_id": _first(
            layers,
            "parent_process_id",
            "creator_process_id",
            "CreatorProcessId",
        ),
        "command_line": redact_sensitive_text(command_line),
        "source_address": _first(layers, "source_network_address", "source_address", "source_ip"),
        "source_port": _first(layers, "source_port", "SourcePort"),
        "destination_address": _first(
            layers,
            "destination_address",
            "dest_address",
            "DestinationAddress",
        ),
        "destination_port": _first(layers, "destination_port", "dest_port", "DestinationPort"),
        "protocol": _first(layers, "protocol", "Protocol"),
        "direction": _first(layers, "direction", "Direction"),
        "application": _first(layers, "application", "Application"),
        "target": _first(layers, "target") or target_user or protected_object,
        "protected_object": protected_object,
        "outcome": _event_outcome(layers),
        "channel": _first(layers, "channel", "Channel"),
        "provider": _first(layers, "provider", "Provider", "provider_name"),
        "record_id": _first(layers, "event_record_id", "EventRecordID", "record_id"),
        "match_reason": _first(layers, "match_reason", "matched_rule_name", "summary"),
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

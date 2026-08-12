"""Bounded, queryable provenance for detector-generated findings."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


PROVENANCE_SCHEMA_VERSION = "detector-provenance-v1"
MAX_EVIDENCE_REFERENCES = 8

DETECTOR_VERSIONS = {
    "siem.native_event": "2026.08.02.1",
    "siem.stateless": "2026.08.02.1",
    "siem.correlation": "2026.08.02.1",
    "siem.dlq_guard": "2026.08.02.1",
    "fbr.evidence": "2026.08.02.1",
    "legacy.detection_worker": "2026.08.02.1",
}


def _text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _layers(*payloads: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    layers: list[Mapping[str, Any]] = []
    queue = [payload for payload in payloads if isinstance(payload, Mapping)]
    seen: set[int] = set()
    while queue:
        payload = queue.pop(0)
        marker = id(payload)
        if marker in seen:
            continue
        seen.add(marker)
        layers.append(payload)
        for field in ("context", "processed_data", "raw_event_data", "system"):
            nested = payload.get(field)
            if isinstance(nested, Mapping):
                queue.append(nested)
    return layers


def _first(layers: list[Mapping[str, Any]], *keys: str) -> Any:
    for layer in layers:
        for key in keys:
            value = layer.get(key)
            if value not in (None, ""):
                return value
    return None


def _telemetry_family(layers: list[Mapping[str, Any]]) -> str:
    event_id = _text(_first(layers, "event_id")).upper()
    channel = _text(_first(layers, "channel", "Channel")).lower()
    event_type = _text(_first(layers, "event_type", "source_type", "log_type")).lower()
    if event_id == "FIM-DB-MOD":
        return "windows_native"
    if event_id in {"FBR-INV-MOD", "FBR-INV-DEL"}:
        return "pos_jsonl"
    if channel in {"security", "system"} or event_id.isdigit():
        return "windows_native"
    if event_type in {"http_request", "web", "iis"}:
        return "web_http"
    if any(_first(layers, key) for key in ("relay_id", "network_device_id", "device_vendor")):
        return "network_syslog"
    return "unknown"


def _evidence_reference(layers: list[Mapping[str, Any]]) -> dict[str, str]:
    fields = {
        "event_uid": _first(layers, "event_uid"),
        "event_id": _first(layers, "event_id"),
        "agent_id": _first(layers, "agent_id"),
        "channel": _first(layers, "channel", "Channel"),
        "record_id": _first(layers, "event_record_id", "EventRecordID", "record_id"),
        "timestamp": _first(layers, "timestamp", "ingested_at", "created_at"),
    }
    return {
        key: _text(value)[:160]
        for key, value in fields.items()
        if value not in (None, "")
    }


def attach_detection_provenance(
    finding: dict[str, Any],
    source_event: Mapping[str, Any] | None = None,
    *,
    detector_module: str,
    rule_id: str | None = None,
    rule_version: str | None = None,
    telemetry_family: str | None = None,
) -> dict[str, Any]:
    """Attach internal detector identity without copying raw evidence."""
    layers = _layers(finding, source_event)
    internal_rule_id = _text(
        rule_id
        or finding.get("matched_rule_id")
        or finding.get("rule_id")
        or finding.get("type")
        or finding.get("event_id")
        or "security_event"
    )
    version = _text(rule_version or DETECTOR_VERSIONS.get(detector_module) or "unversioned")
    family = _text(telemetry_family or _telemetry_family(layers)) or "unknown"
    reference = _evidence_reference(layers)

    finding["rule_id"] = internal_rule_id
    finding["rule_version"] = version
    finding["detector_module"] = detector_module
    finding["required_telemetry_family"] = family
    finding["detection_provenance"] = {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "rule_id": internal_rule_id,
        "rule_version": version,
        "detector_module": detector_module,
        "required_telemetry_family": family,
        "evidence_refs": [reference][:MAX_EVIDENCE_REFERENCES] if reference else [],
    }
    return finding

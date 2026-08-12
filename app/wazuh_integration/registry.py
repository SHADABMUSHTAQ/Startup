"""Validation for the reviewed Wazuh rule and projection registry."""

from __future__ import annotations

import re
from typing import Any


RULE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
MITRE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
FIELD_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")
ALLOWED_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_CONTEXT_FIELDS = {"wazuh_timestamp", "wazuh_manager"}

# Raw identities, IP addresses, invoice/POS fields, payloads and free-form
# messages are deliberately absent. Correlation uses purpose-separated HMACs.
ALLOWED_INPUT_PATHS = {
    "windows_endpoint": {
        "event_type",
        "processed_data.provider",
        "processed_data.channel",
        "processed_data.logon_type",
        "processed_data.status",
        "processed_data.sub_status",
        "processed_data.source_port",
        "processed_data.new_process_name",
        "processed_data.new_process_id",
        "processed_data.parent_process_name",
        "processed_data.command_line",
        "processed_data.token_elevation_type",
        "processed_data.privilege_list",
        "processed_data.previous_time",
        "processed_data.new_time",
        "processed_data.process_name",
        "processed_data.object_type",
        "processed_data.handle_id",
        "processed_data.process_id",
        "processed_data.access_mask",
        "processed_data.access_list",
        "processed_data.operation_type",
        "processed_data.service_name",
        "processed_data.image_path",
        "processed_data.service_type",
        "processed_data.start_type",
        "processed_data.task_name",
        "processed_data.category_id",
        "processed_data.subcategory_id",
        "processed_data.audit_policy_changes",
        "processed_data.caller_process_name",
        "processed_data.caller_process_id",
        "processed_data.ticket_options",
        "processed_data.pre_auth_type",
        "processed_data.authentication_package",
        "processed_data.application",
        "processed_data.destination_port",
        "processed_data.protocol",
    },
    "network_device": {
        "event_type",
        "processed_data.action",
        "processed_data.src_port",
        "processed_data.dst_port",
        "processed_data.protocol",
        "processed_data.direction",
        "processed_data.outcome",
        "processed_data.data_length",
        "processed_data.tcp_flags",
        "processed_data.icmp_type",
        "processed_data.interface",
    },
    "web_application": set(),
}


def source_path_allowed(source_family: str, path: str) -> bool:
    return path in ALLOWED_INPUT_PATHS.get(source_family, set())


def validate_registry_document(document: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(document, dict):
        raise ValueError("Wazuh rule registry must be an object")
    if document.get("schema") != "warsoc.wazuh-rule-registry/v1":
        raise ValueError("Wazuh rule registry schema is unsupported")
    version = str(document.get("ruleset_version") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", version):
        raise ValueError("Wazuh ruleset version is invalid")
    items = document.get("rules")
    if not isinstance(items, list) or not items or len(items) > 1000:
        raise ValueError("Wazuh rule registry must contain 1 to 1000 rules")

    rules: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Wazuh rule registry entries must be objects")
        rule_id = str(item.get("rule_id") or "").strip()
        if not RULE_ID_PATTERN.fullmatch(rule_id) or rule_id in rules:
            raise ValueError("Wazuh rule registry has invalid or duplicate rule IDs")
        source_family = str(item.get("source_family") or "").strip()
        if source_family not in ALLOWED_INPUT_PATHS:
            raise ValueError(f"Wazuh rule {rule_id} has an unsupported source family")
        event_ids = item.get("event_ids")
        if (
            not isinstance(event_ids, list)
            or not event_ids
            or len(event_ids) > 256
            or any(not str(value).strip() or len(str(value)) > 128 for value in event_ids)
        ):
            raise ValueError(f"Wazuh rule {rule_id} has invalid event IDs")
        category = str(item.get("category") or "").strip()
        if not FIELD_NAME_PATTERN.fullmatch(category):
            raise ValueError(f"Wazuh rule {rule_id} has an invalid category")
        severity = str(item.get("severity") or "").strip().upper()
        if severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"Wazuh rule {rule_id} has an invalid severity")
        levels = item.get("allowed_engine_levels")
        if (
            not isinstance(levels, list)
            or not levels
            or any(not isinstance(value, int) or not 0 <= value <= 16 for value in levels)
        ):
            raise ValueError(f"Wazuh rule {rule_id} has invalid engine levels")
        mitre_ids = item.get("mitre_ids", [])
        if not isinstance(mitre_ids, list) or any(
            not MITRE_ID_PATTERN.fullmatch(str(value).strip().upper()) for value in mitre_ids
        ):
            raise ValueError(f"Wazuh rule {rule_id} has invalid MITRE mappings")
        field_map = item.get("input_field_map", {})
        if not isinstance(field_map, dict) or len(field_map) > 64:
            raise ValueError(f"Wazuh rule {rule_id} has an invalid input field map")
        for output_name, source_path in field_map.items():
            output = str(output_name or "").strip()
            source = str(source_path or "").strip()
            if not FIELD_NAME_PATTERN.fullmatch(output):
                raise ValueError(f"Wazuh rule {rule_id} has an invalid output field")
            if not source_path_allowed(source_family, source):
                raise ValueError(
                    f"Wazuh rule {rule_id} requests a source field outside the approved catalog"
                )
        context_fields = item.get("candidate_context_fields", [])
        if not isinstance(context_fields, list) or not set(context_fields).issubset(
            ALLOWED_CONTEXT_FIELDS
        ):
            raise ValueError(f"Wazuh rule {rule_id} has invalid candidate context fields")
        rules[rule_id] = item
    return rules

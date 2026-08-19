"""Versioned engine-neutral contracts for WarSOC detection adapters."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


DETECTION_INPUT_SCHEMA = "warsoc.detection-input/v1"
DETECTION_CANDIDATE_SCHEMA = "warsoc.detection-candidate/v1"
DETECTION_INPUT_BATCH_SCHEMA = "warsoc.detection-input-batch/v1"
DETECTION_CANDIDATE_BATCH_SCHEMA = "warsoc.detection-candidate-batch/v1"
DETECTION_INPUT_RECEIPT_SCHEMA = "warsoc.detection-input-receipt/v1"
DETECTION_CANDIDATE_RECEIPT_SCHEMA = "warsoc.detection-candidate-receipt/v1"
BRIDGE_HEALTH_BATCH_SCHEMA = "warsoc.wazuh-bridge-health-batch/v1"
BRIDGE_HEALTH_RECEIPT_SCHEMA = "warsoc.wazuh-bridge-health-receipt/v1"

DISPATCH_UID_PATTERN = re.compile(r"^WZD_[A-F0-9]{32}$")
BATCH_UID_PATTERN = re.compile(r"^WZB_[A-F0-9]{32}$")
RULE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
MITRE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
CORRELATION_KEY_NAMES = {
    "corr_tenant",
    "corr_tenant_source",
    "corr_tenant_actor",
    "corr_tenant_endpoint",
    "corr_tenant_actor_source",
}


def _utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return value.astimezone(timezone.utc)


def _validate_scalar_map(
    value: dict[str, Any],
    *,
    max_fields: int,
    max_key_length: int = 100,
    max_text_length: int = 4096,
) -> dict[str, Any]:
    if len(value) > max_fields:
        raise ValueError(f"at most {max_fields} fields are allowed")
    cleaned: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key).strip()
        if not key or len(key) > max_key_length or not re.fullmatch(r"[A-Za-z0-9_.:-]+", key):
            raise ValueError("field names must be bounded identifiers")
        if isinstance(raw_value, (dict, list, tuple, set, bytes, bytearray)):
            raise ValueError("nested, array, and binary values are not allowed")
        if raw_value is not None and not isinstance(raw_value, (str, int, float, bool)):
            raise ValueError("only scalar JSON values are allowed")
        if isinstance(raw_value, str) and len(raw_value) > max_text_length:
            raise ValueError(f"text values must not exceed {max_text_length} characters")
        cleaned[key] = raw_value
    return cleaned


class CorrelationKeys(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    corr_tenant: str = Field(pattern=r"^[a-f0-9]{64}$")
    corr_tenant_source: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    corr_tenant_actor: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    corr_tenant_endpoint: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    corr_tenant_actor_source: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class DetectionInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_name: Literal[DETECTION_INPUT_SCHEMA] = Field(
        default=DETECTION_INPUT_SCHEMA,
        serialization_alias="schema",
        validation_alias="schema",
    )
    dispatch_uid: str
    event_uid: str = Field(min_length=8, max_length=200)
    tenant_scope: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_family: Literal["windows_endpoint", "network_device", "web_application"]
    source_assurance: Literal[
        "endpoint_signed",
        "relay_attested",
        "authenticated_application",
    ]
    original_event_time: datetime
    receipt_time: datetime
    dispatch_time: datetime
    dispatch_mode: Literal["live", "retry", "historical_replay"] = "live"
    event_age_ms: int = Field(ge=0, le=31_536_000_000)
    event_id: str = Field(min_length=1, max_length=128)
    endpoint_id: str = Field(min_length=1, max_length=255)
    correlation_key_version: str = Field(min_length=1, max_length=64)
    correlation_keys: CorrelationKeys
    security_fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("dispatch_uid")
    @classmethod
    def validate_dispatch_uid(cls, value: str) -> str:
        if not DISPATCH_UID_PATTERN.fullmatch(value):
            raise ValueError("invalid dispatch UID")
        return value

    @field_validator("original_event_time", "receipt_time", "dispatch_time")
    @classmethod
    def validate_time(cls, value: datetime, info) -> datetime:
        return _utc(value, info.field_name)

    @field_validator("security_fields")
    @classmethod
    def validate_security_fields(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_scalar_map(value, max_fields=64)

    @model_validator(mode="after")
    def validate_assurance(self):
        expected = {
            "windows_endpoint": "endpoint_signed",
            "network_device": "relay_attested",
            "web_application": "authenticated_application",
        }
        if expected[self.source_family] != self.source_assurance:
            raise ValueError("source assurance does not match the telemetry family")
        if self.receipt_time < self.original_event_time and (
            self.original_event_time - self.receipt_time
        ).total_seconds() > 300:
            raise ValueError("original event time is implausibly later than receipt time")
        if self.dispatch_time < self.receipt_time:
            raise ValueError("dispatch time must not precede receipt time")
        return self


class DetectionInputBatch(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_name: Literal[DETECTION_INPUT_BATCH_SCHEMA] = Field(
        default=DETECTION_INPUT_BATCH_SCHEMA,
        serialization_alias="schema",
        validation_alias="schema",
    )
    batch_id: str
    connector_id: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    created_at: datetime
    inputs: list[DetectionInput] = Field(min_length=1, max_length=500)

    @field_validator("batch_id")
    @classmethod
    def validate_batch_id(cls, value: str) -> str:
        if not BATCH_UID_PATTERN.fullmatch(value):
            raise ValueError("invalid batch UID")
        return value

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return _utc(value, "created_at")

    @model_validator(mode="after")
    def unique_dispatches(self):
        dispatches = [item.dispatch_uid for item in self.inputs]
        if len(dispatches) != len(set(dispatches)):
            raise ValueError("duplicate dispatch UID in input batch")
        return self


class RejectedDispatch(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    dispatch_uid: str
    reason_code: str = Field(min_length=1, max_length=64, pattern=r"^[A-Z0-9_]+$")

    @field_validator("dispatch_uid")
    @classmethod
    def validate_dispatch_uid(cls, value: str) -> str:
        if not DISPATCH_UID_PATTERN.fullmatch(value):
            raise ValueError("invalid dispatch UID")
        return value


class DetectionInputReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_name: Literal[DETECTION_INPUT_RECEIPT_SCHEMA] = Field(
        default=DETECTION_INPUT_RECEIPT_SCHEMA,
        serialization_alias="schema",
        validation_alias="schema",
    )
    batch_id: str
    connector_id: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    accepted_dispatch_uids: list[str] = Field(default_factory=list, max_length=500)
    duplicate_dispatch_uids: list[str] = Field(default_factory=list, max_length=500)
    rejected: list[RejectedDispatch] = Field(default_factory=list, max_length=500)

    @field_validator("batch_id")
    @classmethod
    def validate_batch_id(cls, value: str) -> str:
        if not BATCH_UID_PATTERN.fullmatch(value):
            raise ValueError("invalid batch UID")
        return value

    @field_validator("accepted_dispatch_uids", "duplicate_dispatch_uids")
    @classmethod
    def validate_dispatch_uids(cls, values: list[str]) -> list[str]:
        if any(not DISPATCH_UID_PATTERN.fullmatch(value) for value in values):
            raise ValueError("invalid dispatch UID")
        if len(values) != len(set(values)):
            raise ValueError("duplicate dispatch UID in receipt section")
        return values

    @model_validator(mode="after")
    def unique_receipt_results(self):
        all_dispatches = [
            *self.accepted_dispatch_uids,
            *self.duplicate_dispatch_uids,
            *(item.dispatch_uid for item in self.rejected),
        ]
        if len(all_dispatches) != len(set(all_dispatches)):
            raise ValueError("dispatch UID appears in multiple receipt outcomes")
        return self


class DetectionCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_name: Literal[DETECTION_CANDIDATE_SCHEMA] = Field(
        default=DETECTION_CANDIDATE_SCHEMA,
        serialization_alias="schema",
        validation_alias="schema",
    )
    connector_id: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    engine_instance_id: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    engine_version: str = Field(min_length=1, max_length=64)
    ruleset_version: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    engine_alert_id: str = Field(min_length=1, max_length=200)
    engine_rule_id: str
    engine_rule_level: int = Field(ge=0, le=16)
    engine_detected_at: datetime
    trigger_dispatch_uid: str | None = None
    wazuh_agent_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    wazuh_agent_name: str | None = Field(default=None, max_length=128)
    windows_event_id: str | None = Field(default=None, max_length=64)
    windows_event_record_id: str | None = Field(default=None, max_length=64)
    windows_channel: str | None = Field(default=None, max_length=128)
    selected_security_fields: dict[str, Any] = Field(default_factory=dict)
    engine_reported_category: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    engine_reported_mitre_ids: list[str] = Field(default_factory=list, max_length=32)
    engine_context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("engine_rule_id")
    @classmethod
    def validate_rule_id(cls, value: str) -> str:
        if not RULE_ID_PATTERN.fullmatch(value):
            raise ValueError("invalid engine rule ID")
        return value

    @field_validator("trigger_dispatch_uid")
    @classmethod
    def validate_trigger_dispatch_uid(cls, value: str | None) -> str | None:
        if value is not None and not DISPATCH_UID_PATTERN.fullmatch(value):
            raise ValueError("invalid trigger dispatch UID")
        return value

    @field_validator("engine_detected_at")
    @classmethod
    def validate_detected_at(cls, value: datetime) -> datetime:
        return _utc(value, "engine_detected_at")

    @field_validator("selected_security_fields", "engine_context")
    @classmethod
    def validate_maps(cls, value: dict[str, Any], info) -> dict[str, Any]:
        return _validate_scalar_map(value, max_fields=64)

    @model_validator(mode="after")
    def validate_candidate_lineage(self):
        if not self.trigger_dispatch_uid and not self.wazuh_agent_id:
            raise ValueError("candidate must include either trigger_dispatch_uid or wazuh_agent_id")
        return self


    @field_validator("engine_reported_mitre_ids")
    @classmethod
    def validate_mitre_ids(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            candidate = str(value).strip().upper()
            if not MITRE_ID_PATTERN.fullmatch(candidate):
                raise ValueError("invalid MITRE technique ID")
            if candidate not in cleaned:
                cleaned.append(candidate)
        return cleaned

    @field_validator("engine_context")
    @classmethod
    def validate_engine_context(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_scalar_map(value, max_fields=32, max_text_length=2048)


class DetectionCandidateBatch(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_name: Literal[DETECTION_CANDIDATE_BATCH_SCHEMA] = Field(
        default=DETECTION_CANDIDATE_BATCH_SCHEMA,
        serialization_alias="schema",
        validation_alias="schema",
    )
    batch_id: str
    connector_id: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    created_at: datetime
    candidates: list[DetectionCandidate] = Field(min_length=1, max_length=500)

    @field_validator("batch_id")
    @classmethod
    def validate_batch_id(cls, value: str) -> str:
        if not BATCH_UID_PATTERN.fullmatch(value):
            raise ValueError("invalid batch UID")
        return value

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return _utc(value, "created_at")

    @model_validator(mode="after")
    def validate_connector_and_delivery_identity(self):
        delivery_ids: set[tuple[str, str, str]] = set()
        for candidate in self.candidates:
            if candidate.connector_id != self.connector_id:
                raise ValueError("candidate connector does not match batch connector")
            delivery_id = (
                candidate.engine_instance_id,
                candidate.engine_alert_id,
                candidate.ruleset_version,
            )
            if delivery_id in delivery_ids:
                raise ValueError("duplicate engine delivery identity in candidate batch")
            delivery_ids.add(delivery_id)
        return self


class CandidateReceiptOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    engine_alert_id: str = Field(min_length=1, max_length=200)
    outcome: Literal["accepted", "duplicate", "quarantined"]
    reason_code: str | None = Field(default=None, max_length=64, pattern=r"^[A-Z0-9_]+$")


class DetectionCandidateReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_name: Literal[DETECTION_CANDIDATE_RECEIPT_SCHEMA] = Field(
        default=DETECTION_CANDIDATE_RECEIPT_SCHEMA,
        serialization_alias="schema",
        validation_alias="schema",
    )
    batch_id: str
    connector_id: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    outcomes: list[CandidateReceiptOutcome] = Field(min_length=1, max_length=500)

    @field_validator("batch_id")
    @classmethod
    def validate_batch_id(cls, value: str) -> str:
        if not BATCH_UID_PATTERN.fullmatch(value):
            raise ValueError("invalid batch UID")
        return value

    @model_validator(mode="after")
    def unique_alert_outcomes(self):
        identities = [item.engine_alert_id for item in self.outcomes]
        if len(identities) != len(set(identities)):
            raise ValueError("duplicate engine alert ID in candidate receipt")
        return self


class BridgeHealthEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_uid: str = Field(pattern=r"^[a-f0-9]{64}$")
    event_type: str = Field(min_length=3, max_length=64, pattern=r"^[A-Z0-9_]+$")
    severity: Literal["warning", "critical"]
    detail: str = Field(min_length=1, max_length=1024)
    occurrence_count: int = Field(ge=1)
    first_seen_at: datetime
    last_seen_at: datetime

    @field_validator("first_seen_at", "last_seen_at")
    @classmethod
    def validate_health_time(cls, value: datetime, info) -> datetime:
        return _utc(value, info.field_name)

    @model_validator(mode="after")
    def validate_health_order(self):
        if self.last_seen_at < self.first_seen_at:
            raise ValueError("health event last_seen_at precedes first_seen_at")
        return self


class BridgeHealthBatch(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_name: Literal[BRIDGE_HEALTH_BATCH_SCHEMA] = Field(
        default=BRIDGE_HEALTH_BATCH_SCHEMA,
        serialization_alias="schema",
        validation_alias="schema",
    )
    batch_id: str
    connector_id: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    engine_instance_id: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    engine_version: str = Field(min_length=1, max_length=64)
    ruleset_version: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    registry_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime
    state: Literal["healthy", "degraded"]
    input_spool_bytes: int = Field(ge=0)
    candidate_spool_bytes: int = Field(ge=0)
    retry_records: int = Field(ge=0)
    alert_file_lag_bytes: int = Field(ge=0)
    counters: dict[str, int] = Field(default_factory=dict)
    events: list[BridgeHealthEvent] = Field(default_factory=list, max_length=500)

    @field_validator("batch_id")
    @classmethod
    def validate_batch_id(cls, value: str) -> str:
        if not BATCH_UID_PATTERN.fullmatch(value):
            raise ValueError("invalid batch UID")
        return value

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return _utc(value, "created_at")

    @field_validator("counters")
    @classmethod
    def validate_counters(cls, value: dict[str, int]) -> dict[str, int]:
        if len(value) > 64:
            raise ValueError("too many bridge counters")
        for name, count in value.items():
            if not re.fullmatch(r"[a-z0-9_]{3,64}", name):
                raise ValueError("invalid bridge counter name")
            if not isinstance(count, int) or count < 0:
                raise ValueError("bridge counters must be non-negative integers")
        return value

    @model_validator(mode="after")
    def unique_health_events(self):
        identities = [item.event_uid for item in self.events]
        if len(identities) != len(set(identities)):
            raise ValueError("duplicate bridge health event in batch")
        return self


class BridgeHealthReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_name: Literal[BRIDGE_HEALTH_RECEIPT_SCHEMA] = Field(
        default=BRIDGE_HEALTH_RECEIPT_SCHEMA,
        serialization_alias="schema",
        validation_alias="schema",
    )
    batch_id: str
    connector_id: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    accepted_event_uids: list[str] = Field(default_factory=list, max_length=500)

    @field_validator("batch_id")
    @classmethod
    def validate_batch_id(cls, value: str) -> str:
        if not BATCH_UID_PATTERN.fullmatch(value):
            raise ValueError("invalid batch UID")
        return value

    @field_validator("accepted_event_uids")
    @classmethod
    def validate_event_uids(cls, values: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[a-f0-9]{64}", value) for value in values):
            raise ValueError("invalid bridge health event UID")
        if len(values) != len(set(values)):
            raise ValueError("duplicate bridge health receipt UID")
        return values

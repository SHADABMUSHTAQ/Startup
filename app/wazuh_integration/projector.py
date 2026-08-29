"""Post-persistence projection of approved SIEM telemetry into the Wazuh outbox."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import orjson
from pymongo.errors import DuplicateKeyError

from app.wazuh_integration.contracts import (
    DETECTION_INPUT_SCHEMA,
    CorrelationKeys,
    DetectionInput,
)
from app.wazuh_integration.security import encrypt_payload, purpose_hmac
from app.wazuh_integration.registry import source_path_allowed


PROJECTOR_ID = "wazuh-detection-projector-v1"
SENSITIVE_FIELD_PARTS = {
    "authorization",
    "card",
    "cnic",
    "credential",
    "cvv",
    "invoice",
    "pan",
    "passwd",
    "password",
    "payload",
    "secret",
    "token",
}
ALLOWED_ROOT_FIELDS = {
    "event_id",
    "event_type",
    "source_ip",
    "user",
    "message",
    "telemetry_family",
    "processed_data",
}
SECRET_VALUE_PATTERN = re.compile(
    r"(?i)(authorization:\s*bearer\s+|(?:password|passwd|token|secret|api[_-]?key)\s*[=:]\s*)([^\s,;]+)"
)


@dataclass(frozen=True)
class ProjectionResult:
    status: str
    dispatch_uid: str | None = None
    reason: str | None = None
    payload_bytes: int = 0


def _as_utc(value: Any, fallback: datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return fallback
    else:
        return fallback
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _dispatch_uid(tenant_id: str, event_uid: str, ruleset_version: str) -> str:
    material = "\x00".join(
        (tenant_id, event_uid, DETECTION_INPUT_SCHEMA, ruleset_version)
    ).encode("utf-8")
    return f"WZD_{hashlib.sha256(material).hexdigest()[:32].upper()}"


def _source_identity(
    document: dict[str, Any],
    *,
    network_enabled: bool,
    native_endpoint_enabled: bool = False,
) -> tuple[str, str, str] | None:
    family = str(document.get("telemetry_family") or "").strip().lower()
    if (
        not native_endpoint_enabled
        and family == "windows"
        and document.get("signature_verified") is True
        and document.get("source_assurance") == "agent_signed"
    ):
        endpoint_id = str(document.get("agent_id") or "").strip()
        return ("windows_endpoint", "endpoint_signed", endpoint_id) if endpoint_id else None
    if (
        network_enabled
        and family == "network"
        and document.get("source_type") == "network_device"
        and document.get("signature_verified") is True
        and document.get("source_assurance") == "relay_attested"
    ):
        endpoint_id = str(
            document.get("network_device_id") or document.get("agent_id") or ""
        ).strip()
        return ("network_device", "relay_attested", endpoint_id) if endpoint_id else None
    return None


def _read_path(document: dict[str, Any], path: str) -> Any:
    parts = path.split(".")
    if not parts or parts[0] not in ALLOWED_ROOT_FIELDS:
        return None
    current: Any = document
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _safe_field_name(name: str) -> bool:
    parts = {part.lower() for part in re.split(r"[_.:-]+", name) if part}
    return bool(parts) and not parts.intersection(SENSITIVE_FIELD_PARTS)


def _sanitize_scalar(value: Any) -> str | int | float | bool | None:
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if not isinstance(value, str):
        return None
    value = SECRET_VALUE_PATTERN.sub(r"\1[REDACTED]", value.strip())
    return value[:4096]


def _field_map(rules: list[dict[str, Any]], source_family: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for rule in rules:
        mapping = rule.get("input_field_map")
        if not isinstance(mapping, dict):
            continue
        for output_name, source_path in mapping.items():
            output = str(output_name or "").strip()
            source = str(source_path or "").strip()
            if (
                output
                and source
                and _safe_field_name(output)
                and _safe_field_name(source)
                and source_path_allowed(source_family, source)
                and output not in result
            ):
                result[output] = source
    return result


def _security_fields(
    document: dict[str, Any],
    rules: list[dict[str, Any]],
    source_family: str,
) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for output_name, source_path in _field_map(rules, source_family).items():
        value = _sanitize_scalar(_read_path(document, source_path))
        if value is not None and value != "":
            fields[output_name] = value
        if len(fields) >= 64:
            break
    return fields


def _correlation_keys(settings, tenant_id: str, document: dict[str, Any], endpoint_id: str) -> CorrelationKeys:
    secret = settings.wazuh_correlation_hmac_key
    processed_data = document.get("processed_data")
    if not isinstance(processed_data, dict):
        processed_data = {}
    source_ip = str(
        processed_data.get("source_network_address")
        or processed_data.get("src_ip")
        or document.get("source_ip")
        or ""
    ).strip()
    actor = str(
        processed_data.get("user")
        or document.get("user")
        or ""
    ).strip()

    def derive(purpose: str, *values: str) -> str:
        return purpose_hmac(secret, purpose=purpose, values=[tenant_id, *values])

    return CorrelationKeys(
        corr_tenant=derive("correlation:tenant"),
        corr_tenant_source=derive("correlation:source", source_ip) if source_ip else None,
        corr_tenant_actor=derive("correlation:actor", actor) if actor else None,
        corr_tenant_endpoint=derive("correlation:endpoint", endpoint_id),
        corr_tenant_actor_source=(
            derive("correlation:actor-source", actor, source_ip)
            if actor and source_ip
            else None
        ),
    )


async def _approved_rules(db, settings, source_family: str, event_id: str) -> list[dict[str, Any]]:
    query = {
        "engine": "wazuh",
        "status": "approved",
        "dispatch_enabled": True,
        "ruleset_version": settings.wazuh_ruleset_version,
        "source_family": source_family,
        "$or": [{"event_ids": event_id}, {"event_ids": "*"}],
    }
    return await db.detection_rule_registry.find(query).limit(100).to_list(length=100)


async def _active_outbox_bytes(db) -> int:
    rows = await db.detection_dispatch_outbox.aggregate(
        [
            {"$match": {"status": {"$in": ["pending", "retry", "in_flight"]}}},
            {"$group": {"_id": None, "total": {"$sum": "$payload_bytes"}}},
        ]
    ).to_list(length=1)
    return int(rows[0].get("total") or 0) if rows else 0


def build_detection_input(
    document: dict[str, Any],
    rules: list[dict[str, Any]],
    settings,
    *,
    now: datetime | None = None,
) -> DetectionInput:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    tenant_id = str(document.get("tenant_id") or "").strip()
    event_uid = str(document.get("event_uid") or "").strip()
    event_id = str(document.get("event_id") or "").strip()
    if not tenant_id or not event_uid or not event_id:
        raise ValueError("canonical event identity is incomplete")

    identity = _source_identity(
        document,
        network_enabled=bool(settings.network_relay_enabled),
    )
    if identity is None:
        raise ValueError("canonical event does not have approved source assurance")
    source_family, source_assurance, endpoint_id = identity
    original_time = _as_utc(document.get("timestamp"), current)
    receipt_time = _as_utc(document.get("ingested_at"), current)
    if receipt_time < original_time and (original_time - receipt_time) <= timedelta(minutes=5):
        receipt_time = original_time
    age_ms = max(0, int((current - original_time).total_seconds() * 1000))

    return DetectionInput(
        dispatch_uid=_dispatch_uid(tenant_id, event_uid, settings.wazuh_ruleset_version),
        event_uid=event_uid,
        tenant_scope=purpose_hmac(
            settings.wazuh_correlation_hmac_key,
            purpose="tenant-scope:v1",
            values=[tenant_id],
        ),
        source_family=source_family,
        source_assurance=source_assurance,
        original_event_time=original_time,
        receipt_time=receipt_time,
        dispatch_time=current,
        dispatch_mode="live",
        event_age_ms=age_ms,
        event_id=event_id,
        endpoint_id=endpoint_id,
        correlation_key_version=settings.wazuh_correlation_key_version,
        correlation_keys=_correlation_keys(settings, tenant_id, document, endpoint_id),
        security_fields=_security_fields(document, rules, source_family),
    )


async def project_canonical_event(
    db,
    document: dict[str, Any],
    settings,
    *,
    now: datetime | None = None,
    active_outbox_bytes: int | None = None,
) -> ProjectionResult:
    if settings.wazuh_detection_mode == "disabled":
        return ProjectionResult(status="disabled")

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    # Point 4: Per-endpoint native Wazuh binding check.
    # Only skip Windows custom-JSON projection for endpoints that have
    # an active native Wazuh agent binding. Endpoints without a binding
    # continue to be projected normally.
    endpoint_has_native_wazuh = False
    doc_family = str(document.get("telemetry_family") or "").strip().lower()
    if doc_family == "windows":
        endpoint_id = str(document.get("agent_id") or "").strip()
        if endpoint_id:
            bindings_col = getattr(db, "detection_engine_agent_bindings", None)
            if bindings_col is not None:
                native_binding = await bindings_col.find_one(
                    {
                        "engine": "wazuh",
                        "warsoc_agent_id": endpoint_id,
                        "status": "active",
                    }
                )
                endpoint_has_native_wazuh = native_binding is not None

    identity = _source_identity(
        document,
        network_enabled=bool(settings.network_relay_enabled),
        native_endpoint_enabled=endpoint_has_native_wazuh,
    )
    if identity is None:
        return ProjectionResult(status="ineligible", reason="source_assurance")
    source_family = identity[0]
    event_id = str(document.get("event_id") or "").strip()
    rules = await _approved_rules(db, settings, source_family, event_id)
    if not rules:
        return ProjectionResult(status="ineligible", reason="no_approved_rule")

    try:
        detection_input = build_detection_input(document, rules, settings, now=current)
    except ValueError as exc:
        return ProjectionResult(status="ineligible", reason=str(exc))

    if detection_input.event_age_ms > settings.wazuh_live_event_max_age_seconds * 1000:
        return ProjectionResult(
            status="expired",
            dispatch_uid=detection_input.dispatch_uid,
            reason="event_too_old_for_live_dispatch",
        )

    payload = orjson.dumps(
        detection_input.model_dump(mode="json", by_alias=True),
        option=orjson.OPT_SORT_KEYS,
    )
    if len(payload) > settings.wazuh_max_body_bytes:
        return ProjectionResult(
            status="rejected",
            dispatch_uid=detection_input.dispatch_uid,
            reason="projected_payload_too_large",
        )

    current_outbox_bytes = (
        await _active_outbox_bytes(db)
        if active_outbox_bytes is None
        else active_outbox_bytes
    )
    if current_outbox_bytes + len(payload) > settings.wazuh_outbox_max_bytes:
        await db.detection_coverage_gaps.update_one(
            {
                "gap_type": "wazuh_dispatch_outbox_capacity",
                "tenant_id": str(document["tenant_id"]),
                "event_uid": detection_input.event_uid,
                "ruleset_version": settings.wazuh_ruleset_version,
            },
            {
                "$setOnInsert": {
                    "created_at": current,
                    "source_collection": "siem_cold_vault",
                    "source_record_id": str(document.get("_id") or ""),
                },
                "$set": {"last_seen_at": current, "status": "open"},
            },
            upsert=True,
        )
        return ProjectionResult(
            status="capacity_refused",
            dispatch_uid=detection_input.dispatch_uid,
            reason="outbox_capacity_reached",
        )

    tenant_id = str(document["tenant_id"])
    source_record_id = str(document.get("_id") or "")
    payload_hash = hashlib.sha256(payload).hexdigest()
    source_hash = hashlib.sha256(
        "\x00".join(
            (
                tenant_id,
                detection_input.event_uid,
                source_record_id,
                detection_input.original_event_time.isoformat(),
            )
        ).encode("utf-8")
    ).hexdigest()
    rule_ids = sorted({str(rule.get("rule_id") or "") for rule in rules if rule.get("rule_id")})
    outbox_document = {
        "dispatch_uid": detection_input.dispatch_uid,
        "tenant_id": tenant_id,
        "event_uid": detection_input.event_uid,
        "source_collection": "siem_cold_vault",
        "source_record_id": source_record_id,
        "source_record_hash": source_hash,
        "source_family": detection_input.source_family,
        "ruleset_version": settings.wazuh_ruleset_version,
        "eligible_rule_ids": rule_ids,
        "schema": DETECTION_INPUT_SCHEMA,
        "status": "pending",
        "dispatch_mode": "live",
        "attempt_count": 0,
        "next_attempt_at": current,
        "lease_token": None,
        "lease_expires_at": None,
        "payload_ciphertext": encrypt_payload(settings.wazuh_outbox_encryption_key, payload),
        "payload_sha256": payload_hash,
        "payload_bytes": len(payload),
        "created_at": current,
        "updated_at": current,
        "live_expires_at": detection_input.original_event_time
        + timedelta(seconds=settings.wazuh_live_event_max_age_seconds),
        "record_expires_at": current + timedelta(days=settings.wazuh_outbox_record_ttl_days),
    }
    try:
        result = await db.detection_dispatch_outbox.update_one(
            {"dispatch_uid": detection_input.dispatch_uid},
            {"$setOnInsert": outbox_document},
            upsert=True,
        )
    except DuplicateKeyError:
        return ProjectionResult(status="duplicate", dispatch_uid=detection_input.dispatch_uid)
    return ProjectionResult(
        status="created" if result.upserted_id is not None else "duplicate",
        dispatch_uid=detection_input.dispatch_uid,
        payload_bytes=len(payload) if result.upserted_id is not None else 0,
    )


async def project_new_canonical_events(db, settings, *, limit: int | None = None) -> dict[str, int]:
    if settings.wazuh_detection_mode == "disabled":
        return {"disabled": 1}

    batch_limit = limit or settings.wazuh_projector_batch_size
    current = datetime.now(timezone.utc)
    state = await db.detection_projector_state.find_one({"projector_id": PROJECTOR_ID})
    if state and state.get("last_record_id") is not None:
        last_id = state.get("last_record_id")
        query: dict[str, Any] = {"_id": {"$gt": last_id}}
        sort = [("_id", 1)]
    else:
        query = {"ingested_at": {"$gte": current - timedelta(seconds=5)}}
        sort = [("_id", 1)]

    documents = await (
        db.siem_cold_vault.find(query)
        .sort(sort)
        .limit(batch_limit)
        .to_list(length=batch_limit)
    )
    counts: dict[str, int] = {}
    active_outbox_bytes = await _active_outbox_bytes(db)
    for document in documents:
        result = await project_canonical_event(
            db,
            document,
            settings,
            now=current,
            active_outbox_bytes=active_outbox_bytes,
        )
        counts[result.status] = counts.get(result.status, 0) + 1
        active_outbox_bytes += result.payload_bytes

    if documents:
        last = documents[-1]
        await db.detection_projector_state.update_one(
            {"projector_id": PROJECTOR_ID},
            {
                "$set": {
                    "last_ingested_at": _as_utc(last.get("ingested_at"), current),
                    "last_record_id": last.get("_id"),
                    "updated_at": current,
                },
                "$setOnInsert": {"created_at": current},
            },
            upsert=True,
        )
    return counts

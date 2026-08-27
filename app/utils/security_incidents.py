"""Mutable operational incidents derived from immutable security evidence.

The detector and compliance workers remain the source of truth for evidence.
This module projects their alert metadata into a small operator-facing read
model whose workflow state can outlive the seven-day MongoDB evidence window.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

from pymongo.errors import DuplicateKeyError

from app.utils.alert_context import build_alert_context, operator_alert_document


OPEN_INCIDENT_STATUSES = ("NEW", "ACKNOWLEDGED")
TERMINAL_INCIDENT_STATUSES = ("CLOSED", "FALSE_POSITIVE")
INCIDENT_OCCURRENCE_TTL_DAYS = max(
    8,
    min(90, int(os.getenv("INCIDENT_OCCURRENCE_TTL_DAYS", "30"))),
)
MAX_INCIDENT_EVIDENCE_REFS = max(
    20,
    min(500, int(os.getenv("MAX_INCIDENT_EVIDENCE_REFS", "100"))),
)
MAX_INCIDENT_WORKFLOW_HISTORY = max(
    20,
    min(200, int(os.getenv("MAX_INCIDENT_WORKFLOW_HISTORY", "100"))),
)

_SEVERITY_RANK = {
    "INFO": 0,
    "INFORMATIONAL": 0,
    "LOW": 1,
    "WARNING": 2,
    "MEDIUM": 2,
    "ALERT": 3,
    "HIGH": 3,
    "CRITICAL": 4,
}
_GENERIC_ALERT_PATTERNS = (
    re.compile(r"^WIN_EVENT_\d+_DETECTED$", re.IGNORECASE),
    re.compile(r"^EVENT_ID_\d+_", re.IGNORECASE),
    re.compile(r".*_KEYWORD_MATCH$", re.IGNORECASE),
)
_FBR_OPERATIONAL_EVENT_IDS = {"FBR-INV-MOD", "FBR-INV-DEL", "FIM-DB-MOD"}
_SERVICE_INSTALL_EVENT_IDS = {"4697", "7045"}
_SERVICE_INSTALL_RULE_ID = "WINDOWS_SERVICE_INSTALLED"
_SERVICE_INSTALL_BUCKET_MINUTES = 5


def _text(value: Any, default: str = "") -> str:
    return str(value if value is not None else default).strip()


def _normalized(value: Any) -> str:
    return " ".join(_text(value).lower().split())


def _positive_int(value: Any, default: int = 1) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


def _coerce_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            parsed = datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_incident_status(value: Any) -> str:
    status = _text(value or "NEW").upper()
    allowed = {*OPEN_INCIDENT_STATUSES, *TERMINAL_INCIDENT_STATUSES}
    return status if status in allowed else "NEW"


def normalize_incident_severity(value: Any) -> tuple[str, int]:
    raw = _text(value or "MEDIUM").upper()
    aliases = {"INFO": "LOW", "INFORMATIONAL": "LOW", "WARNING": "MEDIUM", "ALERT": "HIGH"}
    normalized = aliases.get(raw, raw)
    if normalized not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        normalized = "MEDIUM"
    return normalized, _SEVERITY_RANK[normalized]


def _interpretation_kind(alert: Mapping[str, Any]) -> str:
    alert_type = _text(alert.get("type") or alert.get("rule_id") or alert.get("matched_rule_id"))
    if alert_type and any(pattern.match(alert_type) for pattern in _GENERIC_ALERT_PATTERNS):
        return "generic"
    return "specific"


def should_project_security_incident(alert: Mapping[str, Any]) -> bool:
    """Return whether alert metadata represents an operator-actionable signal."""
    if not _text(alert.get("tenant_id")):
        return False
    pack = _normalized(alert.get("pack") or alert.get("compliance_pack") or "siem")
    if pack == "fbr_pos":
        return _text(alert.get("event_id")).upper() in _FBR_OPERATIONAL_EVENT_IDS
    # PECA records are evidence by default. Inherently dangerous PECA controls
    # become incidents through the SIEM worker, not by vaulting alone.
    if pack == "peca_forensic" and not (
        alert.get("alert_uid") or alert.get("type") or alert.get("matched_rule_id")
    ):
        return False
    return bool(
        alert.get("alert_uid")
        or alert.get("alert_id")
        or alert.get("type")
        or alert.get("matched_rule_id")
        or alert.get("rule_id")
    )


def _command_fingerprint(context: Mapping[str, Any]) -> str:
    command = _normalized(context.get("command_line"))
    return hashlib.sha256(command.encode("utf-8")).hexdigest()[:16] if command else ""


def build_incident_identity(alert: Mapping[str, Any]) -> dict[str, Any]:
    """Build a conservative, UTC-minute incident identity.

    Severity and workflow status are intentionally excluded so the same
    incident can escalate or be acknowledged without changing identity.
    """
    timestamp = _coerce_datetime(
        alert.get("timestamp") or alert.get("ingested_at") or alert.get("created_at")
    )
    context = build_alert_context(alert)
    rule_id = _text(
        alert.get("matched_rule_id")
        or alert.get("rule_id")
        or alert.get("type")
        or alert.get("event_id")
        or "security_event"
    )
    event_id = _text(alert.get("event_id"))
    is_service_install = event_id in _SERVICE_INSTALL_EVENT_IDS
    if is_service_install:
        bucket_start = timestamp.replace(
            minute=(timestamp.minute // _SERVICE_INSTALL_BUCKET_MINUTES)
            * _SERVICE_INSTALL_BUCKET_MINUTES,
            second=0,
            microsecond=0,
        )
        bucket_end = bucket_start + timedelta(minutes=_SERVICE_INSTALL_BUCKET_MINUTES)
        identity_rule_id = _SERVICE_INSTALL_RULE_ID
        identity_event_id = "service_installed"
    else:
        bucket_start = timestamp.replace(second=0, microsecond=0)
        bucket_end = bucket_start + timedelta(minutes=1)
        identity_rule_id = rule_id
        identity_event_id = event_id
    pack = _normalized(alert.get("pack") or alert.get("compliance_pack") or "siem")
    if is_service_install:
        service_object = _normalized(
            context.get("protected_object")
            or context.get("target")
            or alert.get("target_fingerprint")
        )
        # Without a service identity, preserve separate incidents rather than
        # risk merging unrelated installations on the same endpoint.
        service_identity = service_object or _normalized(
            alert.get("alert_uid") or alert.get("event_uid") or event_id
        )
        fields = (
            _text(alert.get("tenant_id")),
            bucket_start.isoformat(),
            pack,
            _normalized(identity_rule_id),
            _normalized(context.get("endpoint") or alert.get("computer") or alert.get("agent_id")),
            _normalized(context.get("agent_id") or alert.get("agent_id")),
            service_identity,
        )
    else:
        fields = (
            _text(alert.get("tenant_id")),
            bucket_start.isoformat(),
            pack,
            _normalized(identity_rule_id),
            _normalized(identity_event_id),
            _normalized(context.get("endpoint") or alert.get("computer") or alert.get("agent_id")),
            _normalized(context.get("agent_id") or alert.get("agent_id")),
            _normalized(context.get("actor") or context.get("user") or alert.get("user")),
            _normalized(context.get("target_user") or context.get("target") or alert.get("target")),
            _normalized(context.get("process_name")),
            _normalized(context.get("parent_process")),
            _command_fingerprint(context),
            _normalized(context.get("source_address") or alert.get("source_ip")),
            _normalized(context.get("source_port")),
            _normalized(context.get("destination_address")),
            _normalized(context.get("destination_port")),
            _normalized(context.get("protected_object") or context.get("target") or alert.get("target_fingerprint")),
            _normalized(context.get("outcome")),
        )
    digest = hashlib.sha256("|".join(fields).encode("utf-8")).hexdigest()
    return {
        "incident_key": digest,
        "incident_id": f"INC-{digest[:20].upper()}",
        "bucket_start": bucket_start,
        "bucket_end": bucket_end,
        "timestamp": timestamp,
        "rule_id": identity_rule_id,
        "pack": pack,
        "context": context,
    }


def _occurrence_uid(alert: Mapping[str, Any], incident_key: str) -> str:
    explicit = _text(
        alert.get("alert_uid")
        or alert.get("alert_id")
        or alert.get("event_uid")
        or alert.get("_id")
    )
    if explicit:
        source = explicit
    else:
        bounded = {
            "incident_key": incident_key,
            "event_id": alert.get("event_id"),
            "timestamp": str(alert.get("timestamp") or alert.get("ingested_at") or ""),
            "summary": alert.get("summary") or alert.get("message"),
        }
        source = json.dumps(bounded, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _evidence_reference(alert: Mapping[str, Any]) -> dict[str, Any]:
    reference = {
        "document_id": _text(alert.get("_id")) or None,
        "alert_id": _text(alert.get("alert_id")) or None,
        "alert_uid": _text(alert.get("alert_uid")) or None,
        "event_uid": _text(alert.get("event_uid")) or None,
        "cold_id": _text(alert.get("cold_id")) or None,
        "timestamp": _coerce_datetime(
            alert.get("timestamp") or alert.get("ingested_at") or alert.get("created_at")
        ),
    }
    return {key: value for key, value in reference.items() if value not in (None, "")}


def _is_bannable_source(context: Mapping[str, Any]) -> bool:
    raw = _text(context.get("source_address"))
    if not raw:
        return False
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return False
    endpoint = _text(context.get("endpoint"))
    return bool(address.is_global and raw != endpoint)


async def _refresh_incident_suppression(db, tenant_id: str, incident_id: str) -> None:
    document = await db.security_incidents.find_one(
        {"tenant_id": tenant_id, "incident_id": incident_id},
        {"occurrences": 1, "superseded_event_uids": 1},
    )
    if not document:
        return
    superseded_count = len(set(document.get("superseded_event_uids") or []))
    visible_occurrences = max(0, int(document.get("occurrences") or 0) - superseded_count)
    await db.security_incidents.update_one(
        {"_id": document["_id"]},
        {
            "$set": {
                "suppressed": visible_occurrences == 0,
                "visible_occurrences": visible_occurrences,
            }
        },
    )


async def _link_superseded_interpretations(
    db,
    *,
    tenant_id: str,
    incident_id: str,
    event_uid: str | None,
    interpretation_kind: str,
) -> None:
    if not event_uid:
        await _refresh_incident_suppression(db, tenant_id, incident_id)
        return

    counterpart = "generic" if interpretation_kind == "specific" else "specific"
    cursor = db.security_incident_occurrences.find(
        {
            "tenant_id": tenant_id,
            "event_uid": event_uid,
            "interpretation_kind": counterpart,
            "incident_id": {"$ne": incident_id},
        },
        {"incident_id": 1},
    )
    counterpart_ids = []
    async for row in cursor:
        value = _text(row.get("incident_id"))
        if value and value not in counterpart_ids:
            counterpart_ids.append(value)
    generic_ids = counterpart_ids if interpretation_kind == "specific" else [incident_id]
    if generic_ids:
        await db.security_incidents.update_many(
            {"tenant_id": tenant_id, "incident_id": {"$in": generic_ids}},
            {"$addToSet": {"superseded_event_uids": event_uid}},
        )
    for affected_id in set([incident_id, *counterpart_ids]):
        await _refresh_incident_suppression(db, tenant_id, affected_id)


async def project_security_incident(
    db,
    alert: Mapping[str, Any],
    source_event: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Idempotently project one persisted alert into the incident read model."""
    source = dict(alert)
    if source_event:
        source["context"] = build_alert_context(source, source_event)
    if not should_project_security_incident(source):
        return None

    identity = build_incident_identity(source)
    tenant_id = _text(source.get("tenant_id"))
    occurrence_uid = _occurrence_uid(source, identity["incident_key"])
    event_uid = _text(source.get("event_uid")) or None
    alert_uid = _text(source.get("alert_uid")) or None
    alert_ref = _text(source.get("_id") or source.get("alert_id")) or None
    now = datetime.now(timezone.utc)
    occurrence = {
        "tenant_id": tenant_id,
        "occurrence_uid": occurrence_uid,
        "incident_id": identity["incident_id"],
        "incident_key": identity["incident_key"],
        "event_uid": event_uid,
        "alert_uid": alert_uid,
        "alert_ref": alert_ref,
        "interpretation_kind": _interpretation_kind(source),
        "projected_at": now,
        "expires_at": now + timedelta(days=INCIDENT_OCCURRENCE_TTL_DAYS),
    }
    occurrence = {key: value for key, value in occurrence.items() if value is not None}

    try:
        occurrence_result = await db.security_incident_occurrences.insert_one(occurrence)
    except DuplicateKeyError:
        existing = await db.security_incidents.find_one(
            {"tenant_id": tenant_id, "incident_id": identity["incident_id"]}
        )
        if existing and normalize_incident_status(source.get("status")) in TERMINAL_INCIDENT_STATUSES:
            await db.security_incidents.update_one(
                {"_id": existing["_id"]},
                {
                    "$set": {
                        "status": normalize_incident_status(source.get("status")),
                        "resolution_notes": source.get("resolution_notes"),
                        "assignee_id": source.get("assignee_id"),
                        "updated_at": now,
                    }
                },
            )
            existing = await db.security_incidents.find_one({"_id": existing["_id"]})
        return {
            "incident": existing,
            "created": False,
            "duplicate": True,
        } if existing else None

    severity, severity_rank = normalize_incident_severity(source.get("severity"))
    status = normalize_incident_status(source.get("status"))
    title = _text(source.get("display_title") or source.get("summary") or source.get("title") or identity["rule_id"])
    operator = operator_alert_document(source, source_event)
    message = _text(operator.get("message") or title or "Security incident detected")[:320]
    context = identity["context"]
    context["bannable"] = _is_bannable_source(context)
    evidence_ref = _evidence_reference(source)
    interpretation_kind = _interpretation_kind(source)

    update = {
        "$setOnInsert": {
            "tenant_id": tenant_id,
            "incident_id": identity["incident_id"],
            "incident_key": identity["incident_key"],
            "record_type": "incident",
            "bucket_start": identity["bucket_start"],
            "bucket_end": identity["bucket_end"],
            "status": status,
            "workflow_version": 0,
            "workflow_history": [
                {
                    "audit_id": f"DET-{identity['incident_id']}",
                    "action": "detected",
                    "changed_fields": [],
                    "changes": {},
                    "status": status,
                    "resolution_notes": None,
                    "operator": "WarSOC detection engine",
                    "operator_id": None,
                    "operator_role": "system",
                    "timestamp": identity["timestamp"],
                    "workflow_version": 0,
                }
            ],
            "created_at": now,
            "interpretation_kind": interpretation_kind,
        },
        "$set": {
            "title": title[:240],
            "message": message,
            "pack": identity["pack"],
            "rule_id": identity["rule_id"],
            "event_id": source.get("event_id"),
            "engine_source": source.get("engine_source") or source.get("engine") or "SIEM",
            "mitre": source.get("mitre") or source.get("mitre_id"),
            "context": context,
            "updated_at": now,
            "suppressed": False,
        },
        "$min": {"first_seen": identity["timestamp"]},
        "$max": {
            "last_seen": identity["timestamp"],
            "severity_rank": severity_rank,
        },
        "$inc": {"occurrences": _positive_int(source.get("occurrences"))},
        "$push": {
            "evidence_refs": {"$each": [evidence_ref], "$slice": -MAX_INCIDENT_EVIDENCE_REFS},
            "event_uids": {"$each": [event_uid] if event_uid else [], "$slice": -MAX_INCIDENT_EVIDENCE_REFS},
            "alert_uids": {"$each": [alert_uid] if alert_uid else [], "$slice": -MAX_INCIDENT_EVIDENCE_REFS},
        },
    }

    try:
        result = await db.security_incidents.update_one(
            {"tenant_id": tenant_id, "incident_id": identity["incident_id"]},
            update,
            upsert=True,
        )
        await db.security_incidents.update_one(
            {
                "tenant_id": tenant_id,
                "incident_id": identity["incident_id"],
                "severity_rank": {"$lte": severity_rank},
            },
            {"$set": {"severity": severity}},
        )
        incident = await db.security_incidents.find_one(
            {"tenant_id": tenant_id, "incident_id": identity["incident_id"]}
        )
    except Exception:
        await db.security_incident_occurrences.delete_one({"_id": occurrence_result.inserted_id})
        raise

    await _link_superseded_interpretations(
        db,
        tenant_id=tenant_id,
        incident_id=identity["incident_id"],
        event_uid=event_uid,
        interpretation_kind=interpretation_kind,
    )
    incident = await db.security_incidents.find_one(
        {"tenant_id": tenant_id, "incident_id": identity["incident_id"]}
    )

    return {
        "incident": incident,
        "created": result.upserted_id is not None,
        "duplicate": False,
    }


async def project_and_publish_incident(
    db,
    redis_client,
    alert: Mapping[str, Any],
    source_event: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project an alert and publish a small tenant-scoped incident envelope."""
    operator = operator_alert_document(alert, source_event)
    projection = await project_security_incident(db, alert, source_event)
    if not projection or not projection.get("incident"):
        return operator

    incident = projection["incident"]
    operator["incident_id"] = incident.get("incident_id")
    operator["incident_key"] = incident.get("incident_key")
    operator["occurrences"] = incident.get("occurrences", 1)
    if redis_client is not None and not projection.get("duplicate"):
        envelope = {
            "type": "incident.created" if projection.get("created") else "incident.updated",
            "tenant_id": incident.get("tenant_id"),
            "incident_id": incident.get("incident_id"),
            "severity": incident.get("severity"),
            "title": incident.get("title"),
            "message": incident.get("message"),
            "incident": serialize_incident(incident),
        }
        await redis_client.publish("security_incidents", json.dumps(envelope, default=str))
    return operator


def serialize_incident(document: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(document)
    internal_detection_sources = result.pop("detection_sources", None)
    if internal_detection_sources:
        # Detector/vendor provenance is retained in Mongo for engineering and
        # audit use. Customer APIs expose WarSOC as the incident authority.
        result["detection_source"] = "WarSOC"
    evidence_refs = result.get("evidence_refs") or []
    event_uids = result.get("event_uids") or []
    alert_uids = result.get("alert_uids") or []
    if result.get("_id") is not None:
        result["_id"] = str(result["_id"])
    for field in (
        "bucket_start",
        "bucket_end",
        "first_seen",
        "last_seen",
        "created_at",
        "updated_at",
        "closed_at",
    ):
        if isinstance(result.get(field), datetime):
            result[field] = result[field].isoformat()
    result["evidence_reference_count"] = len(evidence_refs)
    result["tracked_event_count"] = len(set(value for value in event_uids if value))
    result["tracked_alert_count"] = len(set(value for value in alert_uids if value))
    result["evidence_tracking_limit"] = MAX_INCIDENT_EVIDENCE_REFS
    result.pop("severity_rank", None)
    result.pop("incident_key", None)
    result.pop("evidence_refs", None)
    result.pop("event_uids", None)
    result.pop("alert_uids", None)
    result.pop("workflow_history", None)
    result["occurrences"] = int(
        result.get("visible_occurrences")
        if result.get("visible_occurrences") is not None
        else result.get("occurrences") or 0
    )
    result.pop("visible_occurrences", None)
    result.pop("superseded_event_uids", None)
    return result


def incident_reference_values(alerts: Iterable[Mapping[str, Any]], extra: Iterable[str] = ()) -> set[str]:
    values = {_text(value) for value in extra if _text(value)}
    for alert in alerts:
        for field in ("_id", "alert_id", "alert_uid", "event_uid"):
            value = _text(alert.get(field))
            if value:
                values.add(value)
    return values


async def find_incident_ids_for_references(db, tenant_id: str, references: Iterable[str]) -> list[str]:
    values = list({value for value in references if value})
    if not values:
        return []
    cursor = db.security_incident_occurrences.find(
        {
            "tenant_id": tenant_id,
            "$or": [
                {"alert_ref": {"$in": values}},
                {"alert_uid": {"$in": values}},
                {"event_uid": {"$in": values}},
            ],
        },
        {"incident_id": 1},
    )
    rows = await cursor.to_list(length=1000)
    return list(dict.fromkeys(_text(row.get("incident_id")) for row in rows if row.get("incident_id")))


async def backfill_hot_security_incidents(db, *, limit: int = 5000) -> dict[str, int]:
    """Run the incident-v1 migration once over the bounded hot alert window."""
    migration_id = "security-incidents-v1"
    existing = await db.system_migrations.find_one({"migration_id": migration_id, "status": "complete"})
    if existing:
        return {"scanned": 0, "projected": 0}

    scanned = 0
    projected = 0
    cursor = db.security_alerts.find({}).sort([("timestamp", 1), ("_id", 1)]).limit(max(0, limit))
    async for alert in cursor:
        scanned += 1
        if await project_security_incident(db, alert):
            projected += 1

    await db.system_migrations.update_one(
        {"migration_id": migration_id},
        {
            "$set": {
                "migration_id": migration_id,
                "status": "complete",
                "scanned": scanned,
                "projected": projected,
                "completed_at": datetime.now(timezone.utc),
            }
        },
        upsert=True,
    )
    return {"scanned": scanned, "projected": projected}

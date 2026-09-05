"""Tenant-scoped Security Story signals and deterministic projections.

Security Stories are mutable operational interpretations. Canonical events,
detections, incidents, PECA/FBR evidence, and custody cases remain independent
sources of truth and are never modified here.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.config.config import get_settings


STORY_SCHEMA_VERSION = "warsoc-security-story-v1"
SIGNAL_SCHEMA_VERSION = "warsoc-story-signal-v1"
STORY_RULE_VERSION = "1"
STORY_SIGNAL_GROUP = "security_story_group"
STORY_SIGNAL_CONSUMER = "security_story_worker_1"

OPEN_STORY_STATUSES = ("OPEN", "ACKNOWLEDGED")
VISIBLE_STORY_STATUSES = ("CANDIDATE", "OPEN", "ACKNOWLEDGED", "CLOSED")
REMOTE_LOGON_TYPES = {"3", "10"}
ALLOWED_NETWORK_ACTIONS = {"allow", "allowed", "accept", "accepted", "pass", "passed"}
SYSTEM_IDENTITIES = {
    "system",
    "local service",
    "network service",
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
}
SIGNAL_TYPES_BY_EVENT = {
    "1102": "audit_log_cleared",
    "4624": "successful_login",
    "4625": "failed_login",
    "4672": "privileged_session",
    "4688": "process_execution",
    "4697": "service_persistence",
    "4698": "scheduled_task_persistence",
    "4719": "audit_policy_changed",
    "7045": "service_persistence",
}
MAX_STORY_TIMELINE_ITEMS = 50
MAX_STORY_ASSETS = 20
MAX_STORY_REASON_CODES = 20
MAX_STORY_WORKFLOW_ITEMS = 50
MAX_SIGNAL_TEXT = 240
SIGNAL_RECHECK_DELAYS = (15, 60)

_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_CRITICALITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def security_stories_enabled() -> bool:
    return bool(get_settings().security_stories_enabled)


def _text(value: Any, *, limit: int = MAX_SIGNAL_TEXT) -> str:
    return " ".join(str(value or "").split())[:limit]


def _normalized(value: Any) -> str:
    return _text(value).casefold()


def _coerce_datetime(value: Any, *, default_now: bool = True) -> datetime | None:
    if isinstance(value, datetime):
        result = value
    else:
        try:
            result = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return datetime.now(timezone.utc) if default_now else None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def _safe_ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(_text(value, limit=64)))
    except ValueError:
        return ""


def _is_private_asset_ip(value: Any) -> bool:
    try:
        address = ipaddress.ip_address(_text(value, limit=64))
    except ValueError:
        return False
    return bool(address.is_private and not address.is_loopback and not address.is_unspecified)


def _is_public_ip(value: Any) -> bool:
    try:
        address = ipaddress.ip_address(_text(value, limit=64))
    except ValueError:
        return False
    return bool(address.is_global)


def _safe_identifier(value: Any, *, limit: int = 200) -> str:
    token = _text(value, limit=limit)
    return token if token and all(ord(char) >= 32 for char in token) else ""


def normalize_identity(value: Any) -> str:
    identity = _normalized(value)
    if identity in {"", "-", "unknown", "anonymous logon", "network_device"}:
        return ""
    return identity[:200]


def classify_account(value: Any) -> str:
    identity = normalize_identity(value)
    if not identity:
        return "UNKNOWN"
    if identity in SYSTEM_IDENTITIES or identity.startswith("nt authority\\"):
        return "SYSTEM"
    if identity.endswith("$"):
        return "MACHINE"
    if identity.startswith(("nt service\\", "iis apppool\\")):
        return "SERVICE"
    return "UNKNOWN"


def _logon_id(value: Any) -> str:
    token = _normalized(value)
    if not token or len(token) > 32 or not re.fullmatch(r"(?:0x)?[0-9a-f]+", token):
        return ""
    return token


def _severity(value: Any, default: str = "MEDIUM") -> str:
    normalized = _text(value).upper()
    aliases = {"INFO": "LOW", "INFORMATIONAL": "LOW", "WARNING": "MEDIUM", "ALERT": "HIGH"}
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in _SEVERITY_RANK else default


def _criticality(value: Any) -> str:
    normalized = _normalized(value)
    return normalized if normalized in _CRITICALITY_RANK else "medium"


def _command_fingerprint(value: Any) -> str:
    command = _normalized(value)
    return hashlib.sha256(command.encode("utf-8")).hexdigest()[:20] if command else ""


def _signal_type(event_id: str, event_type: str, *, is_network: bool = False) -> str:
    # Windows Filtering Platform events (5156/5157) share these event_type
    # strings with relay firewall evidence. Only network-device evidence may
    # become an egress signal; host observations are not egress proof.
    if is_network:
        if event_type == "network_connection_permitted":
            return "allowed_egress"
        if event_type == "network_connection_blocked":
            return "blocked_connection"
    return SIGNAL_TYPES_BY_EVENT.get(event_id, "context_event")


def _asset_context(agent: Mapping[str, Any] | None, agent_id: str, endpoint_name: str) -> dict[str, Any]:
    agent = agent or {}
    is_server = bool(
        agent.get("asset_class") == "server"
        or agent.get("server_monitoring_required")
        or agent.get("monitoring_assignment")
    )
    return {
        "asset_id": agent_id,
        "name": _text(agent.get("endpoint_name") or endpoint_name or agent_id),
        "asset_class": "server" if is_server else _text(agent.get("asset_class") or "workstation", limit=32).lower(),
        "server_role": _text(agent.get("server_role"), limit=64) or None,
        "criticality": _criticality(agent.get("criticality")),
        "environment": _text(agent.get("environment"), limit=32) or None,
    }


async def _load_agent_context(db, tenant_id: str, agent_id: str) -> dict[str, Any] | None:
    if not tenant_id or not agent_id or agent_id.startswith("WARSOC_RELAY_"):
        return None
    return await db.agents.find_one(
        {"tenant_id": tenant_id, "agent_id": agent_id},
        {
            "_id": 0,
            "agent_id": 1,
            "endpoint_name": 1,
            "asset_class": 1,
            "server_role": 1,
            "criticality": 1,
            "environment": 1,
            "server_monitoring_required": 1,
            "monitoring_assignment": 1,
        },
    )


async def build_event_story_signal(db, event: Mapping[str, Any]) -> dict[str, Any] | None:
    tenant_id = _safe_identifier(event.get("tenant_id"), limit=128)
    event_uid = _safe_identifier(event.get("event_uid"), limit=240)
    if not tenant_id or not event_uid:
        return None

    processed = event.get("processed_data") if isinstance(event.get("processed_data"), Mapping) else {}
    raw_event = event.get("raw_event_data") if isinstance(event.get("raw_event_data"), Mapping) else {}
    system = raw_event.get("system") if isinstance(raw_event.get("system"), Mapping) else {}
    event_id = _safe_identifier(event.get("event_id"), limit=32)
    event_type = _normalized(event.get("event_type"))
    source_type = _normalized(event.get("source_type") or "windows_endpoint")
    is_network = source_type == "network_device"
    agent_id = _safe_identifier(event.get("agent_id"), limit=128)
    endpoint_name = _text(processed.get("computer") or system.get("computer") or agent_id)
    agent = await _load_agent_context(db, tenant_id, agent_id)

    if is_network:
        device_id = _safe_identifier(event.get("network_device_id") or event.get("source_id"), limit=64)
        asset = {
            "asset_id": f"network:{device_id}" if device_id else f"relay:{agent_id}",
            "name": device_id or "Network device",
            "asset_class": "network_device",
            "server_role": None,
            "criticality": "high",
            "environment": None,
        }
    else:
        asset = _asset_context(agent, agent_id, endpoint_name)

    if event_id in {"4624", "4625"}:
        identity_value = processed.get("target_user") or event.get("user")
    else:
        identity_value = processed.get("user") or event.get("user") or processed.get("target_user")

    source_ip = _safe_ip(
        processed.get("source_network_address")
        or processed.get("src_ip")
        or event.get("source_ip")
    )
    destination_ip = _safe_ip(
        processed.get("destination_address")
        or processed.get("dst_ip")
    )
    signal_type = _signal_type(event_id, event_type, is_network=is_network)
    if signal_type == "context_event" or signal_type == "blocked_connection":
        return None
    identity = normalize_identity(identity_value)
    event_time = _coerce_datetime(event.get("timestamp") or event.get("ingested_at"))
    signal = {
        "schema_version": SIGNAL_SCHEMA_VERSION,
        "signal_type": signal_type,
        "tenant_id": tenant_id,
        "event_uid": event_uid,
        "event_id": event_id,
        "event_time": event_time,
        "source_family": "network" if is_network else "windows",
        "source_assurance": _text(event.get("source_assurance") or ("relay_attested" if is_network else "agent_signed"), limit=64),
        "asset": asset,
        "identity": identity,
        "account_type": classify_account(identity),
        "source_ip": source_ip,
        "source_port": _safe_identifier(processed.get("source_port") or processed.get("src_port"), limit=16),
        "destination_ip": destination_ip,
        "destination_port": _safe_identifier(processed.get("destination_port") or processed.get("dst_port"), limit=16),
        "protocol": _text(processed.get("protocol"), limit=32).lower(),
        "network_action": _text(processed.get("action"), limit=32).lower(),
        "network_direction": _text(processed.get("direction"), limit=16).lower(),
        "logon_type": _safe_identifier(processed.get("logon_type"), limit=8),
        "target_logon_id": _logon_id(processed.get("target_logon_id") or processed.get("TargetLogonId")),
        "subject_logon_id": _logon_id(processed.get("subject_logon_id") or processed.get("SubjectLogonId")),
        "process_name": _text(processed.get("new_process_name") or processed.get("process_name")),
        "parent_process": _text(processed.get("parent_process_name")),
        "command_fingerprint": _command_fingerprint(processed.get("command_line")),
        "service_name": _text(processed.get("service_name")),
        "task_name": _text(processed.get("task_name")),
        "actionable": False,
        "technical_severity": "LOW",
        "summary": _text(event.get("event_id_meaning") or event.get("message") or signal_type.replace("_", " ")),
        "network_device_id": _safe_identifier(event.get("network_device_id"), limit=64),
        "network_vendor": _text(event.get("network_vendor"), limit=32).lower(),
    }
    return {key: value for key, value in signal.items() if value not in (None, "")}


async def build_incident_story_signal(
    db,
    incident: Mapping[str, Any],
    source: Mapping[str, Any],
    *,
    occurrence_uid: str,
) -> dict[str, Any] | None:
    tenant_id = _safe_identifier(incident.get("tenant_id") or source.get("tenant_id"), limit=128)
    incident_id = _safe_identifier(incident.get("incident_id"), limit=100)
    if not tenant_id or not incident_id or not occurrence_uid:
        return None
    if bool(incident.get("suppressed")) or _text(incident.get("status")).upper() == "FALSE_POSITIVE":
        return None

    context = source.get("context") if isinstance(source.get("context"), Mapping) else {}
    incident_context = incident.get("context") if isinstance(incident.get("context"), Mapping) else {}
    merged = {**incident_context, **context}
    event_id = _safe_identifier(source.get("event_id") or incident.get("event_id"), limit=32)
    event_uid = _safe_identifier(source.get("event_uid") or merged.get("event_uid"), limit=240)
    agent_id = _safe_identifier(source.get("agent_id") or merged.get("agent_id"), limit=128)
    endpoint_name = _text(source.get("computer") or merged.get("endpoint") or agent_id)
    agent = await _load_agent_context(db, tenant_id, agent_id)
    asset = _asset_context(agent, agent_id, endpoint_name)
    identity = normalize_identity(
        merged.get("actor") or merged.get("user") or source.get("user") or merged.get("target_user")
    )
    event_time = _coerce_datetime(
        source.get("timestamp") or incident.get("last_seen") or incident.get("first_seen")
    )
    signal = {
        "schema_version": SIGNAL_SCHEMA_VERSION,
        "signal_type": _signal_type(event_id, _normalized(source.get("event_type"))),
        "tenant_id": tenant_id,
        "event_uid": event_uid,
        "event_id": event_id,
        "event_time": event_time,
        "source_family": "detection",
        "source_assurance": "warsoc_incident",
        "asset": asset,
        "identity": identity,
        "account_type": classify_account(identity),
        "source_ip": _safe_ip(merged.get("source_address") or source.get("source_ip")),
        "destination_ip": _safe_ip(merged.get("destination_address")),
        "logon_type": _safe_identifier(merged.get("logon_type"), limit=8),
        "target_logon_id": _logon_id(merged.get("target_logon_id")),
        "subject_logon_id": _logon_id(merged.get("subject_logon_id")),
        "process_name": _text(merged.get("process_name")),
        "parent_process": _text(merged.get("parent_process")),
        "command_fingerprint": _command_fingerprint(merged.get("command_line")),
        "actionable": True,
        "technical_severity": _severity(incident.get("severity") or source.get("severity")),
        "summary": _text(incident.get("title") or source.get("summary") or "WarSOC detection"),
        "rule_id": _safe_identifier(incident.get("rule_id") or source.get("rule_id") or source.get("type"), limit=160),
        "incident_id": incident_id,
        "occurrence_uid": occurrence_uid,
    }
    return {key: value for key, value in signal.items() if value not in (None, "")}


async def enqueue_story_signal(
    db,
    *,
    source_type: str,
    source_uid: str,
    signal: Mapping[str, Any],
    delay_seconds: int = 0,
) -> bool:
    if not security_stories_enabled():
        return False
    tenant_id = _safe_identifier(signal.get("tenant_id"), limit=128)
    source_type = _safe_identifier(source_type, limit=32).lower()
    source_uid = _safe_identifier(source_uid, limit=240)
    if not tenant_id or source_type not in {"event", "incident"} or not source_uid:
        raise ValueError("Security Story signal identity is incomplete")
    if signal.get("schema_version") != SIGNAL_SCHEMA_VERSION:
        raise ValueError("Security Story signal schema is invalid")

    settings = get_settings()
    now = datetime.now(timezone.utc)
    document = {
        "tenant_id": tenant_id,
        "source_type": source_type,
        "source_uid": source_uid,
        "signal": dict(signal),
        "status": "PENDING",
        "attempt_count": 0,
        "recheck_count": 0,
        "next_attempt_at": now + timedelta(seconds=max(0, min(delay_seconds, 300))),
        "created_at": now,
        "updated_at": now,
        "expires_at": now + timedelta(days=settings.security_story_signal_retention_days),
    }
    result = await db.story_signal_ledger.update_one(
        {"tenant_id": tenant_id, "source_type": source_type, "source_uid": source_uid},
        {"$setOnInsert": document},
        upsert=True,
    )
    return result.upserted_id is not None


async def enqueue_incident_story_signal(
    db,
    incident: Mapping[str, Any],
    source: Mapping[str, Any],
    *,
    occurrence_uid: str,
) -> bool:
    signal = await build_incident_story_signal(
        db, incident, source, occurrence_uid=occurrence_uid
    )
    if signal is None:
        return False
    return await enqueue_story_signal(
        db,
        source_type="incident",
        source_uid=occurrence_uid,
        signal=signal,
    )


async def claim_story_signal(db) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc)
    lease_id = uuid.uuid4().hex
    return await db.story_signal_ledger.find_one_and_update(
        {
            "$or": [
                {"status": {"$in": ["PENDING", "RETRY"]}, "next_attempt_at": {"$lte": now}},
                {"status": "PROCESSING", "lease_until": {"$lte": now}},
            ]
        },
        {
            "$set": {
                "status": "PROCESSING",
                "lease_id": lease_id,
                "lease_until": now + timedelta(seconds=60),
                "updated_at": now,
            },
            "$inc": {"attempt_count": 1},
        },
        sort=[("next_attempt_at", 1), ("_id", 1)],
        return_document=ReturnDocument.AFTER,
    )


async def complete_story_signal(db, document: Mapping[str, Any], story_ids: Iterable[str]) -> None:
    now = datetime.now(timezone.utc)
    recheck_count = int(document.get("recheck_count") or 0)
    source_type = str(document.get("source_type") or "")
    should_recheck = source_type == "event" and recheck_count < len(SIGNAL_RECHECK_DELAYS)
    update: dict[str, Any] = {
        "$set": {
            "status": "PENDING" if should_recheck else "PROCESSED",
            "story_ids": list(dict.fromkeys(str(value) for value in story_ids if value))[:20],
            "processed_at": now,
            "updated_at": now,
        },
        "$unset": {"lease_id": "", "lease_until": "", "last_error_code": ""},
    }
    if should_recheck:
        update["$set"]["next_attempt_at"] = now + timedelta(seconds=SIGNAL_RECHECK_DELAYS[recheck_count])
        update["$inc"] = {"recheck_count": 1}
    await db.story_signal_ledger.update_one(
        {"_id": document["_id"], "lease_id": document.get("lease_id")}, update
    )


async def fail_story_signal(db, document: Mapping[str, Any], exc: Exception) -> None:
    settings = get_settings()
    attempts = int(document.get("attempt_count") or 1)
    failed = attempts >= settings.security_story_max_attempts
    now = datetime.now(timezone.utc)
    await db.story_signal_ledger.update_one(
        {"_id": document["_id"], "lease_id": document.get("lease_id")},
        {
            "$set": {
                "status": "FAILED" if failed else "RETRY",
                "next_attempt_at": now + timedelta(seconds=min(300, 2 ** min(attempts, 8))),
                "last_error_code": type(exc).__name__[:100],
                "updated_at": now,
            },
            "$unset": {"lease_id": "", "lease_until": ""},
        },
    )


async def record_asset_ip_binding(db, signal: Mapping[str, Any]) -> None:
    if signal.get("source_family") != "windows":
        return
    event_id = str(signal.get("event_id") or "")
    if event_id in {"4624", "4625", "4648", "4768", "4769", "4776", "5140", "5156", "5157"}:
        return
    source_ip = _safe_ip(signal.get("source_ip"))
    asset = signal.get("asset") if isinstance(signal.get("asset"), Mapping) else {}
    asset_id = _safe_identifier(asset.get("asset_id"), limit=128)
    tenant_id = _safe_identifier(signal.get("tenant_id"), limit=128)
    event_time = _coerce_datetime(signal.get("event_time"))
    if not tenant_id or not asset_id or not _is_private_asset_ip(source_ip) or event_time is None:
        return
    settings = get_settings()
    await db.asset_ip_bindings.update_one(
        {"tenant_id": tenant_id, "asset_id": asset_id, "ip_address": source_ip},
        {
            "$setOnInsert": {
                "tenant_id": tenant_id,
                "asset_id": asset_id,
                "ip_address": source_ip,
                "created_at": datetime.now(timezone.utc),
            },
            "$min": {"first_seen": event_time},
            "$max": {"last_seen": event_time},
            "$set": {
                "asset_name": _text(asset.get("name")),
                "asset_class": _text(asset.get("asset_class"), limit=32).lower(),
                "criticality": _criticality(asset.get("criticality")),
                "expires_at": datetime.now(timezone.utc)
                + timedelta(days=settings.security_story_signal_retention_days),
            },
        },
        upsert=True,
    )


async def resolve_asset_for_ip(
    db,
    tenant_id: str,
    ip_address: str,
    event_time: datetime,
    *,
    freshness_seconds: int = 3600,
) -> dict[str, Any] | None:
    if not _is_private_asset_ip(ip_address):
        return None
    rows = await db.asset_ip_bindings.find(
        {
            "tenant_id": tenant_id,
            "ip_address": ip_address,
            "first_seen": {"$lte": event_time + timedelta(minutes=5)},
            "last_seen": {"$gte": event_time - timedelta(seconds=freshness_seconds)},
        }
    ).sort("last_seen", -1).limit(3).to_list(length=3)
    asset_ids = {str(row.get("asset_id") or "") for row in rows if row.get("asset_id")}
    if len(asset_ids) != 1:
        return None
    return rows[0]


async def _recent_signals(
    db,
    tenant_id: str,
    signal_types: Iterable[str],
    start: datetime,
    end: datetime,
    *,
    asset_id: str | None = None,
    actionable: bool | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    query: dict[str, Any] = {
        "tenant_id": tenant_id,
        "status": {"$ne": "FAILED"},
        "signal.signal_type": {"$in": list(signal_types)},
        "signal.event_time": {"$gte": start, "$lte": end},
    }
    if asset_id:
        query["signal.asset.asset_id"] = asset_id
    if actionable is not None:
        query["signal.actionable"] = actionable
    rows = await db.story_signal_ledger.find(query).sort("signal.event_time", 1).limit(limit).to_list(length=limit)
    return _collapse_signals(rows)


def _collapse_signals(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    collapsed: dict[str, dict[str, Any]] = {}
    for row in rows:
        signal = dict(row.get("signal") or {})
        key = str(signal.get("event_uid") or f"{row.get('source_type')}:{row.get('source_uid')}")
        if not key:
            continue
        signal.setdefault("_source_uids", [])
        signal["_source_uids"].append(str(row.get("source_uid") or ""))
        existing = collapsed.get(key)
        if existing is None:
            collapsed[key] = signal
            continue
        for field, value in signal.items():
            if value not in (None, "", [], {}) and (
                field not in existing or existing.get(field) in (None, "", [], {}) or field == "actionable"
            ):
                existing[field] = value
        existing["actionable"] = bool(existing.get("actionable") or signal.get("actionable"))
        existing["technical_severity"] = max(
            (_severity(existing.get("technical_severity")), _severity(signal.get("technical_severity"))),
            key=lambda item: _SEVERITY_RANK[item],
        )
        existing["_source_uids"] = list(
            dict.fromkeys([*existing.get("_source_uids", []), *signal.get("_source_uids", [])])
        )
    return sorted(collapsed.values(), key=lambda item: _coerce_datetime(item.get("event_time")) or datetime.min.replace(tzinfo=timezone.utc))


def _same_identity(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return bool(left.get("identity") and left.get("identity") == right.get("identity"))


def _matching_session(login: Mapping[str, Any], other: Mapping[str, Any]) -> bool:
    target = _logon_id(login.get("target_logon_id"))
    subject = _logon_id(other.get("subject_logon_id"))
    return bool(target and subject and target == subject)


def _event_time(signal: Mapping[str, Any]) -> datetime:
    return _coerce_datetime(
        signal.get("event_time") or signal.get("timestamp")
    ) or datetime.now(timezone.utc)


def _asset(signal: Mapping[str, Any]) -> dict[str, Any]:
    value = signal.get("asset") if isinstance(signal.get("asset"), Mapping) else {}
    return {
        "asset_id": _text(value.get("asset_id"), limit=128),
        "name": _text(value.get("name")),
        "asset_class": _text(value.get("asset_class"), limit=32).lower(),
        "server_role": _text(value.get("server_role"), limit=64) or None,
        "criticality": _criticality(value.get("criticality")),
        "environment": _text(value.get("environment"), limit=32) or None,
    }


def _unique_objects(values: Iterable[Mapping[str, Any]], key: str, limit: int) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in values:
        identity = _text(value.get(key), limit=240)
        if not identity or identity in seen:
            continue
        seen.add(identity)
        result.append({field: item for field, item in dict(value).items() if item not in (None, "")})
        if len(result) >= limit:
            break
    return result


def _timeline_item(signal: Mapping[str, Any], phase: str, summary: str | None = None) -> dict[str, Any]:
    return {
        "phase": phase,
        "timestamp": _event_time(signal),
        "summary": _text(summary or signal.get("summary") or signal.get("signal_type")),
        "event_uid": _text(signal.get("event_uid"), limit=240) or None,
        "incident_id": _text(signal.get("incident_id"), limit=100) or None,
        "asset_id": _text(_asset(signal).get("asset_id"), limit=128) or None,
    }


def _story_refs(signals: Iterable[Mapping[str, Any]]) -> tuple[list[dict], list[dict], list[str]]:
    event_refs = []
    incident_refs = []
    signal_refs = []
    for signal in signals:
        if signal.get("event_uid"):
            event_refs.append({
                "event_uid": _text(signal.get("event_uid"), limit=240),
                "event_id": _text(signal.get("event_id"), limit=32),
                "timestamp": _event_time(signal),
            })
        if signal.get("incident_id"):
            incident_refs.append({
                "incident_id": _text(signal.get("incident_id"), limit=100),
                "event_uid": _text(signal.get("event_uid"), limit=240) or None,
            })
        signal_refs.extend(_text(value, limit=240) for value in signal.get("_source_uids", []) if value)
    limit = get_settings().security_story_max_references
    return (
        _unique_objects(event_refs, "event_uid", limit),
        _unique_objects(incident_refs, "incident_id", limit),
        list(dict.fromkeys(signal_refs))[:limit],
    )


def _story_id(tenant_id: str, story_type: str, *identity: Any) -> str:
    material = "|".join([tenant_id, story_type, *(_normalized(value) for value in identity)])
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:24].upper()
    return f"STORY-{digest}"


def _max_severity(signals: Iterable[Mapping[str, Any]], default: str = "HIGH") -> str:
    values = [_severity(signal.get("technical_severity")) for signal in signals if signal.get("actionable")]
    return max(values, key=lambda item: _SEVERITY_RANK[item]) if values else default


def _business_values(assets: Iterable[Mapping[str, Any]], technical_severity: str) -> tuple[str, str]:
    criticality = max(
        (_criticality(asset.get("criticality")) for asset in assets),
        key=lambda item: _CRITICALITY_RANK[item],
        default="medium",
    )
    severity_rank = _SEVERITY_RANK[_severity(technical_severity)]
    criticality_rank = _CRITICALITY_RANK[criticality]
    if severity_rank >= 4 or (severity_rank >= 3 and criticality_rank >= 4):
        priority = "URGENT"
    elif severity_rank >= 3 or criticality_rank >= 4:
        priority = "HIGH"
    elif severity_rank >= 2 or criticality_rank >= 3:
        priority = "MEDIUM"
    else:
        priority = "LOW"
    impact = "HIGH" if criticality_rank >= 4 else "MEDIUM" if criticality_rank >= 3 else "LOW"
    return impact, priority


def _projection_hash(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


async def upsert_security_story(db, payload: Mapping[str, Any]) -> dict[str, Any]:
    tenant_id = _safe_identifier(payload.get("tenant_id"), limit=128)
    story_id = _safe_identifier(payload.get("story_id"), limit=100)
    if not tenant_id or not story_id:
        raise ValueError("Security Story identity is incomplete")

    assets = _unique_objects(payload.get("affected_assets") or [], "asset_id", MAX_STORY_ASSETS)
    event_refs = _unique_objects(
        payload.get("event_refs") or [], "event_uid", get_settings().security_story_max_references
    )
    incident_refs = _unique_objects(
        payload.get("incident_refs") or [], "incident_id", get_settings().security_story_max_references
    )
    network_refs = _unique_objects(
        payload.get("network_refs") or [], "event_uid", get_settings().security_story_max_references
    )
    timeline = sorted(
        list(payload.get("timeline") or []), key=lambda item: _event_time(item)
    )[-MAX_STORY_TIMELINE_ITEMS:]
    confidence = _text(payload.get("technical_confidence"), limit=16).upper()
    if confidence not in {"MEDIUM", "HIGH"}:
        raise ValueError("Security Story confidence must be MEDIUM or HIGH")
    severity = _severity(payload.get("technical_severity"))
    impact, priority = _business_values(assets, severity)
    first_seen = min((_event_time(item) for item in timeline), default=datetime.now(timezone.utc))
    last_seen = max((_event_time(item) for item in timeline), default=first_seen)
    projection = {
        "schema_version": STORY_SCHEMA_VERSION,
        "story_rule_version": STORY_RULE_VERSION,
        "story_type": _safe_identifier(payload.get("story_type"), limit=80),
        "title": _text(payload.get("title")),
        "technical_confidence": confidence,
        "technical_severity": severity,
        "business_impact": impact,
        "attention_priority": priority,
        "primary_identity": normalize_identity(payload.get("primary_identity")) or None,
        "primary_account_type": _text(payload.get("primary_account_type"), limit=16).upper() or "UNKNOWN",
        "affected_assets": assets,
        "affected_asset_ids": [asset["asset_id"] for asset in assets],
        "source_assets": _unique_objects(payload.get("source_assets") or [], "asset_id", MAX_STORY_ASSETS),
        "destination_assets": _unique_objects(payload.get("destination_assets") or [], "asset_id", MAX_STORY_ASSETS),
        "event_refs": event_refs,
        "incident_refs": incident_refs,
        "network_refs": network_refs,
        "signal_refs": list(dict.fromkeys(str(value) for value in payload.get("signal_refs") or []))[
            : get_settings().security_story_max_references
        ],
        "reason_codes": list(dict.fromkeys(_safe_identifier(value, limit=80) for value in payload.get("reason_codes") or [] if value))[
            :MAX_STORY_REASON_CODES
        ],
        "confidence_reasons": list(dict.fromkeys(_text(value) for value in payload.get("confidence_reasons") or [] if value))[
            :MAX_STORY_REASON_CODES
        ],
        "correlation_gaps": list(dict.fromkeys(_text(value) for value in payload.get("correlation_gaps") or [] if value))[
            :MAX_STORY_REASON_CODES
        ],
        "timeline": timeline,
        "linked_story_ids": list(dict.fromkeys(_safe_identifier(value, limit=100) for value in payload.get("linked_story_ids") or [] if value))[:20],
        "first_seen": first_seen,
        "last_seen": last_seen,
        "evidence_state": "SOURCE_REFERENCED",
        "event_reference_count": len(event_refs),
        "incident_reference_count": len(incident_refs),
        "network_reference_count": len(network_refs),
        "reference_limit": get_settings().security_story_max_references,
    }
    projection_hash = _projection_hash(projection)
    now = datetime.now(timezone.utc)

    for _ in range(3):
        existing = await db.security_stories.find_one({"tenant_id": tenant_id, "story_id": story_id})
        if existing and existing.get("projection_hash") == projection_hash:
            return existing
        if existing:
            version = int(existing.get("version") or 1)
            status = str(existing.get("status") or "CANDIDATE")
            if status == "CANDIDATE" and confidence == "HIGH":
                status = "OPEN"
            update = {
                "$set": {
                    **projection,
                    "status": status,
                    "projection_hash": projection_hash,
                    "has_new_activity": status == "CLOSED",
                    "updated_at": now,
                    "version": version + 1,
                }
            }
            result = await db.security_stories.update_one(
                {"_id": existing["_id"], "version": version}, update
            )
            if result.modified_count:
                return await db.security_stories.find_one({"_id": existing["_id"]})
            continue

        document = {
            "tenant_id": tenant_id,
            "story_id": story_id,
            "record_type": "security_story",
            "status": "OPEN" if confidence == "HIGH" else "CANDIDATE",
            "version": 1,
            "workflow_history": [],
            "projection_hash": projection_hash,
            "has_new_activity": False,
            "created_at": now,
            "updated_at": now,
            **projection,
        }
        try:
            await db.security_stories.insert_one(document)
            return document
        except DuplicateKeyError:
            continue
    raise RuntimeError("Security Story update conflicted repeatedly")


def _asset_list(signals: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [_asset(signal) for signal in signals if _asset(signal).get("asset_id")]


async def _server_account_compromise(db, current: Mapping[str, Any]) -> list[dict[str, Any]]:
    if current.get("signal_type") not in {"successful_login", "privileged_session"}:
        return []
    current_asset = _asset(current)
    if current_asset.get("asset_class") != "server":
        return []
    tenant_id = str(current.get("tenant_id") or "")
    now = _event_time(current)
    successes = [current] if current.get("signal_type") == "successful_login" else await _recent_signals(
        db, tenant_id, ["successful_login"], now - timedelta(minutes=5), now,
        asset_id=current_asset["asset_id"], limit=50,
    )
    stories = []
    for success in successes:
        if str(success.get("logon_type") or "") not in REMOTE_LOGON_TYPES:
            continue
        identity = str(success.get("identity") or "")
        source_ip = str(success.get("source_ip") or "")
        if not identity or not source_ip or classify_account(identity) in {"SYSTEM", "MACHINE"}:
            continue
        success_time = _event_time(success)
        failures = await _recent_signals(
            db, tenant_id, ["failed_login"], success_time - timedelta(minutes=10), success_time,
            asset_id=current_asset["asset_id"], limit=200,
        )
        failures = [
            item for item in failures
            if item.get("identity") == identity and item.get("source_ip") == source_ip
            and str(item.get("logon_type") or "") in REMOTE_LOGON_TYPES
        ]
        if len(failures) < 10:
            continue
        privileges = await _recent_signals(
            db, tenant_id, ["privileged_session"], success_time, success_time + timedelta(minutes=5),
            asset_id=current_asset["asset_id"], limit=50,
        )
        privilege = next(
            (item for item in privileges if _same_identity(success, item) and _matching_session(success, item)),
            None,
        )
        signals = [*failures, success, *([privilege] if privilege else [])]
        event_refs, incident_refs, signal_refs = _story_refs(signals)
        source_binding = await resolve_asset_for_ip(db, tenant_id, source_ip, success_time)
        source_assets = []
        if source_binding:
            source_assets.append({
                "asset_id": source_binding.get("asset_id"),
                "name": source_binding.get("asset_name"),
                "asset_class": source_binding.get("asset_class"),
                "criticality": source_binding.get("criticality"),
            })
        timeline = [
            _timeline_item(failures[0], "AUTHENTICATION_FAILURES", f"{len(failures)} failed remote logins"),
            _timeline_item(success, "SUCCESSFUL_REMOTE_ACCESS"),
        ]
        if privilege:
            timeline.append(_timeline_item(privilege, "PRIVILEGED_SESSION"))
        stories.append({
            "tenant_id": tenant_id,
            "story_id": _story_id(tenant_id, "SERVER_ACCOUNT_COMPROMISE", success.get("event_uid")),
            "story_type": "SERVER_ACCOUNT_COMPROMISE",
            "title": "Possible server account compromise",
            "technical_confidence": "HIGH",
            "technical_severity": _max_severity(signals, "HIGH"),
            "primary_identity": identity,
            "primary_account_type": classify_account(identity),
            "affected_assets": [current_asset, *source_assets],
            "source_assets": source_assets,
            "destination_assets": [current_asset],
            "event_refs": event_refs,
            "incident_refs": incident_refs,
            "signal_refs": signal_refs,
            "reason_codes": ["REPEATED_REMOTE_FAILURES", "SUBSEQUENT_REMOTE_SUCCESS"]
            + (["MATCHED_PRIVILEGED_SESSION"] if privilege else []),
            "confidence_reasons": ["Same tenant, server, account and source address within ten minutes"],
            "correlation_gaps": [] if source_binding else ["Source address is not mapped to a fresh managed asset"],
            "timeline": timeline,
        })
    return stories


async def _server_persistence(db, current: Mapping[str, Any]) -> list[dict[str, Any]]:
    if current.get("signal_type") not in {"service_persistence", "scheduled_task_persistence"}:
        return []
    server = _asset(current)
    if server.get("asset_class") != "server":
        return []
    tenant_id = str(current.get("tenant_id") or "")
    end = _event_time(current)
    logins = await _recent_signals(
        db, tenant_id, ["successful_login"], end - timedelta(minutes=20), end,
        asset_id=server["asset_id"], limit=100,
    )
    stories = []
    for login in reversed(logins):
        if str(login.get("logon_type") or "") not in REMOTE_LOGON_TYPES or not login.get("identity"):
            continue
        processes = await _recent_signals(
            db, tenant_id, ["process_execution"], _event_time(login), end,
            asset_id=server["asset_id"], actionable=True, limit=100,
        )
        processes = [item for item in processes if _same_identity(login, item)]
        if not processes:
            continue
        process = processes[-1]
        session_match = _matching_session(login, process)
        persistence_session = _logon_id(current.get("subject_logon_id"))
        if persistence_session and _logon_id(login.get("target_logon_id")):
            session_match = session_match and persistence_session == _logon_id(login.get("target_logon_id"))
        confidence = "HIGH" if session_match else "MEDIUM"
        signals = [login, process, current]
        event_refs, incident_refs, signal_refs = _story_refs(signals)
        source_binding = await resolve_asset_for_ip(
            db, tenant_id, str(login.get("source_ip") or ""), _event_time(login)
        )
        source_assets = []
        if source_binding:
            source_assets.append({
                "asset_id": source_binding.get("asset_id"),
                "name": source_binding.get("asset_name"),
                "asset_class": source_binding.get("asset_class"),
                "criticality": source_binding.get("criticality"),
            })
        stories.append({
            "tenant_id": tenant_id,
            "story_id": _story_id(tenant_id, "SERVER_COMPROMISE_PERSISTENCE", login.get("event_uid"), current.get("event_uid")),
            "story_type": "SERVER_COMPROMISE_PERSISTENCE",
            "title": "Possible server compromise followed by persistence",
            "technical_confidence": confidence,
            "technical_severity": _max_severity(signals, "HIGH"),
            "primary_identity": login.get("identity"),
            "primary_account_type": classify_account(login.get("identity")),
            "affected_assets": [server, *source_assets],
            "source_assets": source_assets,
            "destination_assets": [server],
            "event_refs": event_refs,
            "incident_refs": incident_refs,
            "signal_refs": signal_refs,
            "reason_codes": ["REMOTE_ACCESS", "SUSPICIOUS_EXECUTION", "PERSISTENCE_CREATED"],
            "confidence_reasons": ["Exact logon-session continuity"] if session_match else ["Same tenant, server and account with bounded chronology"],
            "correlation_gaps": [] if session_match else ["Exact Windows logon-session linkage is unavailable"],
            "timeline": [
                _timeline_item(login, "SUCCESSFUL_REMOTE_ACCESS"),
                _timeline_item(process, "SUSPICIOUS_EXECUTION"),
                _timeline_item(current, "PERSISTENCE"),
            ],
        })
        break
    return stories


async def _server_anti_forensics(db, current: Mapping[str, Any]) -> list[dict[str, Any]]:
    if current.get("signal_type") not in {"audit_policy_changed", "audit_log_cleared"}:
        return []
    server = _asset(current)
    if server.get("asset_class") != "server":
        return []
    tenant_id = str(current.get("tenant_id") or "")
    end = _event_time(current)
    suspicious = await _recent_signals(
        db,
        tenant_id,
        ["process_execution", "service_persistence", "scheduled_task_persistence", "privileged_session"],
        end - timedelta(minutes=30),
        end,
        asset_id=server["asset_id"],
        actionable=True,
        limit=100,
    )
    if not suspicious:
        return []
    prior = suspicious[-1]
    same_session = bool(
        _logon_id(current.get("subject_logon_id"))
        and _logon_id(current.get("subject_logon_id")) == _logon_id(prior.get("subject_logon_id"))
    )
    same_identity = _same_identity(current, prior)
    confidence = "HIGH" if same_session else "MEDIUM"
    signals = [prior, current]
    event_refs, incident_refs, signal_refs = _story_refs(signals)
    return [{
        "tenant_id": tenant_id,
        "story_id": _story_id(tenant_id, "SERVER_ANTI_FORENSICS", current.get("event_uid")),
        "story_type": "SERVER_ANTI_FORENSICS",
        "title": "Suspicious server activity followed by anti-forensics",
        "technical_confidence": confidence,
        "technical_severity": _max_severity(signals, "CRITICAL"),
        "primary_identity": current.get("identity") or prior.get("identity"),
        "primary_account_type": classify_account(current.get("identity") or prior.get("identity")),
        "affected_assets": [server],
        "source_assets": [],
        "destination_assets": [server],
        "event_refs": event_refs,
        "incident_refs": incident_refs,
        "signal_refs": signal_refs,
        "reason_codes": ["SUSPICIOUS_SERVER_ACTIVITY", "ANTI_FORENSICS_OBSERVED"],
        "confidence_reasons": ["Exact logon-session continuity"] if same_session else ["Same tenant and server with bounded chronology"],
        "correlation_gaps": [] if same_session else (["Identity differs across the observations"] if not same_identity else ["Exact Windows logon-session linkage is unavailable"]),
        "timeline": [
            _timeline_item(prior, "SUSPICIOUS_ACTIVITY"),
            _timeline_item(current, "ANTI_FORENSICS"),
        ],
    }]


async def _workstation_to_server(db, current: Mapping[str, Any]) -> list[dict[str, Any]]:
    server = _asset(current)
    if server.get("asset_class") != "server" or not current.get("actionable"):
        return []
    if current.get("signal_type") not in {"process_execution", "service_persistence", "scheduled_task_persistence"}:
        return []
    tenant_id = str(current.get("tenant_id") or "")
    end = _event_time(current)
    logins = await _recent_signals(
        db, tenant_id, ["successful_login"], end - timedelta(minutes=20), end,
        asset_id=server["asset_id"], limit=100,
    )
    stories = []
    for login in reversed(logins):
        if str(login.get("logon_type") or "") not in REMOTE_LOGON_TYPES:
            continue
        source_ip = str(login.get("source_ip") or "")
        binding = await resolve_asset_for_ip(db, tenant_id, source_ip, _event_time(login))
        if not binding or str(binding.get("asset_class") or "") != "workstation":
            continue
        workstation_id = str(binding.get("asset_id") or "")
        workstation_signals = await _recent_signals(
            db, tenant_id, ["process_execution"], _event_time(login) - timedelta(minutes=15), _event_time(login),
            asset_id=workstation_id, actionable=True, limit=100,
        )
        workstation_signals = [item for item in workstation_signals if _same_identity(item, login)]
        if not workstation_signals:
            continue
        workstation_signal = workstation_signals[-1]
        signals = [workstation_signal, login, current]
        event_refs, incident_refs, signal_refs = _story_refs(signals)
        workstation = {
            "asset_id": workstation_id,
            "name": binding.get("asset_name"),
            "asset_class": "workstation",
            "criticality": binding.get("criticality") or "medium",
        }
        stories.append({
            "tenant_id": tenant_id,
            "story_id": _story_id(tenant_id, "WORKSTATION_TO_SERVER_MOVEMENT", workstation_signal.get("event_uid"), login.get("event_uid"), server["asset_id"]),
            "story_type": "WORKSTATION_TO_SERVER_MOVEMENT",
            "title": "Possible workstation-to-server movement",
            "technical_confidence": "HIGH",
            "technical_severity": _max_severity(signals, "HIGH"),
            "primary_identity": login.get("identity"),
            "primary_account_type": classify_account(login.get("identity")),
            "affected_assets": [workstation, server],
            "source_assets": [workstation],
            "destination_assets": [server],
            "event_refs": event_refs,
            "incident_refs": incident_refs,
            "signal_refs": signal_refs,
            "reason_codes": ["SUSPICIOUS_WORKSTATION_EXECUTION", "FRESH_SOURCE_ASSET_IP_MATCH", "REMOTE_SERVER_LOGIN", "SUSPICIOUS_SERVER_ACTIVITY"],
            "confidence_reasons": ["Exact tenant, account and fresh workstation-IP relationship with bounded chronology"],
            "correlation_gaps": [],
            "timeline": [
                _timeline_item(workstation_signal, "WORKSTATION_EXECUTION"),
                _timeline_item(login, "REMOTE_SERVER_ACCESS"),
                _timeline_item(current, "SERVER_ACTIVITY"),
            ],
        })
        break
    return stories


async def _firewall_external_activity(db, current: Mapping[str, Any]) -> list[dict[str, Any]]:
    if current.get("signal_type") != "allowed_egress":
        return []
    # Egress proof requires authenticated, signed relay evidence from the
    # network device itself. Host and detection observations never qualify.
    if current.get("source_family") != "network":
        return []
    if _normalized(current.get("network_action")) not in ALLOWED_NETWORK_ACTIONS:
        return []
    source_ip = str(current.get("source_ip") or "")
    destination_ip = str(current.get("destination_ip") or "")
    if not _is_private_asset_ip(source_ip) or not _is_public_ip(destination_ip):
        return []
    tenant_id = str(current.get("tenant_id") or "")
    observed_at = _event_time(current)
    binding = await resolve_asset_for_ip(db, tenant_id, source_ip, observed_at)
    if not binding or str(binding.get("asset_class") or "") != "server":
        return []
    server_id = str(binding.get("asset_id") or "")
    parent = await db.security_stories.find_one(
        {
            "tenant_id": tenant_id,
            "affected_asset_ids": server_id,
            "status": {"$in": ["CANDIDATE", "OPEN", "ACKNOWLEDGED"]},
            "story_type": {"$ne": "EXTERNAL_ACTIVITY_AFTER_SERVER_COMPROMISE"},
            "last_seen": {"$gte": observed_at - timedelta(minutes=30), "$lte": observed_at},
        },
        sort=[("last_seen", -1)],
    )
    if not parent:
        return []
    network_ref = {
        "event_uid": _text(current.get("event_uid"), limit=240),
        "device_id": _text(current.get("network_device_id"), limit=64),
        "vendor": _text(current.get("network_vendor"), limit=32),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": _text(current.get("destination_port"), limit=16),
        "action": _text(current.get("network_action"), limit=32),
        "timestamp": observed_at,
    }
    story_id = _story_id(
        tenant_id,
        "EXTERNAL_ACTIVITY_AFTER_SERVER_COMPROMISE",
        parent.get("story_id"),
        destination_ip,
        observed_at.replace(minute=(observed_at.minute // 30) * 30, second=0, microsecond=0),
    )
    existing = await db.security_stories.find_one(
        {"tenant_id": tenant_id, "story_id": story_id}
    )
    affected_assets = list((existing or parent).get("affected_assets") or [])
    event_refs = list((existing or parent).get("event_refs") or [])
    incident_refs = list((existing or parent).get("incident_refs") or [])
    network_refs = list((existing or {}).get("network_refs") or [])
    network_refs.append(network_ref)
    signal_refs = list((existing or parent).get("signal_refs") or [])
    signal_refs.extend(current.get("_source_uids") or [])
    timeline = list((existing or parent).get("timeline") or [])
    timeline.append(_timeline_item(current, "EXTERNAL_NETWORK_ACTIVITY", f"Allowed connection to {destination_ip}"))
    return [{
        "tenant_id": tenant_id,
        "story_id": story_id,
        "story_type": "EXTERNAL_ACTIVITY_AFTER_SERVER_COMPROMISE",
        "title": "Possible compromise followed by external network activity",
        "technical_confidence": parent.get("technical_confidence") or "MEDIUM",
        "technical_severity": parent.get("technical_severity") or "HIGH",
        "primary_identity": parent.get("primary_identity"),
        "primary_account_type": parent.get("primary_account_type") or "UNKNOWN",
        "affected_assets": affected_assets,
        "source_assets": parent.get("source_assets") or [],
        "destination_assets": parent.get("destination_assets") or [],
        "event_refs": event_refs,
        "incident_refs": incident_refs,
        "network_refs": network_refs,
        "signal_refs": signal_refs,
        "linked_story_ids": [parent.get("story_id")],
        "reason_codes": [*(parent.get("reason_codes") or []), "ALLOWED_PRIVATE_TO_PUBLIC_CONNECTION"],
        "confidence_reasons": [*(parent.get("confidence_reasons") or []), "Firewall source address resolved to the affected managed server"],
        "correlation_gaps": parent.get("correlation_gaps") or [],
        "timeline": timeline,
    }]


async def process_story_signal(db, document: Mapping[str, Any]) -> list[str]:
    signal = dict(document.get("signal") or {})
    if signal.get("schema_version") != SIGNAL_SCHEMA_VERSION:
        raise ValueError("Security Story signal schema is invalid")
    if str(signal.get("tenant_id") or "") != str(document.get("tenant_id") or ""):
        raise ValueError("Security Story signal tenant binding is invalid")
    signal["_source_uids"] = [str(document.get("source_uid") or "")]
    await record_asset_ip_binding(db, signal)

    candidates: list[dict[str, Any]] = []
    for evaluator in (
        _server_account_compromise,
        _server_persistence,
        _server_anti_forensics,
        _workstation_to_server,
        _firewall_external_activity,
    ):
        candidates.extend(await evaluator(db, signal))

    story_ids = []
    for candidate in candidates:
        story = await upsert_security_story(db, candidate)
        if story and story.get("story_id"):
            story_ids.append(str(story["story_id"]))
    return list(dict.fromkeys(story_ids))


def serialize_security_story(document: Mapping[str, Any], *, detail: bool = False) -> dict[str, Any]:
    allowed = {
        "story_id",
        "schema_version",
        "story_rule_version",
        "story_type",
        "title",
        "status",
        "version",
        "technical_confidence",
        "technical_severity",
        "business_impact",
        "attention_priority",
        "primary_identity",
        "primary_account_type",
        "affected_assets",
        "source_assets",
        "destination_assets",
        "reason_codes",
        "confidence_reasons",
        "correlation_gaps",
        "first_seen",
        "last_seen",
        "created_at",
        "updated_at",
        "evidence_state",
        "event_reference_count",
        "incident_reference_count",
        "network_reference_count",
        "reference_limit",
        "has_new_activity",
        "linked_story_ids",
    }
    if detail:
        allowed.update({"event_refs", "incident_refs", "network_refs", "timeline", "workflow_history"})
    result = {key: value for key, value in document.items() if key in allowed}
    result["detection_source"] = "WarSOC"
    return json.loads(json.dumps(result, default=str))

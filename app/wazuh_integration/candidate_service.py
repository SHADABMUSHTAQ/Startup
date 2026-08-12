"""Admission and shadow storage for untrusted external detection candidates."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

import orjson
from pymongo.errors import DuplicateKeyError

from app.wazuh_integration.contracts import (
    CandidateReceiptOutcome,
    DetectionCandidate,
    DetectionCandidateBatch,
    DetectionCandidateReceipt,
)
from app.wazuh_integration.security import purpose_hmac


def _candidate_hash(candidate: DetectionCandidate) -> str:
    body = orjson.dumps(candidate.model_dump(mode="json", by_alias=True), option=orjson.OPT_SORT_KEYS)
    return hashlib.sha256(body).hexdigest()


def _utc_datetime(value: Any) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


async def _quarantine(
    db,
    candidate: DetectionCandidate,
    *,
    reason_code: str,
    received_at: datetime,
    tenant_id: str | None = None,
) -> CandidateReceiptOutcome:
    await db.detection_candidates_quarantine.update_one(
        {
            "connector_id": candidate.connector_id,
            "engine_instance_id": candidate.engine_instance_id,
            "engine_alert_id": candidate.engine_alert_id,
            "ruleset_version": candidate.ruleset_version,
        },
        {
            "$setOnInsert": {
                "connector_id": candidate.connector_id,
                "engine_instance_id": candidate.engine_instance_id,
                "engine_alert_id": candidate.engine_alert_id,
                "ruleset_version": candidate.ruleset_version,
                "engine_rule_id": candidate.engine_rule_id,
                "engine_detected_at": candidate.engine_detected_at,
                "trigger_dispatch_uid": candidate.trigger_dispatch_uid,
                "candidate_sha256": _candidate_hash(candidate),
                "tenant_id": tenant_id,
                "received_at": received_at,
                "record_expires_at": received_at + timedelta(days=90),
            },
            "$set": {"reason_code": reason_code, "last_seen_at": received_at},
        },
        upsert=True,
    )
    return CandidateReceiptOutcome(
        engine_alert_id=candidate.engine_alert_id,
        outcome="quarantined",
        reason_code=reason_code,
    )


def _normalized_registry_values(rule: dict[str, Any]) -> tuple[str, str, list[str]]:
    category = str(rule.get("category") or "").strip()
    severity = str(rule.get("severity") or "").strip().upper()
    mitre_ids = sorted({str(value).strip().upper() for value in rule.get("mitre_ids", [])})
    if not category or severity not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise ValueError("approved rule normalization is incomplete")
    return category, severity, mitre_ids


def _candidate_fingerprint(settings, tenant_id: str, event_uid: str, candidate: DetectionCandidate) -> str:
    return purpose_hmac(
        settings.wazuh_candidate_signing_secret,
        purpose="candidate-fingerprint:v1",
        values=[
            tenant_id,
            event_uid,
            candidate.engine_rule_id,
            candidate.ruleset_version,
        ],
    )


async def admit_candidate(
    db,
    candidate: DetectionCandidate,
    settings,
    *,
    received_at: datetime,
) -> CandidateReceiptOutcome:
    if candidate.connector_id != settings.wazuh_connector_id:
        return await _quarantine(
            db, candidate, reason_code="CONNECTOR_MISMATCH", received_at=received_at
        )
    if candidate.engine_instance_id != settings.wazuh_engine_instance_id:
        return await _quarantine(
            db, candidate, reason_code="ENGINE_INSTANCE_MISMATCH", received_at=received_at
        )
    if candidate.engine_version != settings.wazuh_engine_version:
        return await _quarantine(
            db, candidate, reason_code="ENGINE_VERSION_MISMATCH", received_at=received_at
        )
    if candidate.ruleset_version != settings.wazuh_ruleset_version:
        return await _quarantine(
            db, candidate, reason_code="RULESET_VERSION_MISMATCH", received_at=received_at
        )

    connector = await db.detection_engine_connectors.find_one(
        {
            "connector_id": candidate.connector_id,
            "engine_instance_id": candidate.engine_instance_id,
            "status": "active",
            "ruleset_version": candidate.ruleset_version,
            "engine_version": candidate.engine_version,
            "registry_sha256": settings.wazuh_rule_registry_sha256,
        }
    )
    if connector is None:
        return await _quarantine(
            db, candidate, reason_code="CONNECTOR_NOT_ACTIVE", received_at=received_at
        )

    dispatch = await db.detection_dispatch_outbox.find_one(
        {"dispatch_uid": candidate.trigger_dispatch_uid}
    )
    if dispatch is None:
        return await _quarantine(
            db, candidate, reason_code="UNKNOWN_DISPATCH", received_at=received_at
        )
    tenant_id = str(dispatch.get("tenant_id") or "")
    event_uid = str(dispatch.get("event_uid") or "")
    if (
        not tenant_id
        or not event_uid
        or dispatch.get("source_collection") != "siem_cold_vault"
        or dispatch.get("ruleset_version") != candidate.ruleset_version
        or candidate.engine_rule_id not in set(dispatch.get("eligible_rule_ids") or [])
    ):
        return await _quarantine(
            db,
            candidate,
            reason_code="DISPATCH_LINEAGE_MISMATCH",
            received_at=received_at,
            tenant_id=tenant_id or None,
        )

    dispatch_created_at = _utc_datetime(dispatch.get("created_at"))
    live_expires_at = _utc_datetime(dispatch.get("live_expires_at"))
    if dispatch_created_at is None or live_expires_at is None:
        return await _quarantine(
            db,
            candidate,
            reason_code="DISPATCH_TIMING_INVALID",
            received_at=received_at,
            tenant_id=tenant_id,
        )
    clock_skew = timedelta(seconds=settings.wazuh_candidate_clock_skew_seconds)
    if (
        candidate.engine_detected_at < dispatch_created_at - clock_skew
        or candidate.engine_detected_at > live_expires_at + clock_skew
        or candidate.engine_detected_at > received_at + clock_skew
    ):
        return await _quarantine(
            db,
            candidate,
            reason_code="CANDIDATE_TIME_INVALID",
            received_at=received_at,
            tenant_id=tenant_id,
        )
    if (
        received_at - candidate.engine_detected_at
    ).total_seconds() > settings.wazuh_candidate_delivery_max_age_seconds:
        return await _quarantine(
            db,
            candidate,
            reason_code="CANDIDATE_DELIVERY_EXPIRED",
            received_at=received_at,
            tenant_id=tenant_id,
        )

    source_exists = await db.siem_cold_vault.find_one(
        {"tenant_id": tenant_id, "event_uid": event_uid}, {"_id": 1}
    )
    if source_exists is None:
        return await _quarantine(
            db,
            candidate,
            reason_code="CANONICAL_EVIDENCE_MISSING",
            received_at=received_at,
            tenant_id=tenant_id,
        )

    rule = await db.detection_rule_registry.find_one(
        {
            "engine": "wazuh",
            "status": "approved",
            "candidate_enabled": True,
            "ruleset_version": candidate.ruleset_version,
            "rule_id": candidate.engine_rule_id,
            "source_family": dispatch.get("source_family"),
            "registry_sha256": settings.wazuh_rule_registry_sha256,
        }
    )
    if rule is None:
        return await _quarantine(
            db,
            candidate,
            reason_code="RULE_NOT_APPROVED",
            received_at=received_at,
            tenant_id=tenant_id,
        )
    try:
        category, severity, mitre_ids = _normalized_registry_values(rule)
    except ValueError:
        return await _quarantine(
            db,
            candidate,
            reason_code="RULE_REGISTRY_INVALID",
            received_at=received_at,
            tenant_id=tenant_id,
        )
    allowed_levels = {int(value) for value in rule.get("allowed_engine_levels", [])}
    if allowed_levels and candidate.engine_rule_level not in allowed_levels:
        return await _quarantine(
            db,
            candidate,
            reason_code="ENGINE_LEVEL_MISMATCH",
            received_at=received_at,
            tenant_id=tenant_id,
        )
    if candidate.engine_reported_category != category:
        return await _quarantine(
            db,
            candidate,
            reason_code="CATEGORY_MISMATCH",
            received_at=received_at,
            tenant_id=tenant_id,
        )
    if sorted(candidate.engine_reported_mitre_ids) != mitre_ids:
        return await _quarantine(
            db,
            candidate,
            reason_code="MITRE_MAPPING_MISMATCH",
            received_at=received_at,
            tenant_id=tenant_id,
        )

    allowed_context = {
        str(name) for name in rule.get("candidate_context_fields", []) if str(name).strip()
    }
    engine_context = {
        name: value
        for name, value in candidate.engine_context.items()
        if name in allowed_context
    }
    fingerprint = _candidate_fingerprint(settings, tenant_id, event_uid, candidate)
    observation = {
        "tenant_id": tenant_id,
        "event_uid": event_uid,
        "dispatch_uid": candidate.trigger_dispatch_uid,
        "candidate_fingerprint": fingerprint,
        "connector_id": candidate.connector_id,
        "engine_instance_id": candidate.engine_instance_id,
        "engine_version": candidate.engine_version,
        "ruleset_version": candidate.ruleset_version,
        "engine_alert_id": candidate.engine_alert_id,
        "engine_rule_id": candidate.engine_rule_id,
        "engine_rule_level": candidate.engine_rule_level,
        "engine_detected_at": candidate.engine_detected_at,
        "delivery_latency_ms": max(
            0,
            int((received_at - candidate.engine_detected_at).total_seconds() * 1000),
        ),
        "category": category,
        "severity": severity,
        "mitre_ids": mitre_ids,
        "engine_context": engine_context,
        "lineage_mode": "trigger_only",
        "mode": settings.wazuh_detection_mode,
        "status": "shadow_observation",
        "received_at": received_at,
        "created_at": received_at,
        "record_expires_at": received_at + timedelta(days=settings.wazuh_shadow_retention_days),
    }
    try:
        await db.detection_engine_observations.insert_one(observation)
    except DuplicateKeyError:
        return CandidateReceiptOutcome(
            engine_alert_id=candidate.engine_alert_id,
            outcome="duplicate",
            reason_code="ALREADY_RECORDED",
        )
    connector_update = {
        "last_candidate_at": received_at,
        "updated_at": received_at,
    }
    if category == "integration_canary":
        connector_update["last_canary_at"] = received_at
        connector_update["last_canary_dispatch_uid"] = candidate.trigger_dispatch_uid
    await db.detection_engine_connectors.update_one(
        {
            "connector_id": candidate.connector_id,
            "engine_instance_id": candidate.engine_instance_id,
        },
        {"$set": connector_update},
    )
    return CandidateReceiptOutcome(
        engine_alert_id=candidate.engine_alert_id,
        outcome="accepted",
    )


async def admit_candidate_batch(db, batch: DetectionCandidateBatch, settings) -> DetectionCandidateReceipt:
    received_at = datetime.now(timezone.utc)
    outcomes = [
        await admit_candidate(db, candidate, settings, received_at=received_at)
        for candidate in batch.candidates
    ]
    return DetectionCandidateReceipt(
        batch_id=batch.batch_id,
        connector_id=batch.connector_id,
        outcomes=outcomes,
    )

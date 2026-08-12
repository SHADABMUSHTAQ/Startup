"""Durable delivery state machine for minimized Wazuh detection inputs."""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import orjson
from pymongo import ReturnDocument

from app.wazuh_integration.contracts import (
    DetectionInput,
    DetectionInputBatch,
    DetectionInputReceipt,
)
from app.wazuh_integration.security import (
    build_signed_headers,
    decrypt_payload,
    verify_signed_request,
)


logger = logging.getLogger(__name__)
ACTIVE_STATUSES = ("pending", "retry", "in_flight")


def _batch_id() -> str:
    return f"WZB_{secrets.token_hex(16).upper()}"


def _retry_delay(attempt_count: int) -> timedelta:
    return timedelta(seconds=min(300, 2 ** min(max(attempt_count, 1), 8)))


async def _record_dlq(db, document: dict[str, Any], *, reason_code: str, detail: str) -> None:
    now = datetime.now(timezone.utc)
    await db.detection_dispatch_dlq.update_one(
        {"dispatch_uid": document["dispatch_uid"]},
        {
            "$setOnInsert": {
                "dispatch_uid": document["dispatch_uid"],
                "tenant_id": document.get("tenant_id"),
                "event_uid": document.get("event_uid"),
                "source_collection": document.get("source_collection"),
                "source_record_id": document.get("source_record_id"),
                "source_record_hash": document.get("source_record_hash"),
                "ruleset_version": document.get("ruleset_version"),
                "payload_sha256": document.get("payload_sha256"),
                "payload_bytes": document.get("payload_bytes"),
                "attempt_count": document.get("attempt_count", 0),
                "failed_at": now,
                "record_expires_at": now + timedelta(days=365),
            },
            "$set": {
                "reason_code": reason_code,
                "detail": str(detail or "")[:512],
                "last_seen_at": now,
            },
        },
        upsert=True,
    )
    await db.detection_coverage_gaps.update_one(
        {
            "gap_type": "wazuh_dispatch_terminal_failure",
            "tenant_id": document.get("tenant_id"),
            "event_uid": document.get("event_uid"),
            "ruleset_version": document.get("ruleset_version"),
        },
        {
            "$setOnInsert": {"created_at": now},
            "$set": {
                "last_seen_at": now,
                "status": "open",
                "reason_code": reason_code,
                "dispatch_uid": document.get("dispatch_uid"),
            },
        },
        upsert=True,
    )


async def expire_stale_dispatches(db, *, limit: int = 500) -> int:
    now = datetime.now(timezone.utc)
    documents = await db.detection_dispatch_outbox.find(
        {"status": {"$in": ACTIVE_STATUSES}, "live_expires_at": {"$lt": now}}
    ).limit(limit).to_list(length=limit)
    for document in documents:
        await _record_dlq(
            db,
            document,
            reason_code="LIVE_WINDOW_EXPIRED",
            detail="Dispatch exceeded the approved live correlation age.",
        )
        await db.detection_dispatch_outbox.update_one(
            {"dispatch_uid": document["dispatch_uid"], "status": {"$in": ACTIVE_STATUSES}},
            {
                "$set": {
                    "status": "expired",
                    "updated_at": now,
                    "terminal_reason": "LIVE_WINDOW_EXPIRED",
                },
                "$unset": {"lease_token": "", "lease_expires_at": ""},
            },
        )
    return len(documents)


async def claim_dispatches(db, settings, *, limit: int | None = None) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    lease_token = secrets.token_urlsafe(24)
    claimed: list[dict[str, Any]] = []
    count = min(limit or settings.wazuh_dispatch_batch_size, settings.wazuh_max_batch_events)
    for _ in range(count):
        document = await db.detection_dispatch_outbox.find_one_and_update(
            {
                "live_expires_at": {"$gte": now},
                "$or": [
                    {"status": {"$in": ["pending", "retry"]}, "next_attempt_at": {"$lte": now}},
                    {"status": "in_flight", "lease_expires_at": {"$lt": now}},
                ],
            },
            {
                "$set": {
                    "status": "in_flight",
                    "lease_token": lease_token,
                    "lease_expires_at": now + timedelta(seconds=max(30, settings.wazuh_dispatch_timeout_seconds * 3)),
                    "updated_at": now,
                },
                "$inc": {"attempt_count": 1},
            },
            sort=[("next_attempt_at", 1), ("created_at", 1)],
            return_document=ReturnDocument.AFTER,
        )
        if document is None:
            break
        claimed.append(document)
    return claimed


def _prepare_input(document: dict[str, Any], settings, now: datetime) -> DetectionInput:
    raw = decrypt_payload(settings.wazuh_outbox_encryption_key, document["payload_ciphertext"])
    if hashlib.sha256(raw).hexdigest() != document.get("payload_sha256"):
        raise ValueError("outbox payload hash mismatch")
    item = DetectionInput.model_validate_json(raw)
    if item.dispatch_uid != document.get("dispatch_uid"):
        raise ValueError("outbox dispatch identity mismatch")
    if document.get("attempt_count", 0) > 1:
        item = item.model_copy(
            update={
                "dispatch_mode": "retry",
                "dispatch_time": now,
                "event_age_ms": max(0, int((now - item.original_event_time).total_seconds() * 1000)),
            }
        )
    return item


async def _release_for_retry(db, document: dict[str, Any], settings, detail: str) -> None:
    attempts = int(document.get("attempt_count") or 0)
    if attempts >= settings.wazuh_dispatch_max_attempts:
        await _record_dlq(
            db,
            document,
            reason_code="MAX_ATTEMPTS_EXCEEDED",
            detail=detail,
        )
        await db.detection_dispatch_outbox.update_one(
            {"dispatch_uid": document["dispatch_uid"], "lease_token": document.get("lease_token")},
            {
                "$set": {
                    "status": "failed",
                    "updated_at": datetime.now(timezone.utc),
                    "terminal_reason": "MAX_ATTEMPTS_EXCEEDED",
                },
                "$unset": {"lease_token": "", "lease_expires_at": ""},
            },
        )
        return
    now = datetime.now(timezone.utc)
    await db.detection_dispatch_outbox.update_one(
        {"dispatch_uid": document["dispatch_uid"], "lease_token": document.get("lease_token")},
        {
            "$set": {
                "status": "retry",
                "next_attempt_at": now + _retry_delay(attempts),
                "updated_at": now,
                "last_error": str(detail or "")[:512],
            },
            "$unset": {"lease_token": "", "lease_expires_at": ""},
        },
    )


def _tls_options(settings) -> tuple[str, tuple[str, str]]:
    required = (
        settings.wazuh_dispatch_ca_file,
        settings.wazuh_dispatch_cert_file,
        settings.wazuh_dispatch_key_file,
    )
    if any(not value for value in required):
        raise RuntimeError("Wazuh dispatch mTLS files are not configured")
    for value in required:
        if not Path(value).is_file():
            raise RuntimeError("Wazuh dispatch mTLS file is unavailable")
    return required[0], (required[1], required[2])


async def dispatch_claimed(db, documents: list[dict[str, Any]], settings) -> dict[str, int]:
    if not documents:
        return {"empty": 1}
    now = datetime.now(timezone.utc)
    valid: list[tuple[dict[str, Any], DetectionInput]] = []
    for document in documents:
        try:
            valid.append((document, _prepare_input(document, settings, now)))
        except Exception as exc:
            await _record_dlq(
                db,
                document,
                reason_code="OUTBOX_PAYLOAD_INVALID",
                detail=str(exc),
            )
            await db.detection_dispatch_outbox.update_one(
                {"dispatch_uid": document["dispatch_uid"], "lease_token": document.get("lease_token")},
                {
                    "$set": {
                        "status": "failed",
                        "updated_at": now,
                        "terminal_reason": "OUTBOX_PAYLOAD_INVALID",
                    },
                    "$unset": {"lease_token": "", "lease_expires_at": ""},
                },
            )
    if not valid:
        return {"invalid": len(documents)}

    batch = DetectionInputBatch(
        batch_id=_batch_id(),
        connector_id=settings.wazuh_connector_id,
        created_at=now,
        inputs=[item for _, item in valid],
    )
    body = orjson.dumps(batch.model_dump(mode="json", by_alias=True), option=orjson.OPT_SORT_KEYS)
    if len(body) > settings.wazuh_max_body_bytes:
        for document, _ in valid:
            await _release_for_retry(db, document, settings, "dispatch batch exceeds byte limit")
        return {"retry": len(valid), "batch_too_large": 1}

    try:
        verify, cert = _tls_options(settings)
        headers = build_signed_headers(
            secret=settings.wazuh_dispatch_signing_secret,
            connector_id=settings.wazuh_connector_id,
            body=body,
        )
        async with httpx.AsyncClient(
            verify=verify,
            cert=cert,
            timeout=settings.wazuh_dispatch_timeout_seconds,
        ) as client:
            response = await client.post(
                settings.wazuh_dispatch_url,
                content=body,
                headers={**headers, "Content-Type": "application/json"},
            )
        response.raise_for_status()
        if len(response.content) > settings.wazuh_max_body_bytes:
            raise ValueError("dispatch receipt exceeds byte limit")
        verify_signed_request(
            secret=settings.wazuh_dispatch_signing_secret,
            expected_connector_id=settings.wazuh_connector_id,
            headers=response.headers,
            body=response.content,
        )
        receipt = DetectionInputReceipt.model_validate_json(response.content)
        if receipt.batch_id != batch.batch_id or receipt.connector_id != batch.connector_id:
            raise ValueError("dispatch receipt identity mismatch")
    except Exception as exc:
        logger.warning("Wazuh dispatch failed: %s", exc)
        for document, _ in valid:
            await _release_for_retry(db, document, settings, str(exc))
        return {"retry": len(valid)}

    accepted = set(receipt.accepted_dispatch_uids) | set(receipt.duplicate_dispatch_uids)
    rejected = {item.dispatch_uid: item.reason_code for item in receipt.rejected}
    counts = {"delivered": 0, "rejected": 0, "retry": 0}
    for document, _ in valid:
        dispatch_uid = document["dispatch_uid"]
        if dispatch_uid in accepted:
            await db.detection_dispatch_outbox.update_one(
                {"dispatch_uid": dispatch_uid, "lease_token": document.get("lease_token")},
                {
                    "$set": {
                        "status": "delivered",
                        "delivered_at": datetime.now(timezone.utc),
                        "updated_at": datetime.now(timezone.utc),
                        "receipt_batch_id": receipt.batch_id,
                    },
                    "$unset": {"lease_token": "", "lease_expires_at": "", "last_error": ""},
                },
            )
            counts["delivered"] += 1
        elif dispatch_uid in rejected:
            await _record_dlq(
                db,
                document,
                reason_code="INGRESS_REJECTED",
                detail=rejected[dispatch_uid],
            )
            await db.detection_dispatch_outbox.update_one(
                {"dispatch_uid": dispatch_uid, "lease_token": document.get("lease_token")},
                {
                    "$set": {
                        "status": "rejected",
                        "updated_at": datetime.now(timezone.utc),
                        "terminal_reason": rejected[dispatch_uid],
                    },
                    "$unset": {"lease_token": "", "lease_expires_at": ""},
                },
            )
            counts["rejected"] += 1
        else:
            await _release_for_retry(db, document, settings, "dispatch omitted from receipt")
            counts["retry"] += 1
    return counts

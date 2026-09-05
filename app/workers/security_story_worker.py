"""Independent durable projection worker for tenant-scoped Security Stories."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import time
from datetime import datetime, timezone
from typing import Any, Mapping

from motor.motor_asyncio import AsyncIOMotorClient
from redis import exceptions as redis_exceptions

from app.config.config import get_settings
from app.utils.observability import increment_redis_counter, record_worker_heartbeat_with_client
from app.utils.redis_client import create_redis_client
from app.utils.security_stories import (
    STORY_SIGNAL_GROUP,
    build_event_story_signal,
    claim_story_signal,
    complete_story_signal,
    enqueue_incident_story_signal,
    enqueue_story_signal,
    fail_story_signal,
    process_story_signal,
)


logger = logging.getLogger("security-story-worker")

RAW_LOGS_QUEUE = "raw_logs_queue"
STORY_CONSUMER = f"security_story_{socket.gethostname()}_{os.getpid()}"
READ_BATCH_SIZE = max(1, min(250, int(os.getenv("SECURITY_STORY_READ_BATCH_SIZE", "50"))))
RECLAIM_BATCH_SIZE = max(1, min(250, int(os.getenv("SECURITY_STORY_RECLAIM_BATCH_SIZE", "50"))))
RECLAIM_MIN_IDLE_MS = max(30_000, int(os.getenv("SECURITY_STORY_RECLAIM_MIN_IDLE_MS", "60000")))
LEDGER_BATCH_SIZE = max(1, min(250, int(os.getenv("SECURITY_STORY_LEDGER_BATCH_SIZE", "100"))))


def _field(mapping: Mapping[Any, Any], name: str, default: Any = None) -> Any:
    return mapping.get(name, mapping.get(name.encode("utf-8"), default))


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="strict")
    return str(value or "")


async def _ensure_group(redis_client) -> None:
    try:
        # Security Stories are opt-in. A first enable starts at new traffic so
        # historical raw-stream backlog cannot create an unbounded deployment.
        await redis_client.xgroup_create(
            RAW_LOGS_QUEUE,
            STORY_SIGNAL_GROUP,
            id="$",
            mkstream=True,
        )
    except redis_exceptions.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def _reclaim_stale(redis_client) -> list[tuple[Any, Mapping[Any, Any]]]:
    try:
        pending = await redis_client.xpending_range(
            RAW_LOGS_QUEUE,
            STORY_SIGNAL_GROUP,
            "-",
            "+",
            RECLAIM_BATCH_SIZE,
            idle=RECLAIM_MIN_IDLE_MS,
        )
        message_ids = []
        for row in pending or []:
            message_id = row.get("message_id") if isinstance(row, Mapping) else row[0]
            if message_id:
                message_ids.append(message_id)
        if not message_ids:
            return []
        return await redis_client.xclaim(
            RAW_LOGS_QUEUE,
            STORY_SIGNAL_GROUP,
            STORY_CONSUMER,
            RECLAIM_MIN_IDLE_MS,
            message_ids,
        )
    except redis_exceptions.ResponseError as exc:
        if "NOGROUP" in str(exc):
            await _ensure_group(redis_client)
        else:
            logger.warning("Security Story reclaim skipped: %s", exc)
        return []


async def _persist_raw_signal(db, fields: Mapping[Any, Any]) -> str:
    raw_payload = _field(fields, "payload")
    if raw_payload in (None, ""):
        return "IGNORED"
    try:
        event = json.loads(_text(raw_payload))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        return "INVALID"
    if not isinstance(event, Mapping):
        return "INVALID"
    signal = await build_event_story_signal(db, event)
    if signal is None:
        return "IGNORED"
    event_uid = str(signal.get("event_uid") or "")
    if not event_uid:
        return "INVALID"
    await enqueue_story_signal(
        db,
        source_type="event",
        source_uid=event_uid,
        signal=signal,
        delay_seconds=5,
    )
    return "PERSISTED"


async def _consume_raw_messages(redis_client, db, messages) -> None:
    for message_id, fields in messages or []:
        try:
            outcome = await _persist_raw_signal(db, fields)
            await redis_client.xack(RAW_LOGS_QUEUE, STORY_SIGNAL_GROUP, message_id)
            if outcome == "INVALID":
                await increment_redis_counter(
                    redis_client,
                    "warsoc_security_story_invalid_source_total",
                )
        except Exception as exc:
            # Leave the entry in the PEL. Canonical ingestion and the SIEM have
            # separate groups and continue independently.
            logger.error("Security Story raw handoff failed for %s: %s", message_id, exc)


async def _recover_pending_incident_handoffs(db) -> int:
    rows = await (
        db.security_incident_occurrences.find({"story_signal_status": "PENDING"})
        .sort("projected_at", 1)
        .limit(100)
        .to_list(length=100)
    )
    recovered = 0
    for occurrence in rows:
        tenant_id = str(occurrence.get("tenant_id") or "")
        incident_id = str(occurrence.get("incident_id") or "")
        occurrence_uid = str(occurrence.get("occurrence_uid") or "")
        if not tenant_id or not incident_id or not occurrence_uid:
            continue
        incident = await db.security_incidents.find_one(
            {"tenant_id": tenant_id, "incident_id": incident_id}
        )
        if not incident:
            continue
        source = None
        alert_uid = occurrence.get("alert_uid")
        if alert_uid:
            source = await db.security_alerts.find_one(
                {"tenant_id": tenant_id, "alert_uid": alert_uid}
            )
        source = dict(source or incident)
        source.setdefault("event_uid", occurrence.get("event_uid"))
        await enqueue_incident_story_signal(
            db,
            incident,
            source,
            occurrence_uid=occurrence_uid,
        )
        await db.security_incident_occurrences.update_one(
            {"_id": occurrence["_id"], "story_signal_status": "PENDING"},
            {
                "$set": {
                    "story_signal_status": "ENQUEUED",
                    "story_signal_enqueued_at": datetime.now(timezone.utc),
                }
            },
        )
        recovered += 1
    return recovered


async def _drain_signal_ledger(db) -> int:
    processed = 0
    for _ in range(LEDGER_BATCH_SIZE):
        document = await claim_story_signal(db)
        if document is None:
            break
        try:
            story_ids = await process_story_signal(db, document)
            await complete_story_signal(db, document, story_ids)
        except Exception as exc:
            await fail_story_signal(db, document, exc)
            logger.error("Security Story signal processing failed: %s", exc)
        processed += 1
    return processed


async def security_story_worker() -> None:
    settings = get_settings()
    if not settings.security_stories_enabled:
        logger.info("Security Stories are disabled; worker not started")
        return

    mongo_client = AsyncIOMotorClient(settings.mongodb_uri)
    db = mongo_client[settings.mongodb_db_name]
    redis_client = create_redis_client(settings.redis_url)
    last_reclaim = 0.0
    last_recovery = 0.0
    last_heartbeat = 0.0

    try:
        await _ensure_group(redis_client)
        logger.info("WarSOC Security Story worker online")
        while True:
            try:
                now = time.monotonic()
                if now - last_heartbeat >= 15:
                    await record_worker_heartbeat_with_client(
                        redis_client,
                        "security_story_worker",
                    )
                    last_heartbeat = now

                await _drain_signal_ledger(db)
                if now - last_recovery >= 10:
                    await _recover_pending_incident_handoffs(db)
                    last_recovery = now

                messages = []
                streams = await redis_client.xreadgroup(
                    STORY_SIGNAL_GROUP,
                    STORY_CONSUMER,
                    {RAW_LOGS_QUEUE: ">"},
                    count=READ_BATCH_SIZE,
                    block=500,
                )
                for _, batch in streams or []:
                    messages.extend(batch or [])
                if not messages and now - last_reclaim >= 30:
                    messages = await _reclaim_stale(redis_client)
                    last_reclaim = now
                await _consume_raw_messages(redis_client, db, messages)
            except redis_exceptions.ResponseError as exc:
                if "NOGROUP" in str(exc):
                    await _ensure_group(redis_client)
                else:
                    logger.error("Security Story Redis operation failed: %s", exc)
                    await asyncio.sleep(1)
            except Exception as exc:
                logger.error("Security Story worker iteration failed: %s", exc)
                await asyncio.sleep(1)
    finally:
        await redis_client.aclose()
        mongo_client.close()


if __name__ == "__main__":
    asyncio.run(security_story_worker())

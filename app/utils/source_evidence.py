"""Durable encrypted source envelopes and Redis dispatch outbox."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.fernet import InvalidToken
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.config.config import get_settings
from app.utils.compliance_catalog import COMPLIANCE_CATALOG
from app.utils.fbr_retention import apply_fbr_tenant_retention
from app.utils.peca_retention import apply_peca_tenant_retention
from app.utils.key_lifecycle import (
    active_source_envelope_key,
    source_envelope_decryption_key,
)


logger = logging.getLogger("source_evidence")

SOURCE_ENVELOPE_COLLECTIONS = {
    "SIEM": "source_envelopes_siem",
    "PECA": "source_envelopes_peca",
    "FBR": "source_envelopes_fbr",
}
SOURCE_OUTBOX_COLLECTION = "source_evidence_outbox"
ALLOWED_TARGET_STREAMS = {"raw_logs_queue", "siem_hot_queue"}
OUTBOX_MAX_ATTEMPTS = max(1, int(os.getenv("SOURCE_OUTBOX_MAX_ATTEMPTS", "20")))
OUTBOX_LEASE_SECONDS = max(15, int(os.getenv("SOURCE_OUTBOX_LEASE_SECONDS", "60")))
OUTBOX_RETENTION_DAYS = max(1, int(os.getenv("SOURCE_OUTBOX_RETENTION_DAYS", "30")))
RAW_STREAM_MAX_ENTRIES = max(1, int(os.getenv("RAW_STREAM_MAX_ENTRIES", "500000")))
SOURCE_ENVELOPE_SCHEMA = "warsoc-source-envelope-v1"


class SourceEvidenceConflict(RuntimeError):
    """Raised when a source UID is replayed with different authenticated bytes."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _catalog_event_ids(pack_id: str) -> set[str]:
    return {
        str(rule.get("event_id"))
        for rule in COMPLIANCE_CATALOG.get(pack_id, {}).get("rules", [])
        if rule.get("event_id") is not None
    }


FBR_EVENT_IDS = _catalog_event_ids("fbr_pos")
PECA_EVENT_IDS = _catalog_event_ids("peca_forensic")


def retention_class_for_event(event: dict, source_channel: str) -> str:
    if source_channel == "fbr_pos":
        return "FBR"
    if source_channel == "network_relay":
        return "SIEM"
    event_id = str(event.get("event_id") or "").strip()
    if event_id in FBR_EVENT_IDS:
        return "FBR"
    if event_id in PECA_EVENT_IDS:
        return "PECA"
    return "SIEM"


def _encode_package(source_payload: bytes, dispatch_payloads: list[str]) -> tuple[str, str, int]:
    package = {
        "schema_version": SOURCE_ENVELOPE_SCHEMA,
        "source_payload_b64": base64.b64encode(source_payload).decode("ascii"),
        "dispatch_payloads": dispatch_payloads,
    }
    encoded = json.dumps(package, sort_keys=True, separators=(",", ":")).encode("utf-8")
    compressed = zlib.compress(encoded, level=9)
    key = active_source_envelope_key()
    return key.cipher.encrypt(compressed).decode("ascii"), key.key_id, key.version


def _decode_package(
    token: str,
    *,
    key_id: str | None = None,
    key_version: int | None = None,
) -> dict:
    try:
        key = source_envelope_decryption_key(key_id, key_version)
        compressed = key.cipher.decrypt(token.encode("ascii"))
        package = json.loads(zlib.decompress(compressed))
    except (InvalidToken, ValueError, TypeError, zlib.error, json.JSONDecodeError) as exc:
        raise RuntimeError("Source evidence envelope cannot be decrypted") from exc
    if package.get("schema_version") != SOURCE_ENVELOPE_SCHEMA:
        raise RuntimeError("Unsupported source evidence envelope schema")
    return package


def _dispatch_set_hash(dispatch_events: list[dict]) -> str:
    normalized = [
        {
            "event_uid": str(item["event_uid"]),
            "payload_hash": _sha256(item["serialized_payload"].encode("utf-8")),
            "target_streams": sorted(set(item["target_streams"])),
        }
        for item in dispatch_events
    ]
    return _sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8"))


async def persist_source_envelope(
    db,
    *,
    tenant_id: str,
    source_principal_type: str,
    source_principal_id: str,
    source_channel: str,
    source_envelope_uid: str,
    source_payload: bytes,
    dispatch_events: list[dict],
    retention_class: str,
    auth_metadata: dict[str, Any],
    source_timestamp: datetime | str | None = None,
    retention_metadata: dict[str, Any] | None = None,
) -> list[str]:
    """Persist authenticated source bytes and ready outbox rows idempotently."""

    if retention_class not in SOURCE_ENVELOPE_COLLECTIONS:
        raise ValueError("Unsupported source envelope retention class")
    if not dispatch_events:
        raise ValueError("Source envelope requires at least one dispatch event")
    if (
        retention_class == "PECA"
        and "tenant_retention_days_at_ingest" not in (retention_metadata or {})
    ):
        raise ValueError("PECA source envelope requires tenant retention metadata")

    normalized_events: list[dict] = []
    for item in dispatch_events:
        streams = sorted(set(item.get("target_streams") or []))
        if not streams or not set(streams).issubset(ALLOWED_TARGET_STREAMS):
            raise ValueError("Source outbox target stream is not allowed")
        serialized = str(item.get("serialized_payload") or "")
        event_uid = str(item.get("event_uid") or "").strip()
        if not event_uid or not serialized:
            raise ValueError("Source outbox event identity is incomplete")
        normalized_events.append(
            {
                "event_uid": event_uid,
                "serialized_payload": serialized,
                "target_streams": streams,
            }
        )

    now = datetime.now(timezone.utc)
    source_hash = _sha256(source_payload)
    dispatch_hash = _dispatch_set_hash(normalized_events)
    outbox_descriptors = []
    for item in normalized_events:
        outbox_uid = _sha256(
            "|".join(
                (
                    tenant_id,
                    source_principal_id,
                    source_channel,
                    item["event_uid"],
                )
            ).encode("utf-8")
        )
        outbox_descriptors.append(
            {
                "outbox_uid": outbox_uid,
                "payload_hash": _sha256(item["serialized_payload"].encode("utf-8")),
                "target_streams": item["target_streams"],
            }
        )
    envelope_identity = {
        "tenant_id": tenant_id,
        "source_principal_type": source_principal_type,
        "source_principal_id": source_principal_id,
        "source_channel": source_channel,
        "source_envelope_uid": source_envelope_uid,
    }
    collection_name = SOURCE_ENVELOPE_COLLECTIONS[retention_class]
    collection = db[collection_name]
    encrypted_package, encryption_key_id, encryption_key_version = _encode_package(
        source_payload,
        [item["serialized_payload"] for item in normalized_events],
    )
    envelope_document = {
        **envelope_identity,
        "schema_version": SOURCE_ENVELOPE_SCHEMA,
        "retention_class": retention_class,
        "source_payload_hash": source_hash,
        "dispatch_set_hash": dispatch_hash,
        "event_count": len(normalized_events),
        "encrypted_package": encrypted_package,
        "encryption_algorithm": "Fernet-AES128-CBC-HMAC-SHA256",
        "encryption_key_id": encryption_key_id,
        "encryption_key_version": encryption_key_version,
        "auth_metadata": dict(auth_metadata),
        "source_timestamp": source_timestamp,
        "received_at": now,
        "timestamp": now,
        "state": "PREPARING",
        "dispatch_complete": False,
        "created_at": now,
        "updated_at": now,
    }
    if retention_class == "FBR":
        apply_fbr_tenant_retention(
            envelope_document,
            (retention_metadata or {}).get("tenant_retention_days_at_ingest"),
        )
    elif retention_class == "PECA":
        apply_peca_tenant_retention(
            envelope_document,
            (retention_metadata or {}).get("tenant_retention_days_at_ingest"),
        )

    existing = await collection.find_one(envelope_identity)
    if existing:
        if (
            existing.get("source_payload_hash") != source_hash
            or existing.get("dispatch_set_hash") != dispatch_hash
            or existing.get("auth_metadata") != dict(auth_metadata)
        ):
            raise SourceEvidenceConflict("Source envelope UID was reused with different evidence")
        envelope_id = existing["_id"]
    else:
        # A delivery retry uses a fresh anti-replay nonce, but its authenticated
        # event UIDs and bytes remain stable. If every event is already durably
        # represented by an identical outbox row, return that durable identity
        # without creating an orphan duplicate source envelope. Any byte or
        # routing difference remains an evidence conflict and fails closed.
        existing_outboxes = []
        for descriptor in outbox_descriptors:
            existing_outbox = await db[SOURCE_OUTBOX_COLLECTION].find_one(
                {"outbox_uid": descriptor["outbox_uid"]},
                {"payload_hash": 1, "target_streams": 1},
            )
            if existing_outbox and (
                existing_outbox.get("payload_hash") != descriptor["payload_hash"]
                or sorted(existing_outbox.get("target_streams") or [])
                != descriptor["target_streams"]
            ):
                raise SourceEvidenceConflict(
                    "Source event UID was reused with different evidence"
                )
            existing_outboxes.append(existing_outbox)
        if existing_outboxes and all(existing_outboxes):
            return [descriptor["outbox_uid"] for descriptor in outbox_descriptors]

        try:
            insert_result = await collection.insert_one(envelope_document)
            envelope_id = insert_result.inserted_id
        except DuplicateKeyError:
            existing = await collection.find_one(envelope_identity)
            if not existing:
                raise
            if (
                existing.get("source_payload_hash") != source_hash
                or existing.get("dispatch_set_hash") != dispatch_hash
                or existing.get("auth_metadata") != dict(auth_metadata)
            ):
                raise SourceEvidenceConflict("Source envelope UID was reused with different evidence")
            envelope_id = existing["_id"]

    outbox_uids: list[str] = []
    for index, item in enumerate(normalized_events):
        descriptor = outbox_descriptors[index]
        outbox_uid = descriptor["outbox_uid"]
        outbox_uids.append(outbox_uid)
        payload_hash = descriptor["payload_hash"]
        existing_outbox = await db[SOURCE_OUTBOX_COLLECTION].find_one(
            {"outbox_uid": outbox_uid},
            {"payload_hash": 1, "target_streams": 1},
        )
        if existing_outbox and (
            existing_outbox.get("payload_hash") != payload_hash
            or sorted(existing_outbox.get("target_streams") or []) != item["target_streams"]
        ):
            raise SourceEvidenceConflict("Source event UID was reused with different evidence")
        await db[SOURCE_OUTBOX_COLLECTION].update_one(
            {"outbox_uid": outbox_uid},
            {
                "$setOnInsert": {
                    "outbox_uid": outbox_uid,
                    "tenant_id": tenant_id,
                    "source_principal_id": source_principal_id,
                    "source_channel": source_channel,
                    "source_event_uid": item["event_uid"],
                    "envelope_collection": collection_name,
                    "envelope_id": envelope_id,
                    "envelope_event_index": index,
                    "payload_hash": payload_hash,
                    "target_streams": item["target_streams"],
                    "status": "pending",
                    "ready": False,
                    "attempts": 0,
                    "next_attempt_at": now,
                    "created_at": now,
                },
                "$set": {"updated_at": now},
            },
            upsert=True,
        )

    await collection.update_one(
        {"_id": envelope_id},
        {"$set": {"state": "COMMITTED", "updated_at": now}},
    )
    await db[SOURCE_OUTBOX_COLLECTION].update_many(
        {"outbox_uid": {"$in": outbox_uids}},
        {"$set": {"ready": True, "updated_at": now}},
    )
    return outbox_uids


async def _claim_outbox(db, outbox_uid: str | None = None):
    now = datetime.now(timezone.utc)
    query: dict[str, Any] = {
        "ready": True,
        "attempts": {"$lt": OUTBOX_MAX_ATTEMPTS},
        "$or": [
            {"status": {"$in": ["pending", "retry"]}, "next_attempt_at": {"$lte": now}},
            {"status": "in_flight", "lease_until": {"$lte": now}},
        ],
    }
    if outbox_uid:
        query["outbox_uid"] = outbox_uid
    return await db[SOURCE_OUTBOX_COLLECTION].find_one_and_update(
        query,
        {
            "$set": {
                "status": "in_flight",
                "lease_id": uuid.uuid4().hex,
                "lease_until": now + timedelta(seconds=OUTBOX_LEASE_SECONDS),
                "updated_at": now,
            },
            "$inc": {"attempts": 1},
        },
        sort=[("created_at", 1)],
        return_document=ReturnDocument.AFTER,
    )


async def _publish_claimed_outbox(db, redis, record: dict) -> bool:
    try:
        envelope = await db[record["envelope_collection"]].find_one(
            {"_id": record["envelope_id"], "state": "COMMITTED"}
        )
        if not envelope:
            raise RuntimeError("Committed source envelope is missing")
        package = _decode_package(
            envelope["encrypted_package"],
            key_id=envelope.get("encryption_key_id"),
            key_version=envelope.get("encryption_key_version"),
        )
        payload = package["dispatch_payloads"][int(record["envelope_event_index"])]
        if _sha256(payload.encode("utf-8")) != record["payload_hash"]:
            raise RuntimeError("Source outbox payload integrity check failed")
        if "raw_logs_queue" in record["target_streams"]:
            if await redis.xlen("raw_logs_queue") >= RAW_STREAM_MAX_ENTRIES:
                raise RuntimeError("Raw ingest stream is at its configured entry ceiling")

        async with redis.pipeline(transaction=True) as pipe:
            for stream in record["target_streams"]:
                await pipe.xadd(stream, {"payload": payload})
            stream_ids = await pipe.execute()

        now = datetime.now(timezone.utc)
        await db[SOURCE_OUTBOX_COLLECTION].update_one(
            {"_id": record["_id"], "lease_id": record["lease_id"]},
            {
                "$set": {
                    "status": "published",
                    "stream_ids": [str(value) for value in stream_ids],
                    "published_at": now,
                    "delete_after": now + timedelta(days=OUTBOX_RETENTION_DAYS),
                    "updated_at": now,
                },
                "$unset": {"lease_id": "", "lease_until": "", "last_error": ""},
            },
        )
        remaining = await db[SOURCE_OUTBOX_COLLECTION].count_documents(
            {
                "envelope_collection": record["envelope_collection"],
                "envelope_id": record["envelope_id"],
                "status": {"$ne": "published"},
            },
            limit=1,
        )
        if remaining == 0:
            await db[record["envelope_collection"]].update_one(
                {"_id": record["envelope_id"]},
                {"$set": {"dispatch_complete": True, "dispatch_completed_at": now}},
            )
        return True
    except Exception as exc:
        attempts = int(record.get("attempts") or 1)
        status = "failed" if attempts >= OUTBOX_MAX_ATTEMPTS else "retry"
        delay = min(300, 2 ** min(attempts, 8))
        await db[SOURCE_OUTBOX_COLLECTION].update_one(
            {"_id": record["_id"], "lease_id": record.get("lease_id")},
            {
                "$set": {
                    "status": status,
                    "next_attempt_at": datetime.now(timezone.utc) + timedelta(seconds=delay),
                    "last_error": str(exc)[:500],
                    "updated_at": datetime.now(timezone.utc),
                },
                "$unset": {"lease_id": "", "lease_until": ""},
            },
        )
        logger.error("Source outbox publish failed: uid=%s error=%s", record.get("outbox_uid"), exc)
        return False


async def publish_source_outbox(db, redis, outbox_uids: list[str] | None = None, limit: int = 100) -> int:
    published = 0
    if outbox_uids is not None:
        candidates = list(dict.fromkeys(outbox_uids))[:limit]
        for outbox_uid in candidates:
            record = await _claim_outbox(db, outbox_uid)
            if record and await _publish_claimed_outbox(db, redis, record):
                published += 1
        return published

    for _ in range(limit):
        record = await _claim_outbox(db)
        if not record:
            break
        if await _publish_claimed_outbox(db, redis, record):
            published += 1
    return published


async def source_outbox_worker():
    settings = get_settings()
    mongo_client = AsyncIOMotorClient(settings.mongodb_uri)
    db = mongo_client[settings.mongodb_db_name]
    from app.utils.redis_client import create_redis_client

    redis = create_redis_client(settings.redis_url)
    try:
        while True:
            published = await publish_source_outbox(db, redis, limit=100)
            await asyncio.sleep(0.1 if published else 1.0)
    finally:
        await redis.aclose()
        mongo_client.close()

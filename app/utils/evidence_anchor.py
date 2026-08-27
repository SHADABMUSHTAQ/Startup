"""Immutable external commitments for verified daily evidence roots."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from azure.core.exceptions import ResourceExistsError
from azure.storage.blob import ContentSettings

from app.utils.compliance_chain import verify_ledger_entry


ANCHOR_SCHEMA_VERSION = "warsoc-daily-root-anchor-v1"


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _as_utc(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def build_anchor_payload(ledger: dict) -> bytes:
    if not verify_ledger_entry(ledger):
        raise ValueError("Only verified daily ledgers can be externally anchored")
    payload = {
        "schema_version": ANCHOR_SCHEMA_VERSION,
        "tenant_id": str(ledger["tenant_id"]),
        "date": str(ledger["date"]),
        "chain_version": str(ledger["chain_version"]),
        "hash_algorithm": str(ledger.get("hash_algorithm") or "SHA-256"),
        "daily_root_hash": str(ledger["daily_root_hash"]),
        "previous_root_hash": str(ledger["previous_root_hash"]),
        "evidence_digest": str(ledger["evidence_digest"]),
        "log_count": int(ledger["log_count"]),
        "source_counts": {
            str(key): int(value)
            for key, value in sorted((ledger.get("source_counts") or {}).items())
        },
    }
    return _canonical_bytes(payload)


def anchor_blob_name(ledger: dict) -> str:
    tenant_digest = hashlib.sha256(str(ledger["tenant_id"]).encode("utf-8")).hexdigest()
    return f"daily-roots/{tenant_digest}/{ledger['date']}.json"


def required_anchor_retention_until(ledger: dict, fallback_days: int) -> datetime:
    if fallback_days < 1:
        raise ValueError("EVIDENCE_DAILY_ANCHOR_FALLBACK_DAYS must be positive")
    date_start = datetime.fromisoformat(str(ledger["date"])).replace(tzinfo=timezone.utc)
    fallback = date_start + timedelta(days=fallback_days + 1)
    evidence_until = _as_utc(ledger.get("evidence_retention_until"))
    return max(fallback, evidence_until) if evidence_until else fallback


def _immutability_status(properties: Any, required_until: datetime) -> dict:
    legal_hold = bool(getattr(properties, "has_legal_hold", False))
    policy = getattr(properties, "immutability_policy", None)
    raw_mode = getattr(policy, "policy_mode", "") or ""
    mode = str(getattr(raw_mode, "value", raw_mode))
    expiry = _as_utc(getattr(policy, "expiry_time", None))
    locked = mode.strip().lower() == "locked"
    verified = legal_hold or bool(locked and expiry and expiry >= required_until)
    return {
        "verified": verified,
        "legal_hold": legal_hold,
        "policy_mode": mode or None,
        "policy_expiry": expiry,
    }


async def anchor_daily_ledger(
    blob_service_client,
    *,
    container_name: str,
    ledger: dict,
    fallback_days: int,
) -> dict:
    """Upload, read back, and WORM-verify one deterministic root commitment."""

    if not container_name.strip():
        raise ValueError("EVIDENCE_DAILY_ANCHOR_CONTAINER is required")
    payload = build_anchor_payload(ledger)
    payload_hash = hashlib.sha256(payload).hexdigest()
    blob_name = anchor_blob_name(ledger)
    required_until = required_anchor_retention_until(ledger, fallback_days)
    container = blob_service_client.get_container_client(container_name)
    # Deliberately do not create or alter the container. Operators must provision
    # and lock it before enabling external anchors.
    await container.get_container_properties()
    blob = container.get_blob_client(blob_name)
    try:
        await blob.upload_blob(
            payload,
            overwrite=False,
            content_settings=ContentSettings(content_type="application/json"),
            metadata={
                "warsoc_schema": ANCHOR_SCHEMA_VERSION,
                "sha256": payload_hash,
            },
        )
    except ResourceExistsError:
        pass

    downloader = await blob.download_blob()
    observed = await downloader.readall()
    if observed != payload or hashlib.sha256(observed).hexdigest() != payload_hash:
        raise RuntimeError("Existing Azure daily anchor conflicts with the verified ledger")
    properties = await blob.get_blob_properties()
    immutability = _immutability_status(properties, required_until)
    if not immutability["verified"]:
        raise RuntimeError("Azure daily anchor is not protected by adequate locked immutability")
    return {
        "status": "VERIFIED",
        "schema_version": ANCHOR_SCHEMA_VERSION,
        "container_name": container_name,
        "blob_name": blob_name,
        "payload_sha256": payload_hash,
        "required_retention_until": required_until,
        "immutability": immutability,
    }

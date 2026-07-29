from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

import orjson
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.network_relay.parsers import ParsedNetworkEvent


SCHEMA_VERSION = "warsoc-relay-batch-v1"
GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class SignedRelayBatch:
    body: bytes
    signature: str
    batch_hash: str
    sequence: int
    event_count: int


def relay_event_from_parsed(
    parsed: ParsedNetworkEvent,
    *,
    device_id: str,
    transport: str,
    source_address: str,
    raw_message: str,
    relay_receipt_time: datetime,
    event_uid: str | None = None,
) -> dict[str, Any]:
    """Build the immutable event stored in the evidence spool before retry."""
    relay_time = relay_receipt_time.astimezone(timezone.utc)
    device_time = (
        parsed.device_event_time.astimezone(timezone.utc)
        if parsed.device_event_time is not None
        else None
    )
    return {
        "event_uid": event_uid or f"relay-{uuid.uuid4().hex}",
        "device_id": device_id,
        "vendor": parsed.vendor,
        "transport": transport,
        "source_address": source_address,
        "device_event_time": device_time.isoformat() if device_time else None,
        "relay_receipt_time": relay_time.isoformat(),
        "raw_message": raw_message,
        "raw_message_hash": hashlib.sha256(raw_message.encode("utf-8")).hexdigest(),
        "normalized": parsed.normalized,
    }


def build_signed_batch(
    *,
    relay_id: str,
    chain_id: str,
    key_epoch: int,
    sequence: int,
    previous_batch_hash: str,
    events: Iterable[dict[str, Any]],
    private_key_pem: bytes,
    created_at: datetime | None = None,
) -> SignedRelayBatch:
    """Create deterministic bytes and an Ed25519 signature for cloud admission.

    The caller advances its local checkpoint only after the cloud acknowledges
    this exact ``batch_hash``. Rebuilding a retry with modified timestamps or
    event ordering would intentionally create a different batch and is invalid.
    """
    event_list = list(events)
    if not event_list:
        raise ValueError("relay batch must contain at least one event")
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except Exception as exc:
        raise ValueError("relay private key is unreadable") from exc
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("relay private key must be Ed25519")
    timestamp = (created_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    body = orjson.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "relay_id": relay_id,
            "chain_id": chain_id,
            "key_epoch": key_epoch,
            "sequence": sequence,
            "previous_batch_hash": previous_batch_hash,
            "created_at": timestamp.isoformat(),
            "events": event_list,
        },
        option=orjson.OPT_SORT_KEYS,
    )
    return SignedRelayBatch(
        body=body,
        signature=private_key.sign(body).hex(),
        batch_hash=hashlib.sha256(body).hexdigest(),
        sequence=sequence,
        event_count=len(event_list),
    )


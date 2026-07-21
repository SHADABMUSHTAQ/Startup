import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


EVENT_SIGNATURE_VERSION = "ed25519-v1"


class AgentEventSignatureError(ValueError):
    """Raised when endpoint evidence cannot be authenticated."""


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    )


def build_payload_hash(signable_payload: dict[str, Any]) -> str:
    canonical = canonical_json(signable_payload)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_signable_event_payload(payload: dict[str, Any]) -> dict[str, Any]:
    raw_event_data = payload.get("raw_event_data")
    if raw_event_data is None:
        raw_event_data = payload.get("raw_data", {})

    return {
        "source_ip": payload.get("source_ip", ""),
        "user": payload.get("user", ""),
        "event_id": "" if payload.get("event_id") is None else str(payload.get("event_id")).strip(),
        "event_type": payload.get("event_type", ""),
        "message": payload.get("message", ""),
        "processed_data": payload.get("processed_data") or {},
        "raw_event_data": raw_event_data or {},
        "agent_version": payload.get("agent_version", ""),
    }


def build_event_signature_string(
    agent_id: str,
    timestamp: str,
    event_uid: str,
    payload_hash: str,
) -> str:
    return f"{agent_id}|{timestamp}|{event_uid}|{payload_hash}"


def public_key_id(public_key_pem: str) -> str:
    """Return a stable, non-secret identifier for an enrolled Ed25519 key."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as exc:
        raise AgentEventSignatureError("agent public key is unreadable") from exc
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise AgentEventSignatureError("agent public key is not Ed25519")
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def verify_event_signature(
    payload: dict[str, Any],
    *,
    agent_id: str,
    public_key_pem: str,
) -> dict[str, Any]:
    """Verify one canonical endpoint event and return durable provenance metadata."""
    signature_version = str(payload.get("signature_version") or "").strip().lower()
    if signature_version != EVENT_SIGNATURE_VERSION:
        raise AgentEventSignatureError("unsupported endpoint signature version")

    event_uid = str(payload.get("event_uid") or "").strip()
    timestamp = str(payload.get("timestamp") or "").strip()
    claimed_hash = str(payload.get("payload_hash") or "").strip().lower()
    signature_hex = str(payload.get("agent_signature") or "").strip().lower()
    if not event_uid or not timestamp or not claimed_hash or not signature_hex:
        raise AgentEventSignatureError("endpoint signature metadata is incomplete")
    if len(claimed_hash) != 64 or any(ch not in "0123456789abcdef" for ch in claimed_hash):
        raise AgentEventSignatureError("endpoint payload hash is malformed")
    if len(signature_hex) != 128 or any(ch not in "0123456789abcdef" for ch in signature_hex):
        raise AgentEventSignatureError("endpoint signature is malformed")

    computed_hash = build_payload_hash(build_signable_event_payload(payload))
    if not hmac.compare_digest(claimed_hash, computed_hash):
        raise AgentEventSignatureError("endpoint payload hash mismatch")

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise AgentEventSignatureError("agent public key is not Ed25519")
        signature_input = build_event_signature_string(
            agent_id,
            timestamp,
            event_uid,
            computed_hash,
        ).encode("utf-8")
        public_key.verify(bytes.fromhex(signature_hex), signature_input)
    except AgentEventSignatureError:
        raise
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise AgentEventSignatureError("endpoint signature verification failed") from exc
    except Exception as exc:
        raise AgentEventSignatureError("agent public key is unreadable") from exc

    return {
        "signature_version": EVENT_SIGNATURE_VERSION,
        "signature_algorithm": "Ed25519",
        "payload_hash": computed_hash,
        "signing_key_id": public_key_id(public_key_pem),
        "signature_verified": True,
        "source_assurance": "agent_signed",
        "signature_verified_at": datetime.now(timezone.utc).isoformat(),
    }


def parse_utc_timestamp(timestamp_str: str) -> Optional[datetime]:
    try:
        if not isinstance(timestamp_str, str):
            return None

        ts = timestamp_str.strip()
        if not ts:
            return None

        tz_suffix = ""
        ts_core = ts

        if ts_core.endswith("Z"):
            tz_suffix = "Z"
            ts_core = ts_core[:-1]
        elif (
            len(ts_core) >= 6
            and ts_core[-6] in "+-"
            and ts_core[-3] == ":"
            and ts_core[-5:-3].isdigit()
            and ts_core[-2:].isdigit()
        ):
            tz_suffix = ts_core[-6:]
            ts_core = ts_core[:-6]

        if "." in ts_core:
            head, frac = ts_core.rsplit(".", 1)
            if frac.isdigit() and len(frac) == 7:
                ts_core = f"{head}.{frac[:6]}"

        normalized_ts = f"{ts_core}{tz_suffix}"
        parsed = datetime.fromisoformat(normalized_ts.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def timestamp_age_seconds(timestamp_str: str) -> Optional[int]:
    parsed = parse_utc_timestamp(timestamp_str)
    if parsed is None:
        return None
    return int((datetime.now(timezone.utc) - parsed).total_seconds())

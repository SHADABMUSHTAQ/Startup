"""Cryptographic helpers for private WarSOC detection connectors."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timezone
from typing import Mapping

from cryptography.fernet import Fernet, InvalidToken


NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


class ConnectorSecurityError(ValueError):
    pass


class ConnectorBodyTooLarge(ConnectorSecurityError):
    pass


async def read_bounded_request_body(request, *, max_bytes: int) -> bytes:
    """Read a connector request without buffering beyond the configured cap."""
    claimed_length = request.headers.get("content-length")
    if claimed_length is not None:
        try:
            parsed_length = int(claimed_length)
        except (TypeError, ValueError) as exc:
            raise ConnectorSecurityError("invalid connector content length") from exc
        if parsed_length < 0:
            raise ConnectorSecurityError("invalid connector content length")
        if parsed_length > max_bytes:
            raise ConnectorBodyTooLarge("connector request exceeds byte limit")

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > max_bytes:
            raise ConnectorBodyTooLarge("connector request exceeds byte limit")
        body.extend(chunk)
    if not body:
        raise ConnectorSecurityError("connector request body is empty")
    return bytes(body)


def utc_timestamp(value: datetime | None = None) -> str:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ConnectorSecurityError("connector timestamp must be timezone-aware")
    return current.astimezone(timezone.utc).strftime(TIMESTAMP_FORMAT)


def parse_utc_timestamp(value: str) -> datetime:
    try:
        return datetime.strptime(str(value), TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise ConnectorSecurityError("invalid connector timestamp") from exc


def body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def signing_message(
    *,
    connector_id: str,
    timestamp: str,
    nonce: str,
    body_hash: str,
) -> bytes:
    if not NONCE_PATTERN.fullmatch(str(nonce or "")):
        raise ConnectorSecurityError("invalid connector nonce")
    if not re.fullmatch(r"[a-f0-9]{64}", str(body_hash or "")):
        raise ConnectorSecurityError("invalid connector body hash")
    parts = ("warsoc-connector-v1", connector_id, timestamp, nonce, body_hash)
    if any("\n" in str(part) or "\r" in str(part) for part in parts):
        raise ConnectorSecurityError("invalid connector signing field")
    return "\n".join(parts).encode("utf-8")


def sign_request(
    *,
    secret: str,
    connector_id: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> str:
    key = str(secret or "").encode("utf-8")
    if len(key) < 32:
        raise ConnectorSecurityError("connector signing secret must be at least 32 bytes")
    message = signing_message(
        connector_id=connector_id,
        timestamp=timestamp,
        nonce=nonce,
        body_hash=body_sha256(body),
    )
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def build_signed_headers(
    *,
    secret: str,
    connector_id: str,
    body: bytes,
    timestamp: datetime | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    timestamp_text = utc_timestamp(timestamp)
    nonce_text = nonce or secrets.token_urlsafe(24)
    signature = sign_request(
        secret=secret,
        connector_id=connector_id,
        timestamp=timestamp_text,
        nonce=nonce_text,
        body=body,
    )
    return {
        "X-WarSOC-Connector": connector_id,
        "X-WarSOC-Timestamp": timestamp_text,
        "X-WarSOC-Nonce": nonce_text,
        "X-WarSOC-Body-SHA256": body_sha256(body),
        "X-WarSOC-Signature": signature,
    }


def verify_signed_request(
    *,
    secret: str,
    expected_connector_id: str,
    headers: Mapping[str, str],
    body: bytes,
    now: datetime | None = None,
    max_skew_seconds: int = 300,
) -> tuple[str, datetime]:
    connector_id = str(headers.get("X-WarSOC-Connector") or "").strip()
    timestamp = str(headers.get("X-WarSOC-Timestamp") or "").strip()
    nonce = str(headers.get("X-WarSOC-Nonce") or "").strip()
    claimed_hash = str(headers.get("X-WarSOC-Body-SHA256") or "").strip().lower()
    signature = str(headers.get("X-WarSOC-Signature") or "").strip().lower()
    if connector_id != expected_connector_id:
        raise ConnectorSecurityError("connector identity mismatch")
    actual_hash = body_sha256(body)
    if not hmac.compare_digest(claimed_hash, actual_hash):
        raise ConnectorSecurityError("connector body hash mismatch")
    received_at = parse_utc_timestamp(timestamp)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ConnectorSecurityError("verification time must be timezone-aware")
    if abs((current.astimezone(timezone.utc) - received_at).total_seconds()) > max_skew_seconds:
        raise ConnectorSecurityError("connector timestamp is outside the allowed window")
    expected = sign_request(
        secret=secret,
        connector_id=connector_id,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    if not re.fullmatch(r"[a-f0-9]{64}", signature) or not hmac.compare_digest(signature, expected):
        raise ConnectorSecurityError("connector signature verification failed")
    return nonce, received_at


def purpose_hmac(secret: str, *, purpose: str, values: list[str]) -> str:
    key = str(secret or "").encode("utf-8")
    if len(key) < 32:
        raise ConnectorSecurityError("correlation HMAC secret must be at least 32 bytes")
    canonical = bytearray()
    for raw in [purpose, *values]:
        value = str(raw or "").strip().lower().encode("utf-8")
        canonical.extend(len(value).to_bytes(4, "big"))
        canonical.extend(value)
    return hmac.new(key, bytes(canonical), hashlib.sha256).hexdigest()


def fernet_cipher(key: str) -> Fernet:
    try:
        return Fernet(str(key or "").encode("ascii"))
    except (TypeError, ValueError) as exc:
        raise ConnectorSecurityError("invalid connector encryption key") from exc


def encrypt_payload(key: str, payload: bytes) -> str:
    return fernet_cipher(key).encrypt(payload).decode("ascii")


def decrypt_payload(key: str, token: str) -> bytes:
    try:
        return fernet_cipher(key).decrypt(str(token or "").encode("ascii"))
    except (InvalidToken, UnicodeEncodeError) as exc:
        raise ConnectorSecurityError("connector payload authentication failed") from exc

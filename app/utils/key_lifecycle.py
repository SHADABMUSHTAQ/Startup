"""Versioned source-envelope key selection without persisting key material."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from cryptography.fernet import Fernet

from app.config.config import get_settings


@dataclass(frozen=True)
class SourceEnvelopeKey:
    key_id: str
    version: int
    cipher: Fernet


def _cipher(key: Any, *, key_id: str) -> Fernet:
    try:
        return Fernet(str(key).encode("ascii"))
    except (AttributeError, TypeError, ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError(f"Source evidence key {key_id!r} is not a valid Fernet key") from exc


def _historical_keyring(settings) -> dict[str, SourceEnvelopeKey]:
    raw = settings.source_envelope_decryption_keys_json or "{}"
    try:
        configured = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Historical source evidence key ring is invalid JSON") from exc
    if not isinstance(configured, dict):
        raise RuntimeError("Historical source evidence key ring must be a JSON object")

    result: dict[str, SourceEnvelopeKey] = {}
    for key_id, entry in configured.items():
        if isinstance(entry, str):
            key_material = entry
            version = 1
        elif isinstance(entry, dict):
            key_material = entry.get("key", "")
            version = entry.get("version", 1)
        else:
            raise RuntimeError(f"Historical source evidence key {key_id!r} has an invalid entry")
        if not isinstance(version, int) or version < 1:
            raise RuntimeError(f"Historical source evidence key {key_id!r} has an invalid version")
        result[str(key_id)] = SourceEnvelopeKey(
            key_id=str(key_id),
            version=version,
            cipher=_cipher(key_material, key_id=str(key_id)),
        )
    return result


def active_source_envelope_key() -> SourceEnvelopeKey:
    settings = get_settings()
    key_material = settings.source_envelope_encryption_key or settings.encryption_key
    return SourceEnvelopeKey(
        key_id=settings.source_envelope_key_id,
        version=settings.source_envelope_key_version,
        cipher=_cipher(key_material, key_id=settings.source_envelope_key_id),
    )


def source_envelope_decryption_key(
    key_id: str | None,
    key_version: int | None = None,
) -> SourceEnvelopeKey:
    settings = get_settings()
    active = active_source_envelope_key()
    resolved = active if not key_id or key_id == active.key_id else _historical_keyring(settings).get(key_id)
    if resolved is None:
        raise RuntimeError(f"Source evidence decryption key {key_id!r} is not configured")
    if key_version is not None and int(key_version) != resolved.version:
        raise RuntimeError(
            f"Source evidence key version mismatch for {resolved.key_id!r}: "
            f"expected {key_version}, configured {resolved.version}"
        )
    return resolved

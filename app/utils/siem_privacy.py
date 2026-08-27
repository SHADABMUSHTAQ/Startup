"""Field-level protection for persisted SIEM evidence."""

from __future__ import annotations

import copy
import json
from typing import Any

from cryptography.fernet import Fernet

from app.utils.alert_context import redact_sensitive_text


SIEM_SENSITIVE_FIELDS = (
    "raw_message",
    "raw_event",
    "raw_event_data",
    "raw_data",
    "processed_data",
)
SIEM_ENCRYPTION_VERSION = "fernet-v1"


def _serialize(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return str(value)


def _encrypt(fernet: Fernet, value: Any) -> str:
    token = fernet.encrypt(_serialize(value).encode("utf-8")).decode("ascii")
    return f"{SIEM_ENCRYPTION_VERSION}:{token}"


def _safe_summary(document: dict) -> str:
    event_meaning = str(document.get("event_id_meaning") or "").strip()
    summary = str(document.get("summary") or document.get("display_message") or "").strip()
    event_id = str(document.get("event_id") or "unknown").strip()
    telemetry_family = str(document.get("telemetry_family") or "").strip().lower()

    if summary:
        return redact_sensitive_text(summary, limit=320)
    if event_meaning:
        return redact_sensitive_text(event_meaning, limit=320)
    if telemetry_family == "windows_native":
        return f"Windows event {event_id} observed"
    return f"Security telemetry event {event_id} observed"


def protect_siem_document(document: dict, encryption_key: str) -> dict:
    """Return a persistence copy with raw payloads encrypted and list fields bounded."""

    if not encryption_key:
        raise RuntimeError("ENCRYPTION_KEY is required for SIEM evidence persistence")
    try:
        fernet = Fernet(encryption_key.encode("ascii"))
    except Exception as exc:
        raise RuntimeError("ENCRYPTION_KEY is not a valid Fernet key") from exc

    protected = copy.deepcopy(document)
    original_message = protected.get("raw_message") or protected.get("message")
    if original_message not in (None, ""):
        protected["raw_message"] = original_message

    encrypted_fields = []
    for field in SIEM_SENSITIVE_FIELDS:
        value = protected.get(field)
        if value in (None, "", {}, []):
            continue
        protected[field] = _encrypt(fernet, value)
        encrypted_fields.append(field)

    context = protected.get("context")
    if isinstance(context, dict) and context.get("command_line"):
        protected["command_line_ciphertext"] = _encrypt(
            fernet,
            context.pop("command_line"),
        )
        encrypted_fields.append("command_line")

    protected["message"] = _safe_summary(protected)
    protected["display_message"] = protected["message"]
    protected["siem_sensitive_encryption_version"] = SIEM_ENCRYPTION_VERSION
    protected["siem_sensitive_fields"] = sorted(set(encrypted_fields))
    return protected


def decrypt_siem_value(value: Any, fernet: Fernet | None) -> Any:
    if not value or not isinstance(value, str) or fernet is None:
        return value
    token = value
    prefix = f"{SIEM_ENCRYPTION_VERSION}:"
    if token.startswith(prefix):
        token = token[len(prefix) :]
    try:
        plaintext = fernet.decrypt(token.encode("ascii")).decode("utf-8")
    except Exception:
        return value
    try:
        return json.loads(plaintext)
    except Exception:
        return plaintext

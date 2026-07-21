from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Optional
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken

from app.config.config import get_settings


TOTP_INTERVAL_SECONDS = 30
TOTP_DIGITS = 6
TOTP_ISSUER = "WarSOC"
_FERNET_PREFIX = "fernet-v1:"


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _b32_decode(secret: str) -> bytes:
    normalized = secret.strip().upper().replace(" ", "")
    padding = "=" * (-len(normalized) % 8)
    return base64.b32decode(normalized + padding, casefold=True)


def totp_code(secret: str, counter: Optional[int] = None) -> str:
    step = int(counter if counter is not None else time.time() // TOTP_INTERVAL_SECONDS)
    digest = hmac.new(_b32_decode(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**TOTP_DIGITS)).zfill(TOTP_DIGITS)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    value = str(code or "").strip()
    if len(value) != TOTP_DIGITS or not value.isdigit():
        return False

    current_counter = int(time.time() // TOTP_INTERVAL_SECONDS)
    return any(
        hmac.compare_digest(totp_code(secret, current_counter + delta), value)
        for delta in range(-window, window + 1)
    )


def build_otpauth_uri(username: str, secret: str) -> str:
    label = quote(f"{TOTP_ISSUER}:{username}", safe="")
    issuer = quote(TOTP_ISSUER, safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={issuer}"
        f"&digits={TOTP_DIGITS}&period={TOTP_INTERVAL_SECONDS}"
    )


def protect_totp_secret(secret: str) -> str:
    key = get_settings().encryption_key
    if not key:
        raise RuntimeError("ENCRYPTION_KEY is required to protect TOTP secrets")
    token = Fernet(key.encode("ascii")).encrypt(secret.encode("ascii")).decode("ascii")
    return f"{_FERNET_PREFIX}{token}"


def reveal_totp_secret(value: str) -> str:
    stored = str(value or "").strip()
    if not stored:
        raise ValueError("TOTP secret is missing")
    if not stored.startswith(_FERNET_PREFIX):
        # Compatibility for accounts configured before encrypted TOTP storage.
        return stored

    key = get_settings().encryption_key
    if not key:
        raise RuntimeError("ENCRYPTION_KEY is required to decrypt TOTP secrets")
    try:
        return Fernet(key.encode("ascii")).decrypt(
            stored[len(_FERNET_PREFIX) :].encode("ascii")
        ).decode("ascii")
    except (InvalidToken, ValueError) as exc:
        raise ValueError("Stored TOTP secret cannot be decrypted") from exc

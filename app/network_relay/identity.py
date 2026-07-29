from __future__ import annotations

import base64
import ctypes
import json
import os
import secrets
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


IDENTITY_SCHEMA_VERSION = "warsoc-relay-identity-v1"


class RelayIdentityError(RuntimeError):
    """The local relay identity cannot be loaded or protected safely."""


class SecretProtector(Protocol):
    def protect(self, plaintext: bytes) -> bytes: ...

    def unprotect(self, ciphertext: bytes) -> bytes: ...


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob(data: bytes) -> tuple[_DataBlob, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data)
    return (
        _DataBlob(
            len(data),
            ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
        ),
        buffer,
    )


class WindowsDpapiMachineProtector:
    """Protect relay secrets using Windows DPAPI machine scope.

    Filesystem ACLs remain mandatory. Machine-scope DPAPI protects data at rest
    but cannot defend against a fully compromised local SYSTEM account.
    """

    _CRYPTPROTECT_LOCAL_MACHINE = 0x4
    _CRYPTPROTECT_UI_FORBIDDEN = 0x1

    def __init__(self, *, entropy: bytes = b"WarSOC-Network-Relay-v1"):
        if os.name != "nt":
            raise RelayIdentityError("Windows DPAPI is available only on Windows")
        self._entropy = entropy
        self._crypt32 = ctypes.windll.crypt32
        self._kernel32 = ctypes.windll.kernel32

    def protect(self, plaintext: bytes) -> bytes:
        source, source_buffer = _blob(plaintext)
        entropy, entropy_buffer = _blob(self._entropy)
        output = _DataBlob()
        ok = self._crypt32.CryptProtectData(
            ctypes.byref(source),
            ctypes.c_wchar_p("WarSOC Relay Identity"),
            ctypes.byref(entropy),
            None,
            None,
            self._CRYPTPROTECT_LOCAL_MACHINE | self._CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output),
        )
        del source_buffer, entropy_buffer
        if not ok:
            raise RelayIdentityError("DPAPI could not protect the relay identity")
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            self._kernel32.LocalFree(output.pbData)

    def unprotect(self, ciphertext: bytes) -> bytes:
        source, source_buffer = _blob(ciphertext)
        entropy, entropy_buffer = _blob(self._entropy)
        output = _DataBlob()
        ok = self._crypt32.CryptUnprotectData(
            ctypes.byref(source),
            None,
            ctypes.byref(entropy),
            None,
            None,
            self._CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output),
        )
        del source_buffer, entropy_buffer
        if not ok:
            raise RelayIdentityError("DPAPI could not unprotect the relay identity")
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            self._kernel32.LocalFree(output.pbData)


@dataclass(frozen=True)
class RelayIdentity:
    registration_nonce: str
    private_key_pem_b64: str
    spool_key_b64: str
    relay_id: str | None = None
    tenant_id: str | None = None
    relay_token: str | None = None
    key_epoch: int = 1
    schema_version: str = IDENTITY_SCHEMA_VERSION

    @property
    def registered(self) -> bool:
        return bool(self.relay_id and self.tenant_id and self.relay_token)

    def private_key_pem(self) -> bytes:
        try:
            value = base64.b64decode(self.private_key_pem_b64, validate=True)
            key = serialization.load_pem_private_key(value, password=None)
        except Exception as exc:
            raise RelayIdentityError("relay signing key is invalid") from exc
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise RelayIdentityError("relay signing key is not Ed25519")
        return value

    def public_key_pem(self) -> str:
        key = serialization.load_pem_private_key(self.private_key_pem(), password=None)
        assert isinstance(key, ed25519.Ed25519PrivateKey)
        return key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def spool_key(self) -> bytes:
        try:
            value = base64.b64decode(self.spool_key_b64, validate=True)
        except Exception as exc:
            raise RelayIdentityError("relay spool key is invalid") from exc
        if len(value) != 32:
            raise RelayIdentityError("relay spool key must be 32 bytes")
        return value

    def with_registration(
        self,
        *,
        relay_id: str,
        tenant_id: str,
        relay_token: str,
        key_epoch: int,
    ) -> "RelayIdentity":
        return RelayIdentity(
            registration_nonce=self.registration_nonce,
            private_key_pem_b64=self.private_key_pem_b64,
            spool_key_b64=self.spool_key_b64,
            relay_id=relay_id,
            tenant_id=tenant_id,
            relay_token=relay_token,
            key_epoch=key_epoch,
        )


def new_pending_identity() -> RelayIdentity:
    key = ed25519.Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return RelayIdentity(
        registration_nonce=secrets.token_hex(16),
        private_key_pem_b64=base64.b64encode(private_pem).decode("ascii"),
        spool_key_b64=base64.b64encode(os.urandom(32)).decode("ascii"),
    )


class RelayIdentityStore:
    def __init__(self, path: str | Path, *, protector: SecretProtector):
        self.path = Path(path)
        self.protector = protector

    def exists(self) -> bool:
        return self.path.is_file()

    def save(self, identity: RelayIdentity) -> None:
        identity.private_key_pem()
        identity.spool_key()
        payload = json.dumps(asdict(identity), sort_keys=True, separators=(",", ":")).encode()
        protected = self.protector.protect(payload)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=str(self.path.parent),
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(protected)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    def load(self) -> RelayIdentity:
        try:
            protected = self.path.read_bytes()
            payload = json.loads(self.protector.unprotect(protected))
            identity = RelayIdentity(**payload)
        except Exception as exc:
            if isinstance(exc, RelayIdentityError):
                raise
            raise RelayIdentityError("relay identity file is unreadable") from exc
        if identity.schema_version != IDENTITY_SCHEMA_VERSION:
            raise RelayIdentityError("unsupported relay identity schema")
        identity.private_key_pem()
        identity.spool_key()
        return identity

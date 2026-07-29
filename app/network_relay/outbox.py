from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.network_relay.batch import SignedRelayBatch, build_signed_batch
from app.network_relay.spool import EncryptedBoundedSpool


@dataclass(frozen=True)
class PendingDelivery:
    batch: SignedRelayBatch
    spool_name: str
    through_sequence: int


class RelayOutboxError(RuntimeError):
    """The cloud-chain outbox cannot safely prepare or complete delivery."""


class RelayCloudRejected(RelayOutboxError):
    """The backend rejected identity, signature, or chain continuity."""


class RelayOutbox:
    """Persist the exact pending signed batch until cloud acknowledgement."""

    def __init__(
        self,
        path: str | Path,
        *,
        relay_id: str,
        private_key_pem: bytes,
        encryption_key: bytes,
        key_epoch: int = 1,
        chain_id: str | None = None,
    ):
        if len(encryption_key) != 32:
            raise ValueError("relay outbox encryption key must be 32 bytes")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.relay_id = relay_id
        self.private_key_pem = private_key_pem
        self._cipher = AESGCM(encryption_key)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA secure_delete=ON")
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS cloud_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton=1),
                relay_id TEXT NOT NULL,
                chain_id TEXT NOT NULL,
                key_epoch INTEGER NOT NULL,
                sequence INTEGER NOT NULL,
                last_batch_hash TEXT NOT NULL,
                pending_nonce BLOB,
                pending_ciphertext BLOB
            )
            """
        )
        self._db.execute(
            """
            INSERT OR IGNORE INTO cloud_state(
                singleton,relay_id,chain_id,key_epoch,sequence,last_batch_hash
            ) VALUES (1,?,?,?,?,?)
            """,
            (relay_id, chain_id or uuid.uuid4().hex, key_epoch, 0, "0" * 64),
        )
        row = self._state()
        if row["relay_id"] != relay_id:
            raise RelayOutboxError("relay outbox identity mismatch")

    def _state(self) -> sqlite3.Row:
        row = self._db.execute(
            "SELECT * FROM cloud_state WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise RelayOutboxError("relay cloud state is missing")
        return row

    def _encrypt_pending(self, payload: dict[str, Any]) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ciphertext = self._cipher.encrypt(nonce, plaintext, self.relay_id.encode())
        return nonce, ciphertext

    def _decrypt_pending(self, row: sqlite3.Row) -> PendingDelivery | None:
        if row["pending_nonce"] is None or row["pending_ciphertext"] is None:
            return None
        try:
            plaintext = self._cipher.decrypt(
                bytes(row["pending_nonce"]),
                bytes(row["pending_ciphertext"]),
                self.relay_id.encode(),
            )
            payload = json.loads(plaintext)
            body = base64.b64decode(payload["body_b64"], validate=True)
            batch_hash = hashlib.sha256(body).hexdigest()
            if not hmac.compare_digest(batch_hash, payload["batch_hash"]):
                raise ValueError("pending batch hash mismatch")
            batch = SignedRelayBatch(
                body=body,
                signature=payload["signature"],
                batch_hash=batch_hash,
                sequence=int(payload["sequence"]),
                event_count=int(payload["event_count"]),
            )
            return PendingDelivery(
                batch=batch,
                spool_name=payload["spool_name"],
                through_sequence=int(payload["through_sequence"]),
            )
        except Exception as exc:
            raise RelayOutboxError("pending relay batch is unreadable") from exc

    def pending(self) -> PendingDelivery | None:
        with self._lock:
            return self._decrypt_pending(self._state())

    def prepare(
        self,
        *,
        control_spool: EncryptedBoundedSpool,
        evidence_spool: EncryptedBoundedSpool,
        max_events: int = 200,
    ) -> PendingDelivery | None:
        if max_events < 1 or max_events > 1000:
            raise ValueError("relay batch size must be between 1 and 1000")
        with self._lock:
            state = self._state()
            pending = self._decrypt_pending(state)
            if pending is not None:
                return pending
            control_records = list(control_spool.records(limit=max_events))
            if control_records:
                spool_name = "control"
                selected = control_records
            else:
                spool_name = "evidence"
                selected = list(evidence_spool.records(limit=max_events))
            if not selected:
                return None
            batch = build_signed_batch(
                relay_id=self.relay_id,
                chain_id=str(state["chain_id"]),
                key_epoch=int(state["key_epoch"]),
                sequence=int(state["sequence"]) + 1,
                previous_batch_hash=str(state["last_batch_hash"]),
                events=[record.payload for record in selected],
                private_key_pem=self.private_key_pem,
            )
            payload = {
                "body_b64": base64.b64encode(batch.body).decode("ascii"),
                "signature": batch.signature,
                "batch_hash": batch.batch_hash,
                "sequence": batch.sequence,
                "event_count": batch.event_count,
                "spool_name": spool_name,
                "through_sequence": selected[-1].sequence,
            }
            nonce, ciphertext = self._encrypt_pending(payload)
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute(
                    """
                    UPDATE cloud_state
                    SET pending_nonce=?, pending_ciphertext=?
                    WHERE singleton=1 AND pending_nonce IS NULL
                    """,
                    (nonce, ciphertext),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            return self._decrypt_pending(self._state())

    def complete(
        self,
        batch_hash: str,
        *,
        control_spool: EncryptedBoundedSpool,
        evidence_spool: EncryptedBoundedSpool,
    ) -> int:
        with self._lock:
            pending = self._decrypt_pending(self._state())
            if pending is None:
                raise RelayOutboxError("no pending relay batch")
            if not hmac.compare_digest(pending.batch.batch_hash, batch_hash):
                raise RelayOutboxError("cloud acknowledgement hash mismatch")
            spool = control_spool if pending.spool_name == "control" else evidence_spool
            removed = spool.acknowledge_through(pending.through_sequence)
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute(
                    """
                    UPDATE cloud_state
                    SET sequence=?, last_batch_hash=?,
                        pending_nonce=NULL, pending_ciphertext=NULL
                    WHERE singleton=1
                    """,
                    (pending.batch.sequence, pending.batch.batch_hash),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            return removed

    def close(self) -> None:
        with self._lock:
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._db.close()


async def deliver_once(
    outbox: RelayOutbox,
    *,
    control_spool: EncryptedBoundedSpool,
    evidence_spool: EncryptedBoundedSpool,
    ingest_url: str,
    relay_token: str,
    client: httpx.AsyncClient,
    max_events: int = 200,
) -> str:
    pending = outbox.prepare(
        control_spool=control_spool,
        evidence_spool=evidence_spool,
        max_events=max_events,
    )
    if pending is None:
        return "idle"
    try:
        response = await client.post(
            ingest_url,
            content=pending.batch.body,
            headers={
                "Authorization": f"Bearer {relay_token}",
                "Content-Type": "application/json",
                "X-WarSOC-Signature": pending.batch.signature,
            },
        )
    except httpx.TransportError:
        return "retry"
    if response.status_code in {429, 500, 502, 503, 504}:
        return "retry"
    if response.status_code != 202:
        raise RelayCloudRejected(f"relay cloud rejected batch with HTTP {response.status_code}")
    try:
        result = response.json()
    except ValueError as exc:
        raise RelayCloudRejected("relay cloud returned an invalid acknowledgement") from exc
    if result.get("status") not in {"accepted", "duplicate_acknowledged"}:
        raise RelayCloudRejected("relay cloud acknowledgement status is invalid")
    if int(result.get("sequence") or 0) != pending.batch.sequence:
        raise RelayCloudRejected("relay cloud acknowledgement sequence mismatch")
    outbox.complete(
        pending.batch.batch_hash,
        control_spool=control_spool,
        evidence_spool=evidence_spool,
    )
    return str(result["status"])


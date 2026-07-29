from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


GENESIS_HASH = "0" * 64


class SpoolFullError(RuntimeError):
    """The bounded spool cannot safely accept another record."""


class SpoolIntegrityError(RuntimeError):
    """The authenticated ciphertext or record chain failed verification."""


@dataclass(frozen=True)
class SpoolRecord:
    sequence: int
    payload: dict[str, Any]
    record_hash: str


class EncryptedBoundedSpool:
    """Crash-safe, FIFO, drop-new relay spool backed by SQLite.

    Payloads are AES-GCM encrypted. SQLite transactions supply the commit
    boundary; accepted rows are never evicted to admit newer traffic. Key
    protection is the responsibility of the relay's CNG/DPAPI key store.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        stream_name: str,
        encryption_key: bytes,
        max_payload_bytes: int,
        max_record_bytes: int = 64 * 1024,
        min_free_disk_bytes: int = 256 * 1024 * 1024,
    ):
        if len(encryption_key) != 32:
            raise ValueError("relay spool encryption key must be 32 bytes")
        if max_payload_bytes < max_record_bytes:
            raise ValueError("spool capacity must fit at least one maximum record")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.stream_name = str(stream_name)
        self.max_payload_bytes = int(max_payload_bytes)
        self.max_record_bytes = int(max_record_bytes)
        self.min_free_disk_bytes = int(min_free_disk_bytes)
        self._cipher = AESGCM(encryption_key)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA secure_delete=ON")
            self._db.execute("PRAGMA wal_autocheckpoint=256")
            self._db.execute("PRAGMA journal_size_limit=8388608")
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS spool_records (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    previous_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL UNIQUE,
                    payload_bytes INTEGER NOT NULL,
                    commit_marker INTEGER NOT NULL CHECK (commit_marker = 1)
                )
                """
            )
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS spool_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            defaults = {
                "stream_name": self.stream_name,
                "used_bytes": "0",
                "ack_sequence": "0",
                "ack_hash": GENESIS_HASH,
                "tail_hash": GENESIS_HASH,
            }
            for key, value in defaults.items():
                self._db.execute(
                    "INSERT OR IGNORE INTO spool_meta(key,value) VALUES (?,?)",
                    (key, value),
                )
            stored_stream = self._meta("stream_name")
            if stored_stream != self.stream_name:
                raise SpoolIntegrityError("spool stream identity mismatch")
            self.verify_chain()

    def _meta(self, key: str) -> str:
        row = self._db.execute(
            "SELECT value FROM spool_meta WHERE key=?", (key,)
        ).fetchone()
        if row is None:
            raise SpoolIntegrityError(f"missing spool metadata: {key}")
        return str(row["value"])

    def _set_meta(self, key: str, value: str | int) -> None:
        self._db.execute(
            "UPDATE spool_meta SET value=? WHERE key=?", (str(value), key)
        )

    def _aad(self, sequence: int, previous_hash: str) -> bytes:
        return f"{self.stream_name}|{sequence}|{previous_hash}".encode("utf-8")

    @staticmethod
    def _record_hash(
        sequence: int,
        previous_hash: str,
        nonce: bytes,
        ciphertext: bytes,
    ) -> str:
        digest = hashlib.sha256()
        digest.update(str(sequence).encode("ascii"))
        digest.update(b"|")
        digest.update(previous_hash.encode("ascii"))
        digest.update(b"|")
        digest.update(nonce)
        digest.update(ciphertext)
        return digest.hexdigest()

    def append(self, payload: dict[str, Any]) -> SpoolRecord:
        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        if len(serialized) > self.max_record_bytes:
            raise SpoolFullError("record exceeds relay spool record boundary")
        if shutil.disk_usage(self.path.parent).free < self.min_free_disk_bytes + len(serialized):
            raise SpoolFullError("relay host disk reserve reached")

        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                used_bytes = int(self._meta("used_bytes"))
                if used_bytes + len(serialized) > self.max_payload_bytes:
                    raise SpoolFullError("relay spool capacity reached")
                previous_hash = self._meta("tail_hash")
                next_row = self._db.execute(
                    "SELECT seq FROM sqlite_sequence WHERE name='spool_records'"
                ).fetchone()
                sequence = int(next_row["seq"] if next_row else 0) + 1
                nonce = os.urandom(12)
                ciphertext = self._cipher.encrypt(
                    nonce,
                    serialized,
                    self._aad(sequence, previous_hash),
                )
                record_hash = self._record_hash(
                    sequence, previous_hash, nonce, ciphertext
                )
                self._db.execute(
                    """
                    INSERT INTO spool_records(
                        sequence,nonce,ciphertext,previous_hash,record_hash,
                        payload_bytes,commit_marker
                    ) VALUES (?,?,?,?,?,?,1)
                    """,
                    (
                        sequence,
                        nonce,
                        ciphertext,
                        previous_hash,
                        record_hash,
                        len(serialized),
                    ),
                )
                self._set_meta("used_bytes", used_bytes + len(serialized))
                self._set_meta("tail_hash", record_hash)
                self._db.execute("COMMIT")
                return SpoolRecord(sequence, payload, record_hash)
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def records(self, *, limit: int = 200) -> Iterator[SpoolRecord]:
        if limit < 1 or limit > 1000:
            raise ValueError("spool read limit must be between 1 and 1000")
        with self._lock:
            rows = list(
                self._db.execute(
                    "SELECT * FROM spool_records ORDER BY sequence ASC LIMIT ?",
                    (limit,),
                )
            )
        for row in rows:
            expected = self._record_hash(
                int(row["sequence"]),
                str(row["previous_hash"]),
                bytes(row["nonce"]),
                bytes(row["ciphertext"]),
            )
            if not hmac.compare_digest(expected, str(row["record_hash"])):
                raise SpoolIntegrityError("relay spool record hash mismatch")
            try:
                plaintext = self._cipher.decrypt(
                    bytes(row["nonce"]),
                    bytes(row["ciphertext"]),
                    self._aad(int(row["sequence"]), str(row["previous_hash"])),
                )
                payload = json.loads(plaintext)
            except Exception as exc:
                raise SpoolIntegrityError("relay spool decryption failed") from exc
            yield SpoolRecord(int(row["sequence"]), payload, expected)

    def acknowledge_through(self, sequence: int) -> int:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    """
                    SELECT sequence,record_hash FROM spool_records
                    WHERE sequence<=? ORDER BY sequence DESC LIMIT 1
                    """,
                    (sequence,),
                ).fetchone()
                if row is None:
                    self._db.execute("COMMIT")
                    return 0
                size_row = self._db.execute(
                    "SELECT COALESCE(SUM(payload_bytes),0) AS total FROM spool_records WHERE sequence<=?",
                    (int(row["sequence"]),),
                ).fetchone()
                removed_bytes = int(size_row["total"])
                result = self._db.execute(
                    "DELETE FROM spool_records WHERE sequence<=?",
                    (int(row["sequence"]),),
                )
                self._set_meta("ack_sequence", int(row["sequence"]))
                self._set_meta("ack_hash", str(row["record_hash"]))
                self._set_meta(
                    "used_bytes", max(0, int(self._meta("used_bytes")) - removed_bytes)
                )
                if self._db.execute("SELECT 1 FROM spool_records LIMIT 1").fetchone() is None:
                    self._set_meta("tail_hash", str(row["record_hash"]))
                self._db.execute("COMMIT")
                return max(0, int(result.rowcount))
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def verify_chain(self) -> None:
        with self._lock:
            expected_previous = self._meta("ack_hash")
            previous_sequence = int(self._meta("ack_sequence"))
            for row in self._db.execute(
                "SELECT * FROM spool_records ORDER BY sequence ASC"
            ):
                sequence = int(row["sequence"])
                if sequence != previous_sequence + 1:
                    raise SpoolIntegrityError("relay spool sequence gap")
                if not hmac.compare_digest(str(row["previous_hash"]), expected_previous):
                    raise SpoolIntegrityError("relay spool chain gap")
                expected_hash = self._record_hash(
                    sequence,
                    str(row["previous_hash"]),
                    bytes(row["nonce"]),
                    bytes(row["ciphertext"]),
                )
                if not hmac.compare_digest(expected_hash, str(row["record_hash"])):
                    raise SpoolIntegrityError("relay spool record hash mismatch")
                expected_previous = expected_hash
                previous_sequence = sequence
            if not hmac.compare_digest(self._meta("tail_hash"), expected_previous):
                raise SpoolIntegrityError("relay spool tail checkpoint mismatch")

    def stats(self) -> dict[str, int | str]:
        with self._lock:
            count = int(
                self._db.execute("SELECT COUNT(*) AS count FROM spool_records").fetchone()[
                    "count"
                ]
            )
            return {
                "stream_name": self.stream_name,
                "records": count,
                "used_bytes": int(self._meta("used_bytes")),
                "capacity_bytes": self.max_payload_bytes,
                "ack_sequence": int(self._meta("ack_sequence")),
            }

    def close(self) -> None:
        with self._lock:
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._db.close()


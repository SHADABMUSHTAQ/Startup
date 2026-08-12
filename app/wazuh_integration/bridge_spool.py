"""Crash-durable encrypted SQLite spools for the Compute-B bridge."""

from __future__ import annotations

import hashlib
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.wazuh_integration.security import decrypt_payload, encrypt_payload


class SpoolCapacityError(RuntimeError):
    pass


_SPOOL_IDENTITIES = {
    "input_spool": "dispatch_uid",
    "candidate_spool": "delivery_uid",
}
_HEALTH_TYPE_PATTERN = re.compile(r"^[A-Z0-9_]{3,64}$")


class BridgeSpool:
    def __init__(
        self,
        path: Path,
        encryption_key: str,
        *,
        input_record_ttl_seconds: int = 900,
        candidate_record_ttl_seconds: int = 86400,
        receipt_retention_seconds: int = 604800,
        health_retention_seconds: int = 2592000,
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._encryption_key = encryption_key
        self._input_record_ttl_seconds = input_record_ttl_seconds
        self._candidate_record_ttl_seconds = candidate_record_ttl_seconds
        self._receipt_retention_seconds = receipt_retention_seconds
        self._health_retention_seconds = health_retention_seconds
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._initialize()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _now_epoch() -> int:
        return int(datetime.now(timezone.utc).timestamp())

    @staticmethod
    def _table_identity(table: str, identity_name: str | None = None) -> str:
        expected = _SPOOL_IDENTITIES.get(table)
        if expected is None or (identity_name is not None and identity_name != expected):
            raise ValueError("invalid bridge spool table")
        return expected

    def _columns(self, table: str) -> set[str]:
        return {
            str(row["name"])
            for row in self._db.execute(f"PRAGMA table_info({table})").fetchall()
        }

    def _add_column(self, table: str, definition: str) -> None:
        name = definition.split()[0]
        if name not in self._columns(table):
            self._db.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")

    def _initialize(self) -> None:
        now_epoch = self._now_epoch()
        with self._db:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS input_spool (
                    dispatch_uid TEXT PRIMARY KEY,
                    payload_ciphertext TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    payload_bytes INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    next_attempt_epoch INTEGER NOT NULL DEFAULT 0,
                    record_expires_epoch INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_error TEXT
                );
                CREATE TABLE IF NOT EXISTS input_receipts (
                    dispatch_uid TEXT PRIMARY KEY,
                    payload_sha256 TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    expires_epoch INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS candidate_spool (
                    delivery_uid TEXT PRIMARY KEY,
                    payload_ciphertext TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    payload_bytes INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    next_attempt_epoch INTEGER NOT NULL DEFAULT 0,
                    record_expires_epoch INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_error TEXT
                );
                CREATE TABLE IF NOT EXISTS checkpoints (
                    checkpoint_name TEXT PRIMARY KEY,
                    file_identity TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    byte_offset INTEGER NOT NULL,
                    last_record_start INTEGER,
                    last_record_sha256 TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS request_nonces (
                    connector_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    expires_epoch INTEGER NOT NULL,
                    PRIMARY KEY(connector_id, nonce)
                );
                CREATE TABLE IF NOT EXISTS bridge_health_events (
                    event_uid TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL UNIQUE,
                    severity TEXT NOT NULL DEFAULT 'warning',
                    detail TEXT NOT NULL,
                    occurrence_count INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT,
                    export_pending INTEGER NOT NULL DEFAULT 1,
                    exported_at TEXT,
                    resolved_at TEXT
                );
                CREATE TABLE IF NOT EXISTS bridge_counters (
                    metric_name TEXT PRIMARY KEY,
                    metric_value INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                """
            )

            for table in _SPOOL_IDENTITIES:
                self._add_column(table, "next_attempt_epoch INTEGER NOT NULL DEFAULT 0")
                self._add_column(table, "record_expires_epoch INTEGER NOT NULL DEFAULT 0")
            self._add_column("input_receipts", "expires_epoch INTEGER NOT NULL DEFAULT 0")
            self._add_column("checkpoints", "last_record_start INTEGER")
            self._add_column("checkpoints", "last_record_sha256 TEXT")
            self._add_column("bridge_health_events", "severity TEXT NOT NULL DEFAULT 'warning'")
            self._add_column("bridge_health_events", "occurrence_count INTEGER NOT NULL DEFAULT 1")
            self._add_column("bridge_health_events", "last_seen_at TEXT")
            self._add_column("bridge_health_events", "export_pending INTEGER NOT NULL DEFAULT 1")
            self._add_column("bridge_health_events", "exported_at TEXT")

            self._db.execute(
                "UPDATE input_spool SET record_expires_epoch = ? WHERE record_expires_epoch <= 0",
                (now_epoch + self._input_record_ttl_seconds,),
            )
            self._db.execute(
                "UPDATE candidate_spool SET record_expires_epoch = ? WHERE record_expires_epoch <= 0",
                (now_epoch + self._candidate_record_ttl_seconds,),
            )
            self._db.execute(
                "UPDATE input_receipts SET expires_epoch = ? WHERE expires_epoch <= 0",
                (now_epoch + self._receipt_retention_seconds,),
            )
            self._db.execute(
                "UPDATE bridge_health_events SET last_seen_at = created_at WHERE last_seen_at IS NULL"
            )
            self._db.executescript(
                """
                CREATE INDEX IF NOT EXISTS idx_input_spool_queue_v2
                    ON input_spool(status, next_attempt_epoch, created_at);
                CREATE INDEX IF NOT EXISTS idx_candidate_spool_queue_v2
                    ON candidate_spool(status, next_attempt_epoch, created_at);
                CREATE INDEX IF NOT EXISTS idx_input_receipts_expiry
                    ON input_receipts(expires_epoch);
                CREATE INDEX IF NOT EXISTS idx_bridge_health_export
                    ON bridge_health_events(export_pending, last_seen_at);
                """
            )
        self.maintenance()

    def _active_bytes(self, table: str) -> int:
        self._table_identity(table)
        row = self._db.execute(
            f"SELECT COALESCE(SUM(payload_bytes), 0) AS total FROM {table} "
            "WHERE status IN ('pending', 'retry')"
        ).fetchone()
        return int(row["total"] or 0)

    def _accept(
        self,
        table: str,
        identity_name: str,
        identity: str,
        payload: bytes,
        max_bytes: int,
        *,
        expires_epoch: int,
    ) -> str:
        self._table_identity(table, identity_name)
        now_epoch = self._now_epoch()
        if expires_epoch <= now_epoch:
            raise ValueError("spool record is expired")
        payload_hash = hashlib.sha256(payload).hexdigest()
        ciphertext = encrypt_payload(self._encryption_key, payload)
        now = self._now()
        with self._lock, self._db:
            existing = self._db.execute(
                f"SELECT payload_sha256 FROM {table} WHERE {identity_name} = ?", (identity,)
            ).fetchone()
            if existing:
                if existing["payload_sha256"] != payload_hash:
                    raise ValueError("spool identity was reused with different payload bytes")
                return "duplicate"
            if self._active_bytes(table) + len(payload) > max_bytes:
                raise SpoolCapacityError(f"{table} capacity reached")
            self._db.execute(
                f"""
                INSERT INTO {table}
                    ({identity_name}, payload_ciphertext, payload_sha256, payload_bytes,
                     status, attempt_count, next_attempt_epoch, record_expires_epoch,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?)
                """,
                (
                    identity,
                    ciphertext,
                    payload_hash,
                    len(payload),
                    now_epoch,
                    expires_epoch,
                    now,
                    now,
                ),
            )
        return "accepted"

    def accept_input(
        self,
        dispatch_uid: str,
        payload: bytes,
        max_bytes: int,
        *,
        expires_epoch: int | None = None,
    ) -> str:
        payload_hash = hashlib.sha256(payload).hexdigest()
        with self._lock:
            receipt = self._db.execute(
                "SELECT payload_sha256 FROM input_receipts WHERE dispatch_uid = ?",
                (dispatch_uid,),
            ).fetchone()
        if receipt:
            if receipt["payload_sha256"] != payload_hash:
                raise ValueError("completed dispatch identity was reused with different payload bytes")
            return "duplicate"
        expiry = expires_epoch or (self._now_epoch() + self._input_record_ttl_seconds)
        return self._accept(
            "input_spool",
            "dispatch_uid",
            dispatch_uid,
            payload,
            max_bytes,
            expires_epoch=expiry,
        )

    def accept_candidate(
        self,
        delivery_uid: str,
        payload: bytes,
        max_bytes: int,
        *,
        expires_epoch: int | None = None,
    ) -> str:
        expiry = expires_epoch or (self._now_epoch() + self._candidate_record_ttl_seconds)
        return self._accept(
            "candidate_spool",
            "delivery_uid",
            delivery_uid,
            payload,
            max_bytes,
            expires_epoch=expiry,
        )

    def pending(self, table: str, identity_name: str, limit: int) -> list[dict[str, Any]]:
        self._table_identity(table, identity_name)
        now_epoch = self._now_epoch()
        with self._lock:
            rows = self._db.execute(
                f"""
                SELECT * FROM {table}
                WHERE status IN ('pending', 'retry')
                  AND next_attempt_epoch <= ?
                  AND record_expires_epoch > ?
                ORDER BY next_attempt_epoch ASC, created_at ASC
                LIMIT ?
                """,
                (now_epoch, now_epoch, limit),
            ).fetchall()
        result = []
        for row in rows:
            payload = decrypt_payload(self._encryption_key, row["payload_ciphertext"])
            if hashlib.sha256(payload).hexdigest() != row["payload_sha256"]:
                raise ValueError(f"{table} payload hash mismatch")
            result.append({**dict(row), "identity": row[identity_name], "payload": payload})
        return result

    def mark_complete(self, table: str, identity_name: str, identity: str) -> None:
        self._table_identity(table, identity_name)
        with self._lock, self._db:
            if table == "input_spool":
                row = self._db.execute(
                    "SELECT payload_sha256 FROM input_spool WHERE dispatch_uid = ?",
                    (identity,),
                ).fetchone()
                if row:
                    self._db.execute(
                        """
                        INSERT INTO input_receipts(
                            dispatch_uid, payload_sha256, completed_at, expires_epoch
                        ) VALUES (?, ?, ?, ?)
                        ON CONFLICT(dispatch_uid) DO UPDATE SET
                            payload_sha256 = excluded.payload_sha256,
                            completed_at = excluded.completed_at,
                            expires_epoch = excluded.expires_epoch
                        """,
                        (
                            identity,
                            row["payload_sha256"],
                            self._now(),
                            self._now_epoch() + self._receipt_retention_seconds,
                        ),
                    )
            self._db.execute(
                f"DELETE FROM {table} WHERE {identity_name} = ?",
                (identity,),
            )

    def mark_retry(
        self,
        table: str,
        identity_name: str,
        identity: str,
        error: str,
        *,
        base_seconds: int = 2,
        max_seconds: int = 300,
    ) -> int:
        self._table_identity(table, identity_name)
        with self._lock, self._db:
            row = self._db.execute(
                f"SELECT attempt_count FROM {table} WHERE {identity_name} = ?",
                (identity,),
            ).fetchone()
            if row is None:
                return 0
            attempts = int(row["attempt_count"] or 0) + 1
            delay = min(max_seconds, base_seconds * (2 ** min(attempts - 1, 16)))
            self._db.execute(
                f"""
                UPDATE {table}
                SET status = 'retry', attempt_count = ?, next_attempt_epoch = ?,
                    updated_at = ?, last_error = ?
                WHERE {identity_name} = ?
                """,
                (
                    attempts,
                    self._now_epoch() + delay,
                    self._now(),
                    str(error or "")[:512],
                    identity,
                ),
            )
        return attempts

    def remember_nonce(self, connector_id: str, nonce: str, expires_epoch: int) -> bool:
        now_epoch = self._now_epoch()
        with self._lock, self._db:
            self._db.execute("DELETE FROM request_nonces WHERE expires_epoch < ?", (now_epoch,))
            try:
                self._db.execute(
                    "INSERT INTO request_nonces(connector_id, nonce, expires_epoch) VALUES (?, ?, ?)",
                    (connector_id, nonce, expires_epoch),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def checkpoint(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM checkpoints WHERE checkpoint_name = ?", (name,)
            ).fetchone()
        return dict(row) if row else None

    def save_checkpoint(
        self,
        name: str,
        file_identity: str,
        file_path: str,
        byte_offset: int,
        *,
        last_record_start: int | None = None,
        last_record_sha256: str | None = None,
    ) -> None:
        if byte_offset < 0 or (last_record_start is not None and last_record_start < 0):
            raise ValueError("invalid alert checkpoint offset")
        with self._lock, self._db:
            self._db.execute(
                """
                INSERT INTO checkpoints(
                    checkpoint_name, file_identity, file_path, byte_offset,
                    last_record_start, last_record_sha256, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(checkpoint_name) DO UPDATE SET
                    file_identity = excluded.file_identity,
                    file_path = excluded.file_path,
                    byte_offset = excluded.byte_offset,
                    last_record_start = excluded.last_record_start,
                    last_record_sha256 = excluded.last_record_sha256,
                    updated_at = excluded.updated_at
                """,
                (
                    name,
                    file_identity,
                    file_path,
                    byte_offset,
                    last_record_start,
                    last_record_sha256,
                    self._now(),
                ),
            )

    def _health_event_locked(self, event_type: str, detail: str, severity: str) -> None:
        if not _HEALTH_TYPE_PATTERN.fullmatch(event_type):
            raise ValueError("invalid bridge health event type")
        if severity not in {"warning", "critical"}:
            raise ValueError("invalid bridge health event severity")
        event_uid = hashlib.sha256(event_type.encode("ascii")).hexdigest()
        now = self._now()
        self._db.execute(
            """
            INSERT INTO bridge_health_events(
                event_uid, event_type, severity, detail, occurrence_count,
                created_at, last_seen_at, export_pending
            ) VALUES (?, ?, ?, ?, 1, ?, ?, 1)
            ON CONFLICT(event_uid) DO UPDATE SET
                severity = excluded.severity,
                detail = excluded.detail,
                occurrence_count = bridge_health_events.occurrence_count + 1,
                last_seen_at = excluded.last_seen_at,
                export_pending = 1,
                resolved_at = NULL
            """,
            (event_uid, event_type, severity, str(detail)[:1024], now, now),
        )

    def health_event(self, event_type: str, detail: str, *, severity: str = "warning") -> None:
        with self._lock, self._db:
            self._health_event_locked(event_type, detail, severity)

    def increment_counter(self, name: str, amount: int = 1) -> None:
        if not re.fullmatch(r"[a-z0-9_]{3,64}", name) or amount < 1:
            raise ValueError("invalid bridge counter update")
        with self._lock, self._db:
            self._db.execute(
                """
                INSERT INTO bridge_counters(metric_name, metric_value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(metric_name) DO UPDATE SET
                    metric_value = bridge_counters.metric_value + excluded.metric_value,
                    updated_at = excluded.updated_at
                """,
                (name, amount, self._now()),
            )

    def counters(self) -> dict[str, int]:
        with self._lock:
            rows = self._db.execute(
                "SELECT metric_name, metric_value FROM bridge_counters ORDER BY metric_name"
            ).fetchall()
        return {str(row["metric_name"]): int(row["metric_value"] or 0) for row in rows}

    def pending_health_events(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                """
                SELECT event_uid, event_type, severity, detail, occurrence_count,
                       created_at, last_seen_at
                FROM bridge_health_events
                WHERE export_pending = 1
                ORDER BY last_seen_at ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_health_exported(self, event_uids: list[str]) -> None:
        if not event_uids:
            return
        placeholders = ",".join("?" for _ in event_uids)
        with self._lock, self._db:
            self._db.execute(
                f"UPDATE bridge_health_events SET export_pending = 0, exported_at = ? "
                f"WHERE event_uid IN ({placeholders})",
                (self._now(), *event_uids),
            )

    def maintenance(self) -> dict[str, int]:
        now_epoch = self._now_epoch()
        removed: dict[str, int] = {}
        with self._lock, self._db:
            for table, identity_name in _SPOOL_IDENTITIES.items():
                expired = self._db.execute(
                    f"SELECT {identity_name} FROM {table} "
                    "WHERE status IN ('pending', 'retry') AND record_expires_epoch <= ?",
                    (now_epoch,),
                ).fetchall()
                if expired:
                    self._db.execute(
                        f"DELETE FROM {table} "
                        "WHERE status IN ('pending', 'retry') AND record_expires_epoch <= ?",
                        (now_epoch,),
                    )
                    event_type = (
                        "INPUT_SPOOL_EXPIRED" if table == "input_spool" else "CANDIDATE_SPOOL_EXPIRED"
                    )
                    self._health_event_locked(
                        event_type,
                        f"{len(expired)} record(s) reached the bounded retry deadline",
                        "critical",
                    )
                removed[table] = len(expired)
            receipts = self._db.execute(
                "DELETE FROM input_receipts WHERE expires_epoch <= ?", (now_epoch,)
            ).rowcount
            nonces = self._db.execute(
                "DELETE FROM request_nonces WHERE expires_epoch <= ?", (now_epoch,)
            ).rowcount
            cutoff = datetime.fromtimestamp(
                now_epoch - self._health_retention_seconds, timezone.utc
            ).isoformat()
            health = self._db.execute(
                """
                DELETE FROM bridge_health_events
                WHERE export_pending = 0 AND last_seen_at < ?
                """,
                (cutoff,),
            ).rowcount
        removed.update(receipts=max(0, receipts), nonces=max(0, nonces), health=max(0, health))
        return removed

    def stats(self) -> dict[str, Any]:
        with self._lock:
            result: dict[str, Any] = {}
            for table in _SPOOL_IDENTITIES:
                rows = self._db.execute(
                    f"SELECT status, COUNT(*) AS count, COALESCE(SUM(payload_bytes), 0) AS bytes "
                    f"FROM {table} GROUP BY status"
                ).fetchall()
                result[table] = {
                    str(row["status"]): {
                        "count": int(row["count"] or 0),
                        "bytes": int(row["bytes"] or 0),
                    }
                    for row in rows
                }
            health = self._db.execute(
                "SELECT COUNT(*) AS count FROM bridge_health_events WHERE export_pending = 1"
            ).fetchone()
            pending_health = self._db.execute(
                "SELECT COUNT(*) AS count FROM bridge_health_events WHERE export_pending = 1"
            ).fetchone()
        result["unresolved_health_events"] = int(health["count"] or 0)
        result["pending_health_exports"] = int(pending_health["count"] or 0)
        result["counters"] = self.counters()
        return result

    def close(self) -> None:
        with self._lock:
            self._db.close()

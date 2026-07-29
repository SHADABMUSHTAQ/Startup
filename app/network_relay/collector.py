from __future__ import annotations

import hashlib
import ipaddress
import json
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from app.network_relay.batch import relay_event_from_parsed
from app.network_relay.parsers import NetworkParseError, ParsedNetworkEvent, parse_network_message
from app.network_relay.spool import EncryptedBoundedSpool, SpoolFullError


PARSER_VERSION = "network-native-v1"


@dataclass(frozen=True)
class RelayDevice:
    device_id: str
    vendor: str
    source_addresses: tuple[str, ...]
    transport: str = "udp"
    expected_eps: int = 100

    def __post_init__(self) -> None:
        if self.vendor not in {"fortinet", "cisco_asa", "mikrotik", "pfsense"}:
            raise ValueError("unsupported relay device vendor")
        if self.transport not in {"udp", "tcp", "tls", "api"}:
            raise ValueError("unsupported relay device transport")
        if self.expected_eps < 1 or self.expected_eps > 5000:
            raise ValueError("relay device expected EPS is outside the supported boundary")
        if not self.source_addresses:
            raise ValueError("relay device requires at least one source address")

    def networks(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        return tuple(ipaddress.ip_network(value, strict=False) for value in self.source_addresses)


@dataclass(frozen=True)
class IngressResult:
    status: str
    reason: str | None = None
    event_uid: str | None = None


class TokenBucket:
    def __init__(self, *, rate: float, capacity: float, now: float | None = None):
        if rate <= 0 or capacity <= 0:
            raise ValueError("token-bucket rate and capacity must be positive")
        self.rate = float(rate)
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.updated_at = float(time.monotonic() if now is None else now)

    def consume(self, amount: float = 1.0, *, now: float | None = None) -> bool:
        current = float(time.monotonic() if now is None else now)
        elapsed = max(0.0, current - self.updated_at)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.updated_at = current
        if amount > self.tokens:
            return False
        self.tokens -= amount
        return True


class RelayCollector:
    """Admit customer-LAN syslog into separate encrypted local spools.

    This class performs no cloud I/O. It is safe to test independently from
    the backend and deliberately treats UDP source IP as relay-observed, not
    device-authenticated identity.
    """

    def __init__(
        self,
        *,
        relay_id: str,
        devices: list[RelayDevice],
        evidence_spool: EncryptedBoundedSpool,
        control_spool: EncryptedBoundedSpool,
        max_datagram_bytes: int = 8192,
        global_eps: int = 2000,
        global_bytes_per_second: int = 5 * 1024 * 1024,
        parser_budget_ms: float = 25.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not devices:
            raise ValueError("relay requires at least one device contract")
        if max_datagram_bytes < 256 or max_datagram_bytes > 65535:
            raise ValueError("relay datagram boundary is invalid")
        self.relay_id = relay_id
        self.devices = devices
        self.evidence_spool = evidence_spool
        self.control_spool = control_spool
        self.max_datagram_bytes = int(max_datagram_bytes)
        self.parser_budget_ms = float(parser_budget_ms)
        self._clock = clock
        now = clock()
        self._global_events = TokenBucket(
            rate=global_eps, capacity=max(global_eps * 2, 1), now=now
        )
        self._global_bytes = TokenBucket(
            rate=global_bytes_per_second,
            capacity=max(global_bytes_per_second * 2, max_datagram_bytes),
            now=now,
        )
        self._device_buckets = {
            device.device_id: TokenBucket(
                rate=device.expected_eps,
                capacity=max(device.expected_eps * 2, 1),
                now=now,
            )
            for device in devices
        }
        self._networks = [
            (network, device)
            for device in devices
            for network in device.networks()
        ]
        self._losses: dict[tuple[str, str], dict[str, Any]] = {}
        self._lock = threading.RLock()

    def _device_for_source(self, source_address: str, transport: str) -> RelayDevice | None:
        try:
            address = ipaddress.ip_address(source_address)
        except ValueError:
            return None
        matches = [
            device
            for network, device in self._networks
            if address in network and device.transport == transport
        ]
        unique = {device.device_id: device for device in matches}
        if len(unique) != 1:
            return None
        return next(iter(unique.values()))

    def _record_loss(
        self,
        *,
        device_id: str,
        source_address: str,
        reason: str,
        byte_count: int,
        at: datetime,
    ) -> None:
        key = (device_id, reason)
        with self._lock:
            current = self._losses.setdefault(
                key,
                {
                    "device_id": device_id,
                    "source_address": source_address,
                    "reason": reason,
                    "dropped_events": 0,
                    "dropped_bytes": 0,
                    "interval_start": at,
                    "interval_end": at,
                },
            )
            current["dropped_events"] += 1
            current["dropped_bytes"] += max(0, byte_count)
            current["interval_end"] = at

    def accept_datagram(
        self,
        datagram: bytes,
        *,
        source_address: str,
        receipt_time: datetime | None = None,
    ) -> IngressResult:
        return self.accept_message(
            datagram,
            source_address=source_address,
            transport="udp",
            receipt_time=receipt_time,
        )

    def accept_message(
        self,
        payload: bytes,
        *,
        source_address: str,
        transport: str,
        receipt_time: datetime | None = None,
    ) -> IngressResult:
        received_at = (receipt_time or datetime.now(timezone.utc)).astimezone(timezone.utc)
        device = self._device_for_source(source_address, transport)
        if device is None:
            self._record_loss(
                device_id="unknown",
                source_address=source_address,
                reason="unregistered_or_ambiguous_source",
                byte_count=len(payload),
                at=received_at,
            )
            return IngressResult("dropped", "unregistered_or_ambiguous_source")
        if not payload or len(payload) > self.max_datagram_bytes:
            self._record_loss(
                device_id=device.device_id,
                source_address=source_address,
                reason="datagram_size_boundary",
                byte_count=len(payload),
                at=received_at,
            )
            return IngressResult("dropped", "datagram_size_boundary")

        now = self._clock()
        # Reject an over-limit device before charging the shared buckets. This
        # prevents one noisy or spoofed allowlisted source from exhausting the
        # capacity reserved for every other registered network device.
        allowed = (
            self._device_buckets[device.device_id].consume(now=now)
            and self._global_events.consume(now=now)
            and self._global_bytes.consume(len(payload), now=now)
        )
        if not allowed:
            self._record_loss(
                device_id=device.device_id,
                source_address=source_address,
                reason="edge_rate_limit",
                byte_count=len(payload),
                at=received_at,
            )
            return IngressResult("dropped", "edge_rate_limit")
        try:
            raw_message = payload.decode("utf-8", errors="strict").strip("\x00\r\n")
        except UnicodeDecodeError:
            self._record_loss(
                device_id=device.device_id,
                source_address=source_address,
                reason="invalid_utf8",
                byte_count=len(payload),
                at=received_at,
            )
            return IngressResult("quarantined", "invalid_utf8")
        started = time.perf_counter()
        try:
            parsed = parse_network_message(device.vendor, raw_message)
        except NetworkParseError:
            self._record_loss(
                device_id=device.device_id,
                source_address=source_address,
                reason="parser_rejected",
                byte_count=len(payload),
                at=received_at,
            )
            return IngressResult("quarantined", "parser_rejected")
        elapsed_ms = (time.perf_counter() - started) * 1000
        if elapsed_ms > self.parser_budget_ms:
            self._record_loss(
                device_id=device.device_id,
                source_address=source_address,
                reason="parser_budget_exceeded",
                byte_count=len(payload),
                at=received_at,
            )
            return IngressResult("quarantined", "parser_budget_exceeded")
        event_uid = f"relay-{uuid.uuid4().hex}"
        event = relay_event_from_parsed(
            parsed,
            device_id=device.device_id,
            transport=device.transport,
            source_address=source_address,
            raw_message=raw_message,
            relay_receipt_time=received_at,
            event_uid=event_uid,
        )
        try:
            self.evidence_spool.append(event)
        except SpoolFullError:
            self._record_loss(
                device_id=device.device_id,
                source_address=source_address,
                reason="evidence_spool_saturated",
                byte_count=len(payload),
                at=received_at,
            )
            return IngressResult("dropped", "evidence_spool_saturated")
        return IngressResult("accepted", event_uid=event_uid)

    def flush_loss_summaries(self) -> int:
        with self._lock:
            pending = list(self._losses.values())
            self._losses.clear()
        written = 0
        for loss in pending:
            normalized = {
                "event_type": "device_health",
                "state": "DEGRADED",
                "reason": loss["reason"],
                "dropped_events": loss["dropped_events"],
                "dropped_bytes": loss["dropped_bytes"],
                "interval_start": loss["interval_start"].isoformat(),
                "interval_end": loss["interval_end"].isoformat(),
                "src_ip": loss["source_address"],
                "spool_usage_bytes": self.evidence_spool.stats()["used_bytes"],
                "spool_capacity_bytes": self.evidence_spool.stats()["capacity_bytes"],
                "parser_version": PARSER_VERSION,
                "message": f"Relay ingress loss: {loss['reason']}",
            }
            raw_message = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
            control_event = {
                "event_uid": f"relay-control-{uuid.uuid4().hex}",
                "record_class": "control",
                "device_id": self.relay_id,
                "vendor": "generic",
                "transport": "api",
                "source_address": "127.0.0.1",
                "device_event_time": None,
                "relay_receipt_time": loss["interval_end"].isoformat(),
                "raw_message": raw_message,
                "raw_message_hash": hashlib.sha256(raw_message.encode("utf-8")).hexdigest(),
                "normalized": normalized,
            }
            try:
                self.control_spool.append(control_event)
                written += 1
            except SpoolFullError:
                # Keep the aggregate in memory for the next flush. No evidence
                # spool record is evicted to make room for control telemetry.
                key = (loss["device_id"], loss["reason"])
                with self._lock:
                    self._losses[key] = loss
        return written

    def emit_health(self, *, state: str, reason: str, message: str | None = None) -> bool:
        now = datetime.now(timezone.utc)
        evidence_stats = self.evidence_spool.stats()
        control_stats = self.control_spool.stats()
        normalized = {
            "event_type": "device_health",
            "state": str(state).upper()[:32],
            "reason": str(reason)[:200],
            "spool_usage_bytes": evidence_stats["used_bytes"],
            "spool_capacity_bytes": evidence_stats["capacity_bytes"],
            "evidence_spool_records": evidence_stats["records"],
            "control_spool_records": control_stats["records"],
            "parser_version": PARSER_VERSION,
            "message": (message or f"Relay health: {reason}")[:1000],
        }
        raw_message = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        event = {
            "event_uid": f"relay-control-{uuid.uuid4().hex}",
            "record_class": "control",
            "device_id": self.relay_id,
            "vendor": "generic",
            "transport": "api",
            "source_address": "127.0.0.1",
            "device_event_time": None,
            "relay_receipt_time": now.isoformat(),
            "raw_message": raw_message,
            "raw_message_hash": hashlib.sha256(raw_message.encode("utf-8")).hexdigest(),
            "normalized": normalized,
        }
        try:
            self.control_spool.append(event)
            return True
        except SpoolFullError:
            return False

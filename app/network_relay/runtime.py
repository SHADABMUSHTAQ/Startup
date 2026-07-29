from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import signal
import ssl
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.network_relay.collector import RelayCollector, RelayDevice
from app.network_relay.identity import (
    RelayIdentity,
    RelayIdentityError,
    RelayIdentityStore,
    WindowsDpapiMachineProtector,
    new_pending_identity,
)
from app.network_relay.outbox import RelayCloudRejected, RelayOutbox, deliver_once
from app.network_relay.spool import EncryptedBoundedSpool, SpoolIntegrityError


logger = logging.getLogger("warsoc.network_relay")
RUNTIME_CONFIG_VERSION = "warsoc-relay-runtime-v1"
DEFAULT_RELAY_VERSION = "1.0.0"


class RelayRuntimeError(RuntimeError):
    """The relay cannot continue without risking evidence loss or ambiguity."""


class RelayDeviceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    device_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    vendor: Literal["fortinet", "cisco_asa", "mikrotik", "pfsense"]
    source_addresses: list[str] = Field(min_length=1, max_length=16)
    transport: Literal["udp", "tcp", "tls"] = "udp"
    expected_eps: int = Field(default=100, ge=1, le=5000)

    @field_validator("source_addresses")
    @classmethod
    def validate_sources(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            candidate = str(value).strip()
            ipaddress.ip_network(candidate, strict=False)
            if candidate not in cleaned:
                cleaned.append(candidate)
        return cleaned


class RelayListenerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    transport: Literal["udp", "tcp", "tls"]
    bind_host: str
    port: int = Field(ge=1, le=65535)
    tls_certificate: str | None = None
    tls_private_key: str | None = None

    @field_validator("bind_host")
    @classmethod
    def validate_bind_host(cls, value: str) -> str:
        address = ipaddress.ip_address(value)
        if address.is_unspecified:
            raise ValueError("relay listeners must bind an explicit approved interface address")
        return str(address)

    @model_validator(mode="after")
    def validate_tls(self):
        if self.transport == "tls" and not (self.tls_certificate and self.tls_private_key):
            raise ValueError("TLS listener requires a certificate and private key")
        if self.transport != "tls" and (self.tls_certificate or self.tls_private_key):
            raise ValueError("TLS files are valid only for a TLS listener")
        return self


class RelayRuntimeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: Literal["warsoc-relay-runtime-v1"] = RUNTIME_CONFIG_VERSION
    backend_url: str
    relay_version: str = Field(default=DEFAULT_RELAY_VERSION, min_length=1, max_length=64)
    data_directory: str = r"C:\ProgramData\WarSOCRelay"
    identity_file: str = "identity.dpapi"
    activation_file: str = "activation.secret"
    devices: list[RelayDeviceConfig] = Field(min_length=1, max_length=50)
    listeners: list[RelayListenerConfig] = Field(min_length=1, max_length=3)
    evidence_spool_bytes: int = Field(default=2 * 1024**3, ge=64 * 1024**2, le=20 * 1024**3)
    control_spool_bytes: int = Field(default=64 * 1024**2, ge=8 * 1024**2, le=512 * 1024**2)
    minimum_free_disk_bytes: int = Field(default=1024**3, ge=256 * 1024**2)
    max_message_bytes: int = Field(default=8192, ge=256, le=65535)
    global_eps: int = Field(default=2000, ge=1, le=20000)
    global_bytes_per_second: int = Field(default=5 * 1024**2, ge=65536, le=100 * 1024**2)
    parser_budget_ms: float = Field(default=25.0, ge=1.0, le=250.0)
    batch_events: int = Field(default=200, ge=1, le=1000)
    delivery_idle_seconds: float = Field(default=1.0, ge=0.1, le=60.0)
    loss_flush_seconds: float = Field(default=5.0, ge=1.0, le=300.0)
    health_interval_seconds: float = Field(default=60.0, ge=10.0, le=3600.0)
    graceful_drain_seconds: int = Field(default=30, ge=1, le=300)
    request_timeout_seconds: float = Field(default=15.0, ge=2.0, le=120.0)

    @field_validator("backend_url")
    @classmethod
    def validate_backend_url(cls, value: str) -> str:
        parsed = urlparse(value.rstrip("/"))
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("relay backend URL must be an HTTPS origin without credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("relay backend URL cannot include a query or fragment")
        return value.rstrip("/")

    @model_validator(mode="after")
    def validate_contract(self):
        device_ids = [device.device_id for device in self.devices]
        if len(device_ids) != len(set(device_ids)):
            raise ValueError("relay device IDs must be unique")
        listener_transports = [listener.transport for listener in self.listeners]
        if len(listener_transports) != len(set(listener_transports)):
            raise ValueError("only one listener per transport is supported")
        missing = {device.transport for device in self.devices} - set(listener_transports)
        if missing:
            raise ValueError(f"missing listener for device transport: {sorted(missing)}")
        unused = set(listener_transports) - {device.transport for device in self.devices}
        if unused:
            raise ValueError(f"listener has no registered device contract: {sorted(unused)}")
        for name in (self.identity_file, self.activation_file):
            if Path(name).name != name or name in {".", ".."}:
                raise ValueError("identity and activation files must be simple file names")
        for transport in {device.transport for device in self.devices}:
            contracts = [device for device in self.devices if device.transport == transport]
            for index, left in enumerate(contracts):
                left_networks = [ipaddress.ip_network(value, strict=False) for value in left.source_addresses]
                for right in contracts[index + 1 :]:
                    right_networks = [
                        ipaddress.ip_network(value, strict=False) for value in right.source_addresses
                    ]
                    if any(a.overlaps(b) for a in left_networks for b in right_networks):
                        raise ValueError(
                            f"overlapping {transport} source contracts: "
                            f"{left.device_id} and {right.device_id}"
                        )
        return self

    @property
    def data_path(self) -> Path:
        return Path(self.data_directory)


class LifecycleJournal:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def read(self) -> dict[str, object]:
        if not self.path.exists():
            return {"state": "NEW"}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RelayRuntimeError("relay lifecycle journal is unreadable") from exc
        if not isinstance(value, dict) or not isinstance(value.get("state"), str):
            raise RelayRuntimeError("relay lifecycle journal is invalid")
        return value

    def write(self, state: str, **details: object) -> None:
        payload = {
            "state": state,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            **details,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=str(self.path.parent)
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, collector: RelayCollector):
        self.collector = collector

    def datagram_received(self, data: bytes, address) -> None:
        source = str(address[0])
        self.collector.accept_message(data, source_address=source, transport="udp")

    def error_received(self, exc: Exception) -> None:
        logger.warning("UDP relay listener reported an error: %s", type(exc).__name__)


async def _read_syslog_frame(reader: asyncio.StreamReader, max_bytes: int) -> bytes | None:
    first = await reader.read(1)
    if not first:
        return None
    if first.isdigit():
        digits = bytearray(first)
        while len(digits) <= 8:
            char = await reader.readexactly(1)
            if char == b" ":
                break
            if not char.isdigit():
                raise RelayRuntimeError("invalid RFC6587 octet-counted frame")
            digits.extend(char)
        else:
            raise RelayRuntimeError("RFC6587 frame length is too long")
        length = int(digits)
        if length < 1 or length > max_bytes:
            raise RelayRuntimeError("RFC6587 frame exceeds relay message boundary")
        return await reader.readexactly(length)
    remainder = await reader.readuntil(b"\n")
    frame = first + remainder
    if len(frame) > max_bytes:
        raise RelayRuntimeError("newline syslog frame exceeds relay message boundary")
    return frame.rstrip(b"\r\n")


class RelayRuntime:
    def __init__(
        self,
        config: RelayRuntimeConfig,
        *,
        identity_store: RelayIdentityStore,
        client: httpx.AsyncClient | None = None,
    ):
        self.config = config
        self.identity_store = identity_store
        self._client = client
        self._owns_client = client is None
        self._stop = asyncio.Event()
        self._udp_transports: list[asyncio.DatagramTransport] = []
        self._servers: list[asyncio.AbstractServer] = []
        self._tasks: list[asyncio.Task] = []
        self._started_at = time.monotonic()
        self._shutdown_complete = False
        self.identity: RelayIdentity | None = None
        self.evidence_spool: EncryptedBoundedSpool | None = None
        self.control_spool: EncryptedBoundedSpool | None = None
        self.collector: RelayCollector | None = None
        self.outbox: RelayOutbox | None = None
        self.journal = LifecycleJournal(config.data_path / "lifecycle.json")

    async def _http_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.config.request_timeout_seconds,
                follow_redirects=False,
            )
        return self._client

    async def _ensure_identity(self) -> RelayIdentity:
        if self.identity_store.exists():
            identity = self.identity_store.load()
        else:
            identity = new_pending_identity()
            self.identity_store.save(identity)
        if identity.registered:
            return identity

        activation_path = self.config.data_path / self.config.activation_file
        try:
            activation_code = activation_path.read_text(encoding="utf-8").strip()
        except FileNotFoundError as exc:
            raise RelayRuntimeError(
                "relay identity is pending but the protected activation file is missing"
            ) from exc
        if not 16 <= len(activation_code) <= 100:
            raise RelayRuntimeError("relay activation file is invalid")
        client = await self._http_client()
        try:
            endpoint = "recover-key" if activation_code.startswith(
                "WARSOC-RELAY-RECOVERY-"
            ) else "register"
            response = await client.post(
                f"{self.config.backend_url}/api/v1/network-relay/{endpoint}",
                json={
                    "activation_code": activation_code,
                    "registration_nonce": identity.registration_nonce,
                    "public_key": identity.public_key_pem(),
                    "hostname": os.environ.get("COMPUTERNAME") or "unknown-windows-host",
                    "version": self.config.relay_version,
                },
            )
        except httpx.TransportError as exc:
            raise RelayRuntimeError("relay registration service is unreachable") from exc
        if response.status_code != 200:
            raise RelayRuntimeError(f"relay registration failed with HTTP {response.status_code}")
        try:
            result = response.json()
            registered = identity.with_registration(
                relay_id=result["relay_id"],
                tenant_id=result["tenant_id"],
                relay_token=result["relay_token"],
                key_epoch=int(result["key_epoch"]),
            )
        except Exception as exc:
            raise RelayRuntimeError("relay registration response is invalid") from exc
        self.identity_store.save(registered)
        try:
            activation_path.unlink()
        except FileNotFoundError:
            pass
        return registered

    def _initialize_storage(self, identity: RelayIdentity) -> None:
        data = self.config.data_path
        data.mkdir(parents=True, exist_ok=True)
        key = identity.spool_key()
        self.evidence_spool = EncryptedBoundedSpool(
            data / "evidence-spool.db",
            stream_name="evidence",
            encryption_key=key,
            max_payload_bytes=self.config.evidence_spool_bytes,
            max_record_bytes=self.config.max_message_bytes * 3,
            min_free_disk_bytes=self.config.minimum_free_disk_bytes,
        )
        self.control_spool = EncryptedBoundedSpool(
            data / "control-spool.db",
            stream_name="control",
            encryption_key=key,
            max_payload_bytes=self.config.control_spool_bytes,
            max_record_bytes=self.config.max_message_bytes * 3,
            min_free_disk_bytes=self.config.minimum_free_disk_bytes,
        )
        self.evidence_spool.verify_chain()
        self.control_spool.verify_chain()
        devices = [
            RelayDevice(
                device_id=device.device_id,
                vendor=device.vendor,
                source_addresses=tuple(device.source_addresses),
                transport=device.transport,
                expected_eps=device.expected_eps,
            )
            for device in self.config.devices
        ]
        self.collector = RelayCollector(
            relay_id=str(identity.relay_id),
            devices=devices,
            evidence_spool=self.evidence_spool,
            control_spool=self.control_spool,
            max_datagram_bytes=self.config.max_message_bytes,
            global_eps=self.config.global_eps,
            global_bytes_per_second=self.config.global_bytes_per_second,
            parser_budget_ms=self.config.parser_budget_ms,
        )
        self.outbox = RelayOutbox(
            data / "cloud-outbox.db",
            relay_id=str(identity.relay_id),
            private_key_pem=identity.private_key_pem(),
            encryption_key=key,
            key_epoch=identity.key_epoch,
        )

    async def _handle_stream(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, transport: str
    ) -> None:
        peer = writer.get_extra_info("peername")
        source = str(peer[0]) if peer else ""
        try:
            while not self._stop.is_set():
                frame = await _read_syslog_frame(reader, self.config.max_message_bytes)
                if frame is None:
                    break
                assert self.collector is not None
                self.collector.accept_message(
                    frame,
                    source_address=source,
                    transport=transport,
                )
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, RelayRuntimeError):
            logger.warning("Rejected malformed %s syslog stream from %s", transport, source)
        finally:
            writer.close()
            await writer.wait_closed()

    async def _start_listeners(self) -> None:
        loop = asyncio.get_running_loop()
        assert self.collector is not None
        for listener in self.config.listeners:
            if listener.transport == "udp":
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _UdpProtocol(self.collector),
                    local_addr=(listener.bind_host, listener.port),
                )
                self._udp_transports.append(transport)
                continue
            context = None
            if listener.transport == "tls":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.load_cert_chain(listener.tls_certificate, listener.tls_private_key)
            server = await asyncio.start_server(
                lambda reader, writer, kind=listener.transport: self._handle_stream(
                    reader, writer, kind
                ),
                listener.bind_host,
                listener.port,
                ssl=context,
                limit=self.config.max_message_bytes + 64,
            )
            self._servers.append(server)

    async def _delivery_loop(self) -> None:
        assert self.identity and self.outbox and self.control_spool and self.evidence_spool
        client = await self._http_client()
        backoff = self.config.delivery_idle_seconds
        ingest_url = f"{self.config.backend_url}/api/v1/network-relay/ingest"
        while not self._stop.is_set():
            try:
                result = await deliver_once(
                    self.outbox,
                    control_spool=self.control_spool,
                    evidence_spool=self.evidence_spool,
                    ingest_url=ingest_url,
                    relay_token=str(self.identity.relay_token),
                    client=client,
                    max_events=self.config.batch_events,
                )
                backoff = self.config.delivery_idle_seconds
                if result == "idle":
                    await asyncio.sleep(self.config.delivery_idle_seconds)
            except RelayCloudRejected as exc:
                assert self.collector is not None
                self.collector.emit_health(
                    state="DEGRADED",
                    reason="cloud_rejected",
                    message=str(exc),
                )
                backoff = min(max(backoff * 2, 2.0), 300.0)
                await asyncio.sleep(backoff)
            except Exception:
                logger.exception("Relay delivery failed; retained batch will be retried")
                backoff = min(max(backoff * 2, 2.0), 300.0)
                await asyncio.sleep(backoff)

    async def _maintenance_loop(self) -> None:
        assert self.collector is not None
        next_health = time.monotonic()
        while not self._stop.is_set():
            self.collector.flush_loss_summaries()
            now = time.monotonic()
            if now >= next_health:
                self.collector.emit_health(state="ACTIVE", reason="periodic_health")
                next_health = now + self.config.health_interval_seconds
            await asyncio.sleep(self.config.loss_flush_seconds)

    async def start(self) -> None:
        previous = self.journal.read()
        self.journal.write("RECOVERING", previous_state=previous.get("state"))
        self.identity = await self._ensure_identity()
        try:
            self._initialize_storage(self.identity)
        except (SpoolIntegrityError, RelayIdentityError) as exc:
            self.journal.write("FAILED_INTEGRITY", error_type=type(exc).__name__)
            raise RelayRuntimeError("relay local evidence integrity check failed") from exc
        assert self.collector is not None
        if previous.get("state") not in {"NEW", "CHECKPOINTED", "STOPPED"}:
            self.collector.emit_health(
                state="DEGRADED",
                reason="unclean_recovery",
                message=f"Relay recovered after state {previous.get('state')}",
            )
        await self._start_listeners()
        self.journal.write("RUNNING", relay_id=self.identity.relay_id)
        self.collector.emit_health(state="ACTIVE", reason="service_started")
        self._tasks = [
            asyncio.create_task(self._delivery_loop(), name="relay-cloud-delivery"),
            asyncio.create_task(self._maintenance_loop(), name="relay-maintenance"),
        ]

    async def stop(self) -> None:
        if self._shutdown_complete:
            return
        self.journal.write("QUIESCING")
        self._stop.set()
        for transport in self._udp_transports:
            transport.close()
        for server in self._servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in self._servers))
        if self.collector is not None:
            self.collector.flush_loss_summaries()
            self.collector.emit_health(state="STOPPING", reason="graceful_shutdown")
        self.journal.write("DRAINING")
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        deadline = time.monotonic() + self.config.graceful_drain_seconds
        if self.identity and self.outbox and self.control_spool and self.evidence_spool:
            client = await self._http_client()
            while time.monotonic() < deadline:
                try:
                    result = await asyncio.wait_for(
                        deliver_once(
                            self.outbox,
                            control_spool=self.control_spool,
                            evidence_spool=self.evidence_spool,
                            ingest_url=(
                                f"{self.config.backend_url}/api/v1/network-relay/ingest"
                            ),
                            relay_token=str(self.identity.relay_token),
                            client=client,
                            max_events=self.config.batch_events,
                        ),
                        timeout=max(0.1, deadline - time.monotonic()),
                    )
                except Exception:
                    break
                if result in {"idle", "retry"}:
                    break
        pending_evidence = self.evidence_spool.stats()["records"] if self.evidence_spool else 0
        pending_control = self.control_spool.stats()["records"] if self.control_spool else 0
        self.journal.write(
            "CHECKPOINTED",
            pending_evidence=pending_evidence,
            pending_control=pending_control,
        )
        if self.outbox is not None:
            self.outbox.close()
        if self.evidence_spool is not None:
            self.evidence_spool.close()
        if self.control_spool is not None:
            self.control_spool.close()
        if self._owns_client and self._client is not None:
            await self._client.aclose()
        self.journal.write("STOPPED")
        self._shutdown_complete = True

    async def run(self) -> None:
        try:
            await self.start()
            await self._stop.wait()
        finally:
            await self.stop()


def load_runtime_config(path: str | Path) -> RelayRuntimeConfig:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return RelayRuntimeConfig.model_validate(payload)
    except Exception as exc:
        raise RelayRuntimeError("relay runtime configuration is invalid") from exc


def prepare_dead_key_recovery(
    config: RelayRuntimeConfig,
    *,
    identity_store: RelayIdentityStore,
) -> Path:
    """Preserve inaccessible state and create a new pending identity.

    This operation never deletes the previous spool. The tenant-authorized
    recovery endpoint records the cloud continuity break separately.
    """

    previous = LifecycleJournal(config.data_path / "lifecycle.json").read()
    if previous.get("state") in {"RUNNING", "QUIESCING", "DRAINING"}:
        raise RelayRuntimeError("stop the WarSOC Relay service before key recovery")
    activation_path = config.data_path / config.activation_file
    if not activation_path.is_file():
        raise RelayRuntimeError("protected relay recovery-code file is missing")
    recovery_code = activation_path.read_text(encoding="utf-8").strip()
    if not recovery_code.startswith("WARSOC-RELAY-RECOVERY-"):
        raise RelayRuntimeError("activation file does not contain a relay recovery code")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = config.data_path / f"dead-key-{timestamp}"
    archive.mkdir(parents=True, exist_ok=False)
    names = [
        config.identity_file,
        "evidence-spool.db",
        "control-spool.db",
        "cloud-outbox.db",
        "lifecycle.json",
    ]
    retained: list[str] = []
    for name in names:
        for suffix in ("", "-wal", "-shm"):
            source = config.data_path / f"{name}{suffix}"
            if source.exists():
                shutil.move(str(source), str(archive / source.name))
                retained.append(source.name)
    (archive / "evidence-gap.json").write_text(
        json.dumps(
            {
                "reason": "dead_key_recovery",
                "preserved_at": datetime.now(timezone.utc).isoformat(),
                "previous_lifecycle": previous,
                "retained_files": retained,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    identity_store.save(new_pending_identity())
    LifecycleJournal(config.data_path / "lifecycle.json").write(
        "KEY_RECOVERY_PENDING", preserved_directory=archive.name
    )
    return archive


async def _run_service(config_path: Path) -> None:
    config = load_runtime_config(config_path)
    protector = WindowsDpapiMachineProtector()
    store = RelayIdentityStore(config.data_path / config.identity_file, protector=protector)
    runtime = RelayRuntime(config, identity_store=store)
    loop = asyncio.get_running_loop()
    for name in ("SIGINT", "SIGTERM"):
        signal_value = getattr(signal, name, None)
        if signal_value is not None:
            try:
                loop.add_signal_handler(signal_value, runtime._stop.set)
            except NotImplementedError:
                pass
    try:
        await runtime.start()
        await runtime._stop.wait()
    finally:
        await runtime.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description="WarSOC customer-side network relay")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--prepare-key-recovery", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if os.name != "nt":
        raise SystemExit("WarSOC Relay runtime is supported only on Windows")
    if args.prepare_key_recovery:
        config = load_runtime_config(args.config)
        protector = WindowsDpapiMachineProtector()
        store = RelayIdentityStore(config.data_path / config.identity_file, protector=protector)
        archive = prepare_dead_key_recovery(config, identity_store=store)
        print(f"Previous relay state retained at {archive}")
        return 0
    asyncio.run(_run_service(args.config))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

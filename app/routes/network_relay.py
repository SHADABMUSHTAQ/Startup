from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import jwt
import orjson
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from packaging.version import InvalidVersion, Version
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import ORJSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from app.config.config import get_settings
from app.database import get_db
from app.network_relay.runtime import RelayRuntimeConfig
from app.routes.auth import (
    AGENT_TOKEN_EXPIRE_MINUTES,
    ALGORITHM,
    SECRET_KEY,
    create_access_token,
    get_current_user,
)
from app.routes.ingest_pulse import (
    INGEST_DAILY_QUOTA_TTL_SECONDS,
    PLATFORM_DAILY_INGEST_BYTES_MAX,
    _resolve_daily_ingest_quota_bytes,
    _enforce_raw_stream_capacity,
)
from app.utils.agent_crypto import public_key_id
from app.utils.limiter import limiter
from app.utils.rbac import RoleChecker
from app.utils.totp import reveal_totp_secret, verify_totp
from app.utils.source_provenance import apply_source_provenance
from app.utils.source_evidence import (
    SourceEvidenceConflict,
    persist_source_envelope,
    publish_source_outbox,
)


router = APIRouter()
settings = get_settings()
logger = logging.getLogger(__name__)
bearer = HTTPBearer(auto_error=False)

RELAY_SIGNATURE_VERSION = "relay-ed25519-v1"
RELAY_SCHEMA_VERSION = "warsoc-relay-batch-v1"
RELAY_GENESIS_HASH = "0" * 64
RAW_LOGS_QUEUE = "raw_logs_queue"
RAW_STREAM_MAX_ENTRIES = max(1, int(os.getenv("RAW_STREAM_MAX_ENTRIES", "500000")))
DEVICE_SILENCE_SECONDS = settings.network_relay_device_silence_seconds
INACTIVE_TENANT_STATUSES = {"inactive", "suspended", "cancelled", "canceled", "past_due"}
INACTIVE_RELAY_STATUSES = {"inactive", "revoked"}
RELAY_ID_PATTERN = re.compile(r"^WARSOC_RELAY_[a-f0-9]{32}$")
CHAIN_ID_PATTERN = re.compile(r"^[a-f0-9]{32}$")
HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")
EVENT_UID_PATTERN = re.compile(r"^[A-Za-z0-9_.:@/-]{8,200}$")

NETWORK_EVENT_IDS = {
    "network_connection_permitted": "NET-CONNECTION-ALLOW",
    "network_connection_blocked": "NET-CONNECTION-BLOCK",
    "vpn_authentication": "NET-VPN-AUTH",
    "vpn_session": "NET-VPN-SESSION",
    "dns_query": "NET-DNS-QUERY",
    "dhcp_lease": "NET-DHCP-LEASE",
    "device_admin": "NET-DEVICE-ADMIN",
    "device_health": "NET-DEVICE-HEALTH",
    "network_observation": "NET-OBSERVATION",
}

NORMALIZED_NETWORK_FIELDS = {
    "event_type",
    "action",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "user",
    "bytes_sent",
    "bytes_received",
    "policy_id",
    "session_id",
    "severity",
    "message_id",
    "interface_in",
    "interface_out",
    "vpn_tunnel",
    "hostname",
    "dns_query",
    "nat_source_ip",
    "nat_source_port",
    "message",
    "state",
    "reason",
    "dropped_events",
    "dropped_bytes",
    "interval_start",
    "interval_end",
    "observed_eps",
    "spool_usage_bytes",
    "spool_capacity_bytes",
    "parser_version",
    "direction",
    "ip_version",
    "rule_id",
    "tracker_id",
    "packet_length",
    "data_length",
    "tcp_flags",
    "icmp_type",
    "evidence_spool_records",
    "control_spool_records",
    "affected_device_id",
}


def _feature_guard() -> None:
    if not settings.network_relay_enabled:
        raise HTTPException(status_code=503, detail="Network relay service is not enabled")


def _redis_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


async def _claim_one_time_secret(
    redis,
    *,
    secret_key: str,
    claimant: str,
    invalid_detail: str,
) -> tuple[str, str]:
    claim_key = f"{secret_key}:claim"
    result = await redis.eval(
        "local secret=redis.call('GET',KEYS[1]); if not secret then return {0,''} end; "
        "local holder=redis.call('GET',KEYS[2]); "
        "if holder and holder ~= ARGV[1] then return {-1,''} end; "
        "if not holder then redis.call('SET',KEYS[2],ARGV[1],'EX',ARGV[2],'NX') end; "
        "return {1,secret}",
        2,
        secret_key,
        claim_key,
        claimant,
        300,
    )
    status = int(result[0]) if result else 0
    if status == 0:
        raise HTTPException(status_code=401, detail=invalid_detail)
    if status == -1:
        raise HTTPException(status_code=409, detail="One-time code is already in use")
    return _redis_text(result[1]) or "", claim_key


async def _consume_claimed_secret(
    redis,
    *,
    secret_key: str,
    claim_key: str,
    claimant: str,
) -> None:
    consumed = await redis.eval(
        "if redis.call('GET',KEYS[2]) == ARGV[1] then "
        "redis.call('DEL',KEYS[1]); redis.call('DEL',KEYS[2]); return 1 end; return 0",
        2,
        secret_key,
        claim_key,
        claimant,
    )
    if int(consumed or 0) != 1:
        logger.warning("One-time relay code commit marker was not consumed")


def _tenant_is_active(tenant: dict | None) -> bool:
    if not tenant:
        return False
    status = str(tenant.get("status") or "active").strip().lower()
    return bool(
        tenant.get("active", True) is not False
        and tenant.get("has_active_plan", True) is not False
        and status not in INACTIVE_TENANT_STATUSES
    )


def _tenant_relay_limit(tenant: dict | None) -> int:
    if not _tenant_is_active(tenant):
        return 0
    try:
        configured = int((tenant or {}).get("max_network_relays") or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, min(configured, settings.network_relay_max_per_tenant))


async def _resolve_tenant_relay_limit(
    redis, tenant: dict | None, tenant_id: str
) -> int:
    """Resolve a relay entitlement without allowing cache drift to grant more.

    The tenant document is the canonical grant. Redis is a hot-path mirror and
    may only lower that grant, never raise it above Mongo. This makes partial
    cross-store updates fail closed: a stale-high cache cannot authorize an
    extra relay, while a stale-low cache temporarily restricts activation.
    Cache misses and Redis failures fall back to the canonical document.
    """
    document_limit = _tenant_relay_limit(tenant)
    if document_limit <= 0:
        return 0
    if redis is not None:
        try:
            cached = _redis_text(
                await redis.get(f"tenant_max_network_relays:{tenant_id}")
            )
        except Exception:
            cached = None
        if cached is not None:
            try:
                configured = int(cached.strip())
            except (TypeError, ValueError):
                configured = None
            if configured is not None:
                cached_limit = max(
                    0, min(configured, settings.network_relay_max_per_tenant)
                )
                return min(document_limit, cached_limit)
    return document_limit


def _canonical_public_key(value: str) -> str:
    try:
        parsed = serialization.load_pem_public_key(value.encode("utf-8"))
        if not isinstance(parsed, ed25519.Ed25519PublicKey):
            raise ValueError("expected Ed25519 public key")
        return parsed.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid relay Ed25519 public key") from exc


def _ip_or_network(
    value: str,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid source address or CIDR: {value}") from exc


def _source_matches(source_address: str, configured: list[str]) -> bool:
    try:
        address = ipaddress.ip_address(source_address)
    except ValueError:
        return False
    return any(address in _ip_or_network(candidate) for candidate in configured)


def _parse_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _time_confidence(device_time: datetime | None, relay_time: datetime) -> tuple[str, int | None]:
    if device_time is None:
        return "unknown", None
    offset = int((_parse_utc(device_time) - _parse_utc(relay_time)).total_seconds())
    absolute = abs(offset)
    if absolute <= 120:
        return "high", offset
    if absolute <= 300:
        return "medium", offset
    return "low", offset


def _encrypt_relay_raw_data(raw_data: dict[str, Any]) -> str:
    """Protect raw vendor evidence before it enters shared cloud infrastructure."""
    key = str(settings.encryption_key or "").strip()
    if not key:
        raise RuntimeError("Network relay evidence encryption is not configured")
    try:
        cipher = Fernet(key.encode("ascii"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Network relay evidence encryption is invalid") from exc
    return cipher.encrypt(orjson.dumps(raw_data, option=orjson.OPT_SORT_KEYS)).decode("ascii")


def _reject_future_time(value: datetime, now: datetime, *, seconds: int = 300) -> None:
    # Historical signed batches are valid after an outage. Chain sequence and
    # exact-batch hashes provide replay protection; only impossible future
    # timestamps are rejected here.
    if (_parse_utc(value) - _parse_utc(now)).total_seconds() > seconds:
        raise ValueError("timestamp is in the future")


class RelayDeviceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    device_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    vendor: Literal["fortinet", "cisco_asa", "mikrotik", "pfsense"]
    model: str = Field(default="unknown", min_length=1, max_length=100)
    source_addresses: list[str] = Field(min_length=1, max_length=16)
    transport: Literal["udp", "tcp", "tls", "api"] = "udp"
    timezone: str = Field(default="UTC", min_length=1, max_length=64)
    expected_eps: int = Field(default=100, ge=1, le=5000)

    @field_validator("source_addresses")
    @classmethod
    def validate_sources(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            candidate = str(value).strip()
            _ip_or_network(candidate)
            if candidate not in cleaned:
                cleaned.append(candidate)
        return cleaned


class RelayListenerSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    transport: Literal["udp", "tcp"] = "udp"
    bind_host: str
    port: int = Field(default=5514, ge=1, le=65535)

    @field_validator("bind_host")
    @classmethod
    def validate_bind_host(cls, value: str) -> str:
        address = ipaddress.ip_address(value)
        if address.is_unspecified or address.is_multicast:
            raise ValueError("relay listener must use an explicit unicast address")
        return str(address)


class RelayActivationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    relay_name: str = Field(min_length=3, max_length=100)
    devices: list[RelayDeviceSpec] = Field(min_length=1, max_length=50)
    listeners: list[RelayListenerSpec] = Field(min_length=1, max_length=2)

    @model_validator(mode="after")
    def unique_devices(self):
        ids = [device.device_id for device in self.devices]
        if len(ids) != len(set(ids)):
            raise ValueError("Relay device IDs must be unique")
        device_transports = {device.transport for device in self.devices}
        if "api" in device_transports or "tls" in device_transports:
            raise ValueError("customer relay setup currently supports UDP or TCP syslog")
        listener_transports = [listener.transport for listener in self.listeners]
        if len(listener_transports) != len(set(listener_transports)):
            raise ValueError("Relay listener transports must be unique")
        if device_transports != set(listener_transports):
            raise ValueError("Every device transport must have exactly one relay listener")
        return self


def _runtime_configuration(body: RelayActivationRequest) -> dict[str, Any]:
    configuration = RelayRuntimeConfig(
        backend_url=settings.backend_public_url,
        relay_version=settings.network_relay_minimum_version,
        devices=[
            {
                "device_id": device.device_id,
                "vendor": device.vendor,
                "source_addresses": device.source_addresses,
                "transport": device.transport,
                "expected_eps": device.expected_eps,
            }
            for device in body.devices
        ],
        listeners=[
            {
                "transport": listener.transport,
                "bind_host": listener.bind_host,
                "port": listener.port,
            }
            for listener in body.listeners
        ],
    )
    return configuration.model_dump(mode="json", exclude_none=True)


class RelayRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    activation_code: str = Field(min_length=16, max_length=80)
    registration_nonce: str = Field(pattern=r"^[a-f0-9]{32}$")
    public_key: str = Field(min_length=80, max_length=1000)
    hostname: str = Field(min_length=1, max_length=255)
    version: str = Field(min_length=1, max_length=64)


class RelayRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    reason: str = Field(min_length=5, max_length=500)


class RelayRecoveryAuthorizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    reason: str = Field(min_length=5, max_length=500)
    totp_code: str = Field(pattern=r"^\d{6}$")


class RelayRecoverRequest(RelayRegisterRequest):
    pass


class RelayEvent(BaseModel):
    # Raw syslog text is signed evidence. Normalizing its whitespace before
    # hash verification changes the evidence and makes valid events fail.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    event_uid: str = Field(min_length=8, max_length=200)
    record_class: Literal["evidence", "control"] = "evidence"
    device_id: str = Field(min_length=1, max_length=64)
    vendor: Literal["fortinet", "cisco_asa", "mikrotik", "pfsense", "generic"]
    transport: Literal["udp", "tcp", "tls", "api"]
    source_address: str = Field(min_length=3, max_length=45)
    device_event_time: datetime | None = None
    relay_receipt_time: datetime
    raw_message: str = Field(min_length=1, max_length=8192)
    raw_message_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    normalized: dict[str, Any]

    @field_validator("event_uid")
    @classmethod
    def validate_event_uid(cls, value: str) -> str:
        if not EVENT_UID_PATTERN.fullmatch(value):
            raise ValueError("Invalid relay event UID")
        return value

    @field_validator("device_id")
    @classmethod
    def validate_device_id(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("Relay device ID must not contain surrounding whitespace")
        return value

    @field_validator("source_address")
    @classmethod
    def validate_source_address(cls, value: str) -> str:
        ipaddress.ip_address(value)
        return value

    @field_validator("normalized")
    @classmethod
    def validate_normalized(cls, value: dict[str, Any]) -> dict[str, Any]:
        unknown = set(value) - NORMALIZED_NETWORK_FIELDS
        if unknown:
            raise ValueError(f"Unsupported normalized network fields: {sorted(unknown)}")
        event_type = str(value.get("event_type") or "")
        if event_type not in NETWORK_EVENT_IDS:
            raise ValueError("Unsupported normalized network event type")
        ip_fields = {"src_ip", "dst_ip", "nat_source_ip"}
        port_fields = {"src_port", "dst_port", "nat_source_port"}
        nonnegative_fields = {
            "bytes_sent",
            "bytes_received",
            "dropped_events",
            "dropped_bytes",
            "observed_eps",
            "spool_usage_bytes",
            "spool_capacity_bytes",
            "packet_length",
            "data_length",
            "evidence_spool_records",
            "control_spool_records",
        }
        for key, item in value.items():
            if isinstance(item, (dict, list, tuple, set)):
                raise ValueError(f"Normalized field {key} must be scalar")
            if isinstance(item, str) and len(item) > 1000:
                raise ValueError(f"Normalized field {key} is too long")
            if item is None:
                continue
            if key in ip_fields:
                try:
                    ipaddress.ip_address(str(item))
                except ValueError as exc:
                    raise ValueError(f"Normalized field {key} must be an IP address") from exc
            if key in port_fields and (
                isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 65535
            ):
                raise ValueError(f"Normalized field {key} must be a valid port")
            if key in nonnegative_fields and (
                isinstance(item, bool) or not isinstance(item, int) or item < 0
            ):
                raise ValueError(f"Normalized field {key} must be a non-negative integer")
        return value

    @model_validator(mode="after")
    def verify_raw_hash(self):
        actual = hashlib.sha256(self.raw_message.encode("utf-8")).hexdigest()
        if not secrets.compare_digest(actual, self.raw_message_hash):
            raise ValueError("Relay raw message hash mismatch")
        if self.record_class == "control":
            if (
                self.vendor != "generic"
                or self.transport != "api"
                or self.normalized.get("event_type") != "device_health"
            ):
                raise ValueError("Relay control records must use the device-health contract")
        elif self.normalized.get("event_type") == "device_health":
            raise ValueError("Device-health records must use the control-record contract")
        return self


class RelayBatch(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: Literal["warsoc-relay-batch-v1"]
    relay_id: str
    chain_id: str
    key_epoch: int = Field(ge=1, le=2_147_483_647)
    sequence: int = Field(ge=1)
    previous_batch_hash: str
    created_at: datetime
    events: list[RelayEvent] = Field(min_length=1)

    @field_validator("relay_id")
    @classmethod
    def validate_relay_id(cls, value: str) -> str:
        if not RELAY_ID_PATTERN.fullmatch(value):
            raise ValueError("Invalid relay ID")
        return value

    @field_validator("chain_id")
    @classmethod
    def validate_chain_id(cls, value: str) -> str:
        if not CHAIN_ID_PATTERN.fullmatch(value):
            raise ValueError("Invalid relay chain ID")
        return value

    @field_validator("previous_batch_hash")
    @classmethod
    def validate_previous_hash(cls, value: str) -> str:
        if not HASH_PATTERN.fullmatch(value):
            raise ValueError("Invalid previous batch hash")
        return value


async def _relay_context(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db=Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Relay authentication required")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Relay token expired") from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid relay token") from exc

    relay_id = str(payload.get("sub") or "")
    tenant_id = str(payload.get("tenant_id") or "")
    jti = str(payload.get("jti") or "")
    if payload.get("type") != "network_relay" or not relay_id or not tenant_id or not jti:
        raise HTTPException(status_code=401, detail="Invalid relay token")

    redis = getattr(request.app.state, "redis", None)
    if redis is None:
        raise HTTPException(status_code=503, detail="Relay verification unavailable")
    if await redis.exists(f"warsoc:blacklist:{jti}") or await redis.exists(
        f"warsoc:relay_revoked:{relay_id}"
    ):
        raise HTTPException(status_code=403, detail="Relay has been revoked")

    cached = await redis.hgetall(f"warsoc:relay_cache:{relay_id}")
    if cached:
        cached_status = _redis_text(cached.get("status") or cached.get(b"status"))
        cached_tenant = _redis_text(cached.get("tenant_id") or cached.get(b"tenant_id"))
        public_key = _redis_text(cached.get("public_key") or cached.get(b"public_key"))
    else:
        cached_status = cached_tenant = public_key = None

    relay = None
    if cached_tenant != tenant_id or not public_key:
        relay = await db["network_relays"].find_one({"relay_id": relay_id})
        if not relay or relay.get("tenant_id") != tenant_id:
            raise HTTPException(status_code=401, detail="Unknown relay")
        cached_status = str(relay.get("status") or "active").lower()
        public_key = relay.get("public_key")
        await redis.hset(
            f"warsoc:relay_cache:{relay_id}",
            mapping={
                "tenant_id": tenant_id,
                "public_key": public_key,
                "status": cached_status,
            },
        )
        await redis.expire(f"warsoc:relay_cache:{relay_id}", 3600)
    if str(cached_status or "").lower() in INACTIVE_RELAY_STATUSES:
        raise HTTPException(status_code=403, detail="Relay is inactive")

    relay = relay or await db["network_relays"].find_one({"relay_id": relay_id})
    tenant = await db["tenants"].find_one({"tenant_id": tenant_id})
    if not relay or not _tenant_is_active(tenant):
        raise HTTPException(status_code=403, detail="Relay tenant is inactive")

    # Version gate (hardening): compute the rejection signal here; the ingest
    # route enforces it per record class so control/health records (the
    # relay's own heartbeat) still land when the relay is outdated — the
    # operator must see the relay to push an upgrade.
    relay_version = str(relay.get("version") or "0.0.0").strip()
    minimum_version = settings.network_relay_minimum_version
    version_gate = None
    if minimum_version and minimum_version != "0.0.0":
        try:
            if Version(relay_version) < Version(minimum_version):
                version_gate = {
                    "error": "relay_version_below_minimum",
                    "message": "Relay version below minimum; update required.",
                    "current_version": relay_version,
                    "minimum_version": minimum_version,
                }
        except InvalidVersion:
            version_gate = {
                "error": "relay_version_invalid",
                "message": "Relay version is not a valid PEP 440 string; update required.",
                "current_version": relay_version,
                "minimum_version": minimum_version,
            }

    return {
        "relay_id": relay_id,
        "tenant_id": tenant_id,
        "public_key": public_key,
        "relay": relay,
        "version_gate": version_gate,
    }


@router.post("/generate-activation")
@limiter.limit("20/minute")
async def generate_relay_activation(
    request: Request,
    body: RelayActivationRequest,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["Admin"])),
    db=Depends(get_db),
):
    _feature_guard()
    tenant_id = str(current_user.get("tenant_id") or "")
    tenant = await db["tenants"].find_one({"tenant_id": tenant_id})
    if not _tenant_is_active(tenant):
        raise HTTPException(status_code=403, detail="Tenant contract is inactive")
    redis = getattr(request.app.state, "redis", None)
    active_count = await db["network_relays"].count_documents(
        {"tenant_id": tenant_id, "status": {"$nin": list(INACTIVE_RELAY_STATUSES)}}
    )
    tenant_limit = await _resolve_tenant_relay_limit(redis, tenant, tenant_id)
    if active_count >= tenant_limit:
        raise HTTPException(status_code=403, detail="Network relay contract limit reached")

    if redis is None:
        raise HTTPException(status_code=503, detail="Relay activation unavailable")
    try:
        runtime_configuration = _runtime_configuration(body)
    except ValueError as exc:
        logger.error("Relay runtime configuration is invalid: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="Relay setup configuration is unavailable",
        ) from exc
    code = "WARSOC-RELAY-" + secrets.token_urlsafe(18).replace("-", "").replace("_", "")
    activation = {
        "purpose": "network_relay",
        "tenant_id": tenant_id,
        "relay_name": body.relay_name,
        "devices": [device.model_dump() for device in body.devices],
        "listeners": [listener.model_dump() for listener in body.listeners],
        "created_by": current_user.get("username") or current_user.get("email"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    ttl = settings.network_relay_activation_ttl_seconds
    await redis.set(
        f"warsoc:relay_activation:{code}", json.dumps(activation), ex=ttl
    )
    await db["management_audit"].insert_one(
        {
            "tenant_id": tenant_id,
            "operator": activation["created_by"],
            "action": "network_relay_activation_created",
            "relay_name": body.relay_name,
            "device_ids": [device.device_id for device in body.devices],
            "listener_transports": [
                listener.transport for listener in body.listeners
            ],
            "timestamp": datetime.now(timezone.utc),
        }
    )
    return {
        "activation_code": code,
        "expires_in_seconds": ttl,
        "setup": {
            "configuration_filename": "relay-config.json",
            "configuration": runtime_configuration,
            "package_available": bool(
                settings.network_relay_installer_url
                and settings.network_relay_installer_sha256
            ),
            "package_endpoint": "/api/v1/network-relay/setup-package",
            "package_sha256": settings.network_relay_installer_sha256 or None,
            "publisher_trust": "hash_allowlisted_pilot",
        },
    }


@router.post("/register")
@limiter.limit("20/minute")
async def register_relay(request: Request, body: RelayRegisterRequest, db=Depends(get_db)):
    _feature_guard()
    redis = getattr(request.app.state, "redis", None)
    if redis is None:
        raise HTTPException(status_code=503, detail="Relay registration unavailable")
    public_key = _canonical_public_key(body.public_key)
    key_id = public_key_id(public_key)
    activation_digest = hashlib.sha256(body.activation_code.encode("utf-8")).hexdigest()
    existing = await db["network_relays"].find_one(
        {"registration_nonce": body.registration_nonce}
    )
    if existing:
        if (
            existing.get("activation_digest") != activation_digest
            or existing.get("signing_key_id") != key_id
        ):
            raise HTTPException(status_code=409, detail="Relay registration nonce conflict")
        if str(existing.get("status") or "").lower() in INACTIVE_RELAY_STATUSES:
            raise HTTPException(status_code=403, detail="Relay is inactive")
        token = create_access_token(
            data={
                "sub": existing["relay_id"],
                "type": "network_relay",
                "tenant_id": existing["tenant_id"],
            },
            expires_delta=timedelta(minutes=AGENT_TOKEN_EXPIRE_MINUTES),
        )
        return {
            "relay_id": existing["relay_id"],
            "tenant_id": existing["tenant_id"],
            "relay_token": token,
            "key_epoch": int(existing.get("key_epoch") or 1),
            "signature_version": RELAY_SIGNATURE_VERSION,
            "schema_version": RELAY_SCHEMA_VERSION,
            "minimum_version": settings.network_relay_minimum_version,
            "registration_recovered": True,
        }
    if await db["network_relays"].find_one({"activation_digest": activation_digest}):
        raise HTTPException(status_code=409, detail="Relay activation was already consumed")
    activation_key = f"warsoc:relay_activation:{body.activation_code}"
    raw, activation_claim_key = await _claim_one_time_secret(
        redis,
        secret_key=activation_key,
        claimant=body.registration_nonce,
        invalid_detail="Invalid or expired relay activation",
    )
    try:
        activation = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=401, detail="Invalid relay activation") from exc
    if activation.get("purpose") != "network_relay":
        raise HTTPException(status_code=401, detail="Activation is not valid for a network relay")

    tenant_id = str(activation.get("tenant_id") or "")
    tenant = await db["tenants"].find_one({"tenant_id": tenant_id})
    if not _tenant_is_active(tenant):
        raise HTTPException(status_code=403, detail="Relay tenant is inactive")
    registration_lock_key = f"warsoc:relay_registration_lock:{tenant_id}"
    lock_acquired = await redis.set(
        registration_lock_key, body.registration_nonce, nx=True, ex=30
    )
    if not lock_acquired:
        raise HTTPException(status_code=409, detail="Relay registration is in progress")
    try:
        active_count = await db["network_relays"].count_documents(
            {"tenant_id": tenant_id, "status": {"$nin": list(INACTIVE_RELAY_STATUSES)}}
        )
        tenant_limit = await _resolve_tenant_relay_limit(redis, tenant, tenant_id)
        if active_count >= tenant_limit:
            raise HTTPException(status_code=403, detail="Network relay contract limit reached")

        relay_id = f"WARSOC_RELAY_{uuid.uuid4().hex}"
        now = datetime.now(timezone.utc)
        relay_doc = {
            "relay_id": relay_id,
            "tenant_id": tenant_id,
            "relay_name": activation["relay_name"],
            "hostname": body.hostname,
            "version": body.version,
            "public_key": public_key,
            "signing_key_id": key_id,
            "registration_nonce": body.registration_nonce,
            "activation_digest": activation_digest,
            "key_epoch": 1,
            "chain_id": None,
            "last_sequence": 0,
            "last_batch_hash": RELAY_GENESIS_HASH,
            "devices": activation["devices"],
            "listeners": activation.get("listeners") or [],
            "status": "active",
            "created_at": now,
            "last_seen": None,
            "last_ip": request.client.host if request.client else None,
        }
        await db["network_relays"].insert_one(relay_doc)
    finally:
        await redis.eval(
            "if redis.call('GET',KEYS[1]) == ARGV[1] then "
            "return redis.call('DEL',KEYS[1]) end; return 0",
            1,
            registration_lock_key,
            body.registration_nonce,
        )
    await _consume_claimed_secret(
        redis,
        secret_key=activation_key,
        claim_key=activation_claim_key,
        claimant=body.registration_nonce,
    )
    await redis.hset(
        f"warsoc:relay_cache:{relay_id}",
        mapping={"tenant_id": tenant_id, "public_key": public_key, "status": "active"},
    )
    await redis.expire(f"warsoc:relay_cache:{relay_id}", 3600)

    token = create_access_token(
        data={"sub": relay_id, "type": "network_relay", "tenant_id": tenant_id},
        expires_delta=timedelta(minutes=AGENT_TOKEN_EXPIRE_MINUTES),
    )
    await db["management_audit"].insert_one(
        {
            "tenant_id": tenant_id,
            "operator": relay_id,
            "action": "network_relay_registered",
            "relay_name": activation["relay_name"],
            "device_ids": [device["device_id"] for device in activation["devices"]],
            "timestamp": now,
        }
    )
    return {
        "relay_id": relay_id,
        "tenant_id": tenant_id,
        "relay_token": token,
        "key_epoch": 1,
        "signature_version": RELAY_SIGNATURE_VERSION,
        "schema_version": RELAY_SCHEMA_VERSION,
        "minimum_version": settings.network_relay_minimum_version,
    }


def _device_public_status(
    device: dict[str, Any],
    observation: dict[str, Any] | None,
    relay_health: str,
    now: datetime,
) -> dict[str, Any]:
    observation = observation or {}
    last_event_at = observation.get("last_event_at")
    last_failure_at = observation.get("last_failure_at")
    age_seconds = None
    if isinstance(last_event_at, datetime):
        age_seconds = max(0, int((now - _parse_utc(last_event_at)).total_seconds()))

    if relay_health in {"REVOKED", "INACTIVE", "OFFLINE"}:
        health = "RELAY_OFFLINE"
    elif age_seconds is None:
        health = "NOT_SEEN"
    elif age_seconds > DEVICE_SILENCE_SECONDS:
        health = "SILENT"
    elif (
        isinstance(last_failure_at, datetime)
        and _parse_utc(last_failure_at) >= _parse_utc(last_event_at)
    ):
        health = "DEGRADED"
    else:
        health = "ACTIVE"

    return {
        "device_id": device.get("device_id"),
        "vendor": device.get("vendor"),
        "model": device.get("model"),
        "transport": device.get("transport"),
        "expected_eps": device.get("expected_eps"),
        "health": health,
        "last_event_at": (
            last_event_at.isoformat() if isinstance(last_event_at, datetime) else None
        ),
        "last_event_age_seconds": age_seconds,
        "last_event_type": observation.get("last_event_type"),
        "time_confidence": observation.get("time_confidence"),
        "detected_clock_offset_seconds": observation.get(
            "detected_clock_offset_seconds"
        ),
        "last_failure_at": (
            last_failure_at.isoformat()
            if isinstance(last_failure_at, datetime)
            else None
        ),
        "last_failure_reason": observation.get("last_failure_reason"),
        "last_reported_drops": int(observation.get("last_reported_drops") or 0),
        "last_reported_dropped_bytes": int(
            observation.get("last_reported_dropped_bytes") or 0
        ),
    }


def _relay_public_status(
    relay: dict[str, Any],
    now: datetime,
    observations: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    status = str(relay.get("status") or "active").lower()
    last_seen = relay.get("last_seen")
    age_seconds = None
    if isinstance(last_seen, datetime):
        age_seconds = max(0, int((now - _parse_utc(last_seen)).total_seconds()))
    if status in INACTIVE_RELAY_STATUSES:
        health = "REVOKED" if status == "revoked" else "INACTIVE"
    elif age_seconds is None or age_seconds > 900:
        health = "OFFLINE"
    elif age_seconds > 180 or str(relay.get("last_health_state") or "").upper() == "DEGRADED":
        health = "DEGRADED"
    else:
        health = "ACTIVE"
    observations = observations or {}
    devices = [
        _device_public_status(
            device,
            observations.get(str(device.get("device_id") or "")),
            health,
            now,
        )
        for device in relay.get("devices") or []
    ]
    device_health_summary: dict[str, int] = {}
    for device in devices:
        device_health = str(device["health"])
        device_health_summary[device_health] = device_health_summary.get(device_health, 0) + 1

    return {
        "relay_id": relay.get("relay_id"),
        "relay_name": relay.get("relay_name"),
        "hostname": relay.get("hostname"),
        "version": relay.get("version"),
        "status": status,
        "health": health,
        "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else None,
        "last_seen_age_seconds": age_seconds,
        "last_health_state": relay.get("last_health_state"),
        "last_health_reason": relay.get("last_health_reason"),
        "key_epoch": int(relay.get("key_epoch") or 1),
        "chain_id": relay.get("chain_id"),
        "last_sequence": int(relay.get("last_sequence") or 0),
        "device_count": len(relay.get("devices") or []),
        "device_silence_threshold_seconds": DEVICE_SILENCE_SECONDS,
        "device_health_summary": device_health_summary,
        "devices": devices,
    }


@router.get("/contract")
@limiter.limit("10/minute")
async def relay_contract(request: Request):
    """Public relay compatibility contract so installers and operators can
    compare an installed relay version against the backend minimum before
    evidence ingest gets rejected. Rate-limited like every other unauthenticated
    boundary (PUBLIC_BOUNDED) even though it only exposes version constants."""
    _feature_guard()
    return {
        "minimum_version": settings.network_relay_minimum_version,
        "signature_version": RELAY_SIGNATURE_VERSION,
        "schema_version": RELAY_SCHEMA_VERSION,
        "setup_package_available": bool(
            settings.network_relay_installer_url
            and settings.network_relay_installer_sha256
        ),
        "setup_package_sha256": settings.network_relay_installer_sha256 or None,
        "publisher_trust": "hash_allowlisted_pilot",
    }


@router.get("/setup-package")
@limiter.limit("10/minute")
async def download_relay_setup_package(
    request: Request,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin"])),
    db=Depends(get_db),
):
    _feature_guard()
    tenant_id = str(current_user.get("tenant_id") or "")
    tenant = await db["tenants"].find_one({"tenant_id": tenant_id})
    if not _tenant_is_active(tenant):
        raise HTTPException(status_code=403, detail="Tenant contract is inactive")
    tenant_limit = await _resolve_tenant_relay_limit(
        getattr(request.app.state, "redis", None), tenant, tenant_id
    )
    if tenant_limit <= 0:
        raise HTTPException(status_code=403, detail="Network relay is not entitled")
    if not (
        settings.network_relay_installer_url
        and settings.network_relay_installer_sha256
    ):
        raise HTTPException(status_code=503, detail="Relay setup package is unavailable")
    return RedirectResponse(
        url=settings.network_relay_installer_url,
        status_code=307,
        headers={
            "Cache-Control": "no-store",
            "X-WarSOC-Artifact-SHA256": settings.network_relay_installer_sha256,
        },
    )


@router.get("/status")
async def list_relay_status(
    request: Request,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "manager", "analyst", "auditor"])),
    db=Depends(get_db),
):
    _feature_guard()
    tenant_id = str(current_user.get("tenant_id") or "")
    tenant = await db["tenants"].find_one({"tenant_id": tenant_id})
    tenant_limit = await _resolve_tenant_relay_limit(
        getattr(request.app.state, "redis", None), tenant, tenant_id
    )
    rows = await db["network_relays"].find({"tenant_id": tenant_id}).sort(
        "created_at", -1
    ).to_list(length=100)
    active_count = sum(
        1
        for row in rows
        if str(row.get("status") or "active").lower()
        not in INACTIVE_RELAY_STATUSES
    )
    relay_ids = [str(row.get("relay_id") or "") for row in rows if row.get("relay_id")]
    observations_by_relay: dict[str, dict[str, dict[str, Any]]] = {}
    if relay_ids:
        observations = await db["network_relay_device_status"].find(
            {"tenant_id": tenant_id, "relay_id": {"$in": relay_ids}}
        ).to_list(length=5000)
        for observation in observations:
            relay_id = str(observation.get("relay_id") or "")
            device_id = str(observation.get("device_id") or "")
            if relay_id and device_id:
                observations_by_relay.setdefault(relay_id, {})[device_id] = observation
    now = datetime.now(timezone.utc)
    return {
        "capability": {
            "enabled": True,
            "entitled": tenant_limit > 0,
            "max_relays": tenant_limit,
            "active_relays": active_count,
            "remaining_relays": max(0, tenant_limit - active_count),
            "can_manage": str(current_user.get("role") or "").strip().lower()
            == "admin",
            "metadata_only": True,
            "validated_firewall_vendors": ["pfsense"],
            "minimum_relay_version": settings.network_relay_minimum_version,
            "setup_package_available": bool(
                settings.network_relay_installer_url
                and settings.network_relay_installer_sha256
            ),
            "setup_package_endpoint": "/api/v1/network-relay/setup-package",
            "setup_package_sha256": settings.network_relay_installer_sha256 or None,
            "publisher_trust": "hash_allowlisted_pilot",
        },
        "relays": [
            _relay_public_status(
                row,
                now,
                observations_by_relay.get(str(row.get("relay_id") or "")),
            )
            for row in rows
        ]
    }


@router.post("/{relay_id}/revoke")
@limiter.limit("10/minute")
async def revoke_relay(
    relay_id: str,
    body: RelayRevokeRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin"])),
    db=Depends(get_db),
):
    _feature_guard()
    if not RELAY_ID_PATTERN.fullmatch(relay_id):
        raise HTTPException(status_code=404, detail="Relay not found")
    tenant_id = str(current_user.get("tenant_id") or "")
    now = datetime.now(timezone.utc)
    redis = getattr(request.app.state, "redis", None)
    if redis is None:
        raise HTTPException(status_code=503, detail="Relay revocation service unavailable")
    relay = await db["network_relays"].find_one(
        {"relay_id": relay_id, "tenant_id": tenant_id}, {"_id": 1}
    )
    if not relay:
        raise HTTPException(status_code=404, detail="Relay not found")
    await redis.set(f"warsoc:relay_revoked:{relay_id}", "revoked")
    await redis.delete(f"warsoc:relay_cache:{relay_id}")
    result = await db["network_relays"].update_one(
        {"relay_id": relay_id, "tenant_id": tenant_id},
        {"$set": {"status": "revoked", "revoked_at": now, "revoked_reason": body.reason}},
    )
    if result.matched_count != 1:
        raise HTTPException(status_code=404, detail="Relay not found")
    await db["management_audit"].insert_one(
        {
            "tenant_id": tenant_id,
            "operator": current_user.get("username") or current_user.get("email"),
            "action": "network_relay_revoked",
            "relay_id": relay_id,
            "reason": body.reason,
            "timestamp": now,
        }
    )
    return {"status": "revoked", "relay_id": relay_id}


@router.post("/{relay_id}/authorize-key-recovery")
@limiter.limit("5/minute")
async def authorize_relay_key_recovery(
    relay_id: str,
    body: RelayRecoveryAuthorizationRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin"])),
    db=Depends(get_db),
):
    _feature_guard()
    if not RELAY_ID_PATTERN.fullmatch(relay_id):
        raise HTTPException(status_code=404, detail="Relay not found")
    if not current_user.get("two_factor_enabled") or not current_user.get("two_factor_secret"):
        raise HTTPException(status_code=403, detail="MFA is required for relay key recovery")
    try:
        secret = reveal_totp_secret(current_user["two_factor_secret"])
    except Exception as exc:
        raise HTTPException(status_code=503, detail="MFA verification unavailable") from exc
    if not verify_totp(secret, body.totp_code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")
    tenant_id = str(current_user.get("tenant_id") or "")
    relay = await db["network_relays"].find_one(
        {"relay_id": relay_id, "tenant_id": tenant_id}
    )
    if not relay:
        raise HTTPException(status_code=404, detail="Relay not found")
    redis = getattr(request.app.state, "redis", None)
    if redis is None:
        raise HTTPException(status_code=503, detail="Relay recovery service unavailable")
    code = "WARSOC-RELAY-RECOVERY-" + secrets.token_urlsafe(18).replace("-", "").replace("_", "")
    now = datetime.now(timezone.utc)
    authorization = {
        "purpose": "network_relay_key_recovery",
        "tenant_id": tenant_id,
        "relay_id": relay_id,
        "authorized_by": current_user.get("username") or current_user.get("email"),
        "reason": body.reason,
        "previous_chain_id": relay.get("chain_id"),
        "previous_key_epoch": int(relay.get("key_epoch") or 1),
        "previous_sequence": int(relay.get("last_sequence") or 0),
        "previous_batch_hash": relay.get("last_batch_hash") or RELAY_GENESIS_HASH,
        "authorized_at": now.isoformat(),
    }
    await redis.set(
        f"warsoc:relay_recovery:{code}",
        json.dumps(authorization),
        ex=settings.network_relay_activation_ttl_seconds,
    )
    await db["management_audit"].insert_one(
        {
            "tenant_id": tenant_id,
            "operator": authorization["authorized_by"],
            "action": "network_relay_key_recovery_authorized",
            "relay_id": relay_id,
            "reason": body.reason,
            "timestamp": now,
        }
    )
    return {
        "recovery_code": code,
        "expires_in_seconds": settings.network_relay_activation_ttl_seconds,
        "relay_id": relay_id,
    }


@router.post("/recover-key")
@limiter.limit("10/minute")
async def recover_relay_key(request: Request, body: RelayRecoverRequest, db=Depends(get_db)):
    _feature_guard()
    redis = getattr(request.app.state, "redis", None)
    if redis is None:
        raise HTTPException(status_code=503, detail="Relay recovery service unavailable")
    public_key = _canonical_public_key(body.public_key)
    key_id = public_key_id(public_key)
    activation_digest = hashlib.sha256(body.activation_code.encode("utf-8")).hexdigest()
    existing = await db["network_relays"].find_one(
        {"last_recovery_nonce": body.registration_nonce}
    )
    if existing:
        if (
            existing.get("last_recovery_digest") != activation_digest
            or existing.get("signing_key_id") != key_id
        ):
            raise HTTPException(status_code=409, detail="Relay recovery nonce conflict")
        reset_record = existing.get("last_recovery_reset")
        if isinstance(reset_record, dict):
            await db["network_relay_chain_resets"].update_one(
                {
                    "relay_id": existing["relay_id"],
                    "new_key_epoch": int(existing["key_epoch"]),
                },
                {"$setOnInsert": reset_record},
                upsert=True,
            )
        await redis.hset(
            f"warsoc:relay_chain:{existing['relay_id']}",
            mapping={
                "sequence": 0,
                "batch_hash": RELAY_GENESIS_HASH,
                "chain_id": "",
                "key_epoch": int(existing["key_epoch"]),
            },
        )
        await redis.delete(
            f"warsoc:relay_revoked:{existing['relay_id']}",
            f"warsoc:relay_cache:{existing['relay_id']}",
            f"warsoc:relay_recovery:{body.activation_code}",
            f"warsoc:relay_recovery:{body.activation_code}:claim",
        )
        token = create_access_token(
            data={
                "sub": existing["relay_id"],
                "type": "network_relay",
                "tenant_id": existing["tenant_id"],
            },
            expires_delta=timedelta(minutes=AGENT_TOKEN_EXPIRE_MINUTES),
        )
        return {
            "relay_id": existing["relay_id"],
            "tenant_id": existing["tenant_id"],
            "relay_token": token,
            "key_epoch": int(existing["key_epoch"]),
            "signature_version": RELAY_SIGNATURE_VERSION,
            "schema_version": RELAY_SCHEMA_VERSION,
            "minimum_version": settings.network_relay_minimum_version,
            "recovery_replayed": True,
        }
    if await db["network_relays"].find_one({"last_recovery_digest": activation_digest}):
        raise HTTPException(status_code=409, detail="Relay recovery was already consumed")
    recovery_key = f"warsoc:relay_recovery:{body.activation_code}"
    raw, recovery_claim_key = await _claim_one_time_secret(
        redis,
        secret_key=recovery_key,
        claimant=body.registration_nonce,
        invalid_detail="Invalid or expired relay recovery",
    )
    try:
        authorization = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=401, detail="Invalid relay recovery") from exc
    if authorization.get("purpose") != "network_relay_key_recovery":
        raise HTTPException(status_code=401, detail="Invalid relay recovery")
    relay_id = str(authorization.get("relay_id") or "")
    tenant_id = str(authorization.get("tenant_id") or "")
    previous_epoch = int(authorization.get("previous_key_epoch") or 1)
    new_epoch = previous_epoch + 1
    now = datetime.now(timezone.utc)
    reset_record = {
        **authorization,
        "new_key_epoch": new_epoch,
        "new_signing_key_id": key_id,
        "recovered_at": now,
    }
    result = await db["network_relays"].update_one(
        {
            "relay_id": relay_id,
            "tenant_id": tenant_id,
            "key_epoch": previous_epoch,
        },
        {
            "$set": {
                "hostname": body.hostname,
                "version": body.version,
                "public_key": public_key,
                "signing_key_id": key_id,
                "key_epoch": new_epoch,
                "chain_id": None,
                "last_sequence": 0,
                "last_batch_hash": RELAY_GENESIS_HASH,
                "status": "active",
                "last_recovery_nonce": body.registration_nonce,
                "last_recovery_digest": activation_digest,
                "last_recovered_at": now,
                "last_recovery_reset": reset_record,
            }
        },
    )
    if result.matched_count != 1:
        raise HTTPException(status_code=409, detail="Relay recovery state changed")
    await db["network_relay_chain_resets"].update_one(
        {"relay_id": relay_id, "new_key_epoch": new_epoch},
        {"$setOnInsert": reset_record},
        upsert=True,
    )
    try:
        await redis.hset(
            f"warsoc:relay_chain:{relay_id}",
            mapping={
                "sequence": 0,
                "batch_hash": RELAY_GENESIS_HASH,
                "chain_id": "",
                "key_epoch": new_epoch,
            },
        )
        await redis.delete(
            f"warsoc:relay_revoked:{relay_id}", f"warsoc:relay_cache:{relay_id}"
        )
        await _consume_claimed_secret(
            redis,
            secret_key=recovery_key,
            claim_key=recovery_claim_key,
            claimant=body.registration_nonce,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Relay recovery state is pending; retain identity and retry",
        ) from exc
    token = create_access_token(
        data={"sub": relay_id, "type": "network_relay", "tenant_id": tenant_id},
        expires_delta=timedelta(minutes=AGENT_TOKEN_EXPIRE_MINUTES),
    )
    return {
        "relay_id": relay_id,
        "tenant_id": tenant_id,
        "relay_token": token,
        "key_epoch": new_epoch,
        "signature_version": RELAY_SIGNATURE_VERSION,
        "schema_version": RELAY_SCHEMA_VERSION,
        "minimum_version": settings.network_relay_minimum_version,
        "previous_chain_closed": True,
    }


def _queue_event(
    event: RelayEvent,
    relay_context: dict[str, Any],
    batch: RelayBatch,
    batch_hash: str,
    signature: str,
    cloud_receipt_time: datetime,
) -> dict[str, Any]:
    normalized = dict(event.normalized)
    event_type = str(normalized["event_type"])
    device_time = _parse_utc(event.device_event_time) if event.device_event_time else None
    relay_time = _parse_utc(event.relay_receipt_time)
    confidence, offset = _time_confidence(device_time, relay_time)
    source_ip = str(normalized.get("src_ip") or event.source_address)
    user = str(normalized.get("user") or "NETWORK_DEVICE")[:255]
    message = str(
        normalized.get("message")
        or f"{event.vendor} {event_type.replace('_', ' ')} observed"
    )[:1000]
    encrypted_raw_data = _encrypt_relay_raw_data(
        {
            "raw_message": event.raw_message,
            "raw_message_hash": event.raw_message_hash,
            "transport": event.transport,
            "observed_source_address": event.source_address,
        }
    )
    queued_event = {
        "tenant_id": relay_context["tenant_id"],
        "agent_id": relay_context["relay_id"],
        "source_id": event.device_id,
        "source_type": "network_device",
        "source_assurance": "relay_attested",
        "record_class": event.record_class,
        "network_device_id": event.device_id,
        "network_vendor": event.vendor,
        "event_id": NETWORK_EVENT_IDS[event_type],
        "event_type": event_type,
        "event_uid": event.event_uid,
        "source_ip": source_ip,
        "user": user,
        "message": message,
        "timestamp": relay_time.isoformat(),
        "device_event_time": device_time.isoformat() if device_time else None,
        "relay_receipt_time": relay_time.isoformat(),
        "cloud_receipt_time": cloud_receipt_time.isoformat(),
        "time_confidence": confidence,
        "detected_clock_offset_seconds": offset,
        "raw_data": encrypted_raw_data,
        "raw_data_encryption_version": "fernet-v1",
        "raw_event_data": {
            "vendor": event.vendor,
            "device_id": event.device_id,
            "normalized": normalized,
        },
        "processed_data": normalized,
        "relay_chain": {
            "schema_version": batch.schema_version,
            "chain_id": batch.chain_id,
            "key_epoch": batch.key_epoch,
            "sequence": batch.sequence,
            "previous_batch_hash": batch.previous_batch_hash,
            "batch_hash": batch_hash,
        },
        "agent_signature": signature,
        "payload_hash": batch_hash,
        "signature_version": RELAY_SIGNATURE_VERSION,
        "signature_algorithm": "Ed25519",
        "signing_key_id": relay_context["relay"].get("signing_key_id"),
        "signature_verified": True,
        "signature_verification_status": "verified",
        "signature_verified_at": cloud_receipt_time.isoformat(),
        "agent_version": relay_context["relay"].get("version") or "unknown",
    }
    return apply_source_provenance(queued_event)


async def _admit_batch(
    redis,
    relay_context: dict[str, Any],
    batch: RelayBatch,
    batch_hash: str,
    payloads: list[str],
    *,
    quota_bytes: int = 2**63 - 1,
    platform_quota_bytes: int = PLATFORM_DAILY_INGEST_BYTES_MAX,
    payload_bytes: int = 0,
) -> int:
    relay = relay_context["relay"]
    state_key = f"warsoc:relay_chain:{relay_context['relay_id']}"
    script = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  redis.call('HSET', KEYS[1],
    'sequence', ARGV[9],
    'batch_hash', ARGV[10],
    'chain_id', ARGV[11],
    'key_epoch', ARGV[12])
end
local current_sequence = tonumber(redis.call('HGET', KEYS[1], 'sequence') or '0')
local current_hash = redis.call('HGET', KEYS[1], 'batch_hash') or ARGV[7]
local current_chain = redis.call('HGET', KEYS[1], 'chain_id') or ''
local current_epoch = tonumber(redis.call('HGET', KEYS[1], 'key_epoch') or ARGV[5])
local incoming_sequence = tonumber(ARGV[1])
local incoming_previous = ARGV[2]
local incoming_hash = ARGV[3]
local incoming_chain = ARGV[4]
local incoming_epoch = tonumber(ARGV[5])
local stream_limit = tonumber(ARGV[6])
local payload_count = tonumber(ARGV[8])
local incoming_bytes = tonumber(ARGV[13])
local quota_limit = tonumber(ARGV[14])
local quota_ttl = tonumber(ARGV[15])
local platform_quota_limit = tonumber(ARGV[16])

if current_sequence == incoming_sequence and current_hash == incoming_hash and current_chain == incoming_chain then
  return 2
end
if current_sequence == 0 then
  if incoming_epoch ~= current_epoch then return -2 end
  if incoming_sequence ~= 1 or incoming_previous ~= ARGV[7] then return -1 end
else
  if incoming_chain ~= current_chain or incoming_epoch ~= current_epoch then return -2 end
  if incoming_sequence ~= current_sequence + 1 or incoming_previous ~= current_hash then return -1 end
end
local quota_used = tonumber(redis.call('GET', KEYS[3]) or '0')
local platform_quota_used = tonumber(redis.call('GET', KEYS[4]) or '0')
if incoming_bytes > 0 and quota_used + incoming_bytes > quota_limit then return -4 end
if incoming_bytes > 0 and platform_quota_limit > 0 and platform_quota_used + incoming_bytes > platform_quota_limit then return -5 end
if redis.call('XLEN', KEYS[2]) + payload_count > stream_limit then return -3 end
if incoming_bytes > 0 then
  redis.call('INCRBY', KEYS[3], incoming_bytes)
  redis.call('INCRBY', KEYS[4], incoming_bytes)
  redis.call('EXPIRE', KEYS[3], quota_ttl)
  redis.call('EXPIRE', KEYS[4], quota_ttl)
end
redis.call('HSET', KEYS[1],
  'sequence', incoming_sequence,
  'batch_hash', incoming_hash,
  'chain_id', incoming_chain,
  'key_epoch', incoming_epoch)
return 1
"""
    return int(
        await redis.eval(
            script,
            4,
            state_key,
            RAW_LOGS_QUEUE,
            f"warsoc:ingest:bytes:{relay_context['tenant_id']}:{datetime.now(timezone.utc).strftime('%Y%m%d')}",
            f"warsoc:ingest:bytes:platform:{datetime.now(timezone.utc).strftime('%Y%m%d')}",
            batch.sequence,
            batch.previous_batch_hash,
            batch_hash,
            batch.chain_id,
            batch.key_epoch,
            RAW_STREAM_MAX_ENTRIES,
            RELAY_GENESIS_HASH,
            len(payloads),
            int(relay.get("last_sequence") or 0),
            str(relay.get("last_batch_hash") or RELAY_GENESIS_HASH),
            str(relay.get("chain_id") or ""),
            int(relay.get("key_epoch") or 1),
            max(0, int(payload_bytes)),
            max(1, int(quota_bytes)),
            INGEST_DAILY_QUOTA_TTL_SECONDS,
            max(0, int(platform_quota_bytes)),
        )
    )


async def _persist_batch_receipt(
    db,
    relay_context: dict[str, Any],
    batch: RelayBatch,
    batch_hash: str,
    cloud_receipt_time: datetime,
) -> None:
    receipt = {
        "tenant_id": relay_context["tenant_id"],
        "relay_id": relay_context["relay_id"],
        "chain_id": batch.chain_id,
        "key_epoch": batch.key_epoch,
        "sequence": batch.sequence,
        "previous_batch_hash": batch.previous_batch_hash,
        "batch_hash": batch_hash,
        "event_count": len(batch.events),
        "cloud_receipt_time": cloud_receipt_time,
    }
    await db["network_relay_batches"].update_one(
        {
            "relay_id": relay_context["relay_id"],
            "chain_id": batch.chain_id,
            "key_epoch": batch.key_epoch,
            "sequence": batch.sequence,
        },
        {"$setOnInsert": receipt},
        upsert=True,
    )
    configured_devices = {
        str(device.get("device_id") or ""): device
        for device in relay_context["relay"].get("devices", [])
        if device.get("device_id")
    }
    latest_by_device: dict[str, RelayEvent] = {}
    for event in batch.events:
        if event.record_class != "evidence" or event.device_id not in configured_devices:
            continue
        previous = latest_by_device.get(event.device_id)
        if previous is None or _parse_utc(event.relay_receipt_time) > _parse_utc(
            previous.relay_receipt_time
        ):
            latest_by_device[event.device_id] = event

    for device_id, event in latest_by_device.items():
        device = configured_devices[device_id]
        event_time = _parse_utc(event.relay_receipt_time)
        device_time = _parse_utc(event.device_event_time) if event.device_event_time else None
        confidence, offset = _time_confidence(device_time, event_time)
        await db["network_relay_device_status"].update_one(
            {
                "tenant_id": relay_context["tenant_id"],
                "relay_id": relay_context["relay_id"],
                "device_id": device_id,
            },
            {
                "$set": {
                    "vendor": device.get("vendor"),
                    "model": device.get("model"),
                    "transport": device.get("transport"),
                    "expected_eps": device.get("expected_eps"),
                    "last_event_at": event_time,
                    "last_device_event_at": device_time,
                    "last_cloud_receipt_at": cloud_receipt_time,
                    "last_event_type": event.normalized.get("event_type"),
                    "last_source_address": event.source_address,
                    "time_confidence": confidence,
                    "detected_clock_offset_seconds": offset,
                    "updated_at": cloud_receipt_time,
                },
                "$setOnInsert": {"created_at": cloud_receipt_time},
            },
            upsert=True,
        )

    for event in batch.events:
        if (
            event.record_class != "control"
            or event.normalized.get("event_type") != "device_health"
        ):
            continue
        affected_device_id = str(event.normalized.get("affected_device_id") or "")
        if affected_device_id not in configured_devices:
            continue
        await db["network_relay_device_status"].update_one(
            {
                "tenant_id": relay_context["tenant_id"],
                "relay_id": relay_context["relay_id"],
                "device_id": affected_device_id,
            },
            {
                "$set": {
                    "vendor": configured_devices[affected_device_id].get("vendor"),
                    "model": configured_devices[affected_device_id].get("model"),
                    "transport": configured_devices[affected_device_id].get("transport"),
                    "expected_eps": configured_devices[affected_device_id].get(
                        "expected_eps"
                    ),
                    "last_failure_at": _parse_utc(event.relay_receipt_time),
                    "last_failure_reason": event.normalized.get("reason"),
                    "last_reported_drops": int(
                        event.normalized.get("dropped_events") or 0
                    ),
                    "last_reported_dropped_bytes": int(
                        event.normalized.get("dropped_bytes") or 0
                    ),
                    "updated_at": cloud_receipt_time,
                },
                "$setOnInsert": {"created_at": cloud_receipt_time},
            },
            upsert=True,
        )
    relay_updates: dict[str, Any] = {
        "chain_id": batch.chain_id,
        "key_epoch": batch.key_epoch,
        "last_sequence": batch.sequence,
        "last_batch_hash": batch_hash,
        "last_seen": cloud_receipt_time,
    }
    health_events = [
        event
        for event in batch.events
        if event.record_class == "control"
        and event.normalized.get("event_type") == "device_health"
    ]
    if health_events:
        latest_health = max(health_events, key=lambda event: _parse_utc(event.relay_receipt_time))
        relay_updates.update(
            {
                "last_health_state": latest_health.normalized.get("state"),
                "last_health_reason": latest_health.normalized.get("reason"),
                "last_health_at": _parse_utc(latest_health.relay_receipt_time),
                "last_spool_usage_bytes": latest_health.normalized.get("spool_usage_bytes"),
                "last_spool_capacity_bytes": latest_health.normalized.get(
                    "spool_capacity_bytes"
                ),
            }
        )
    await db["network_relays"].update_one(
        {
            "relay_id": relay_context["relay_id"],
            "$or": [
                {"last_sequence": {"$lt": batch.sequence}},
                {"last_sequence": {"$exists": False}},
            ],
        },
        {
            "$set": relay_updates
        },
    )


@router.post("/ingest", status_code=202, response_class=ORJSONResponse)
@limiter.limit("120/minute")
async def ingest_relay_batch(
    request: Request,
    x_warsoc_signature: str = Header(..., alias="X-WarSOC-Signature"),
    relay_context: dict[str, Any] = Depends(_relay_context),
    db=Depends(get_db),
):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared_size = int(content_length)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from exc
        if declared_size < 0:
            raise HTTPException(status_code=400, detail="Invalid Content-Length")
        if declared_size > settings.network_relay_max_body_bytes:
            raise HTTPException(status_code=413, detail="Relay batch is too large")
    raw_body = await request.body()
    if not raw_body or len(raw_body) > settings.network_relay_max_body_bytes:
        raise HTTPException(status_code=413, detail="Relay batch is too large")
    signature = str(x_warsoc_signature or "").strip().lower()
    if len(signature) != 128 or any(ch not in "0123456789abcdef" for ch in signature):
        raise HTTPException(status_code=401, detail="Relay signature verification failed")
    try:
        public_key = serialization.load_pem_public_key(relay_context["public_key"].encode("ascii"))
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise ValueError("invalid relay key type")
        public_key.verify(bytes.fromhex(signature), raw_body)
    except Exception as exc:
        redis = getattr(request.app.state, "redis", None)
        if redis is not None:
            await redis.incr("warsoc_network_relay_batches_rejected_total")
        raise HTTPException(status_code=401, detail="Relay signature verification failed") from exc
    try:
        batch = RelayBatch.model_validate_json(raw_body)
    except Exception as exc:
        raise HTTPException(status_code=422, detail="Invalid network relay batch") from exc
    if batch.relay_id != relay_context["relay_id"]:
        raise HTTPException(status_code=403, detail="Relay identity mismatch")
    if relay_context.get("version_gate") and any(
        event.record_class == "evidence" for event in batch.events
    ):
        # Evidence from an outdated relay is rejected with a structured
        # update-required signal; control/health-only batches are still
        # accepted so the relay stays visible to operators. The body is
        # returned directly (not via HTTPException) so the relay-facing
        # contract survives the sanitized public error envelope.
        return ORJSONResponse(status_code=403, content=relay_context["version_gate"])
    if len(batch.events) > settings.network_relay_max_batch_events:
        raise HTTPException(status_code=413, detail="Relay batch contains too many events")
    now = datetime.now(timezone.utc)
    try:
        _reject_future_time(batch.created_at, now)
    except ValueError:
        raise HTTPException(status_code=400, detail="Relay batch timestamp is outside the allowed window")

    devices = {device["device_id"]: device for device in relay_context["relay"].get("devices", [])}
    seen_uids: set[str] = set()
    for event in batch.events:
        if event.event_uid in seen_uids:
            raise HTTPException(status_code=422, detail="Duplicate event UID within relay batch")
        seen_uids.add(event.event_uid)
        if event.record_class == "control":
            if event.device_id != batch.relay_id or event.source_address not in {"127.0.0.1", "::1"}:
                raise HTTPException(status_code=403, detail="Invalid relay control identity")
        else:
            device = devices.get(event.device_id)
            if not device:
                raise HTTPException(status_code=403, detail="Unregistered relay device")
            if event.vendor != device.get("vendor") or event.transport != device.get("transport"):
                raise HTTPException(status_code=403, detail="Relay device contract mismatch")
            if not _source_matches(event.source_address, device.get("source_addresses") or []):
                raise HTTPException(status_code=403, detail="Relay source address is not allowlisted")
        try:
            _reject_future_time(event.relay_receipt_time, now)
        except ValueError:
            raise HTTPException(status_code=400, detail="Relay receipt time is outside the allowed window")

    redis = getattr(request.app.state, "redis", None)
    if redis is None:
        raise HTTPException(status_code=503, detail="Relay ingest queue unavailable")
    try:
        quota_bytes = await _resolve_daily_ingest_quota_bytes(
            redis, relay_context["tenant_id"], db
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Ingest quota service unavailable") from exc
    batch_hash = hashlib.sha256(raw_body).hexdigest()
    try:
        payloads = [
            orjson.dumps(
                _queue_event(event, relay_context, batch, batch_hash, signature, now)
            ).decode("utf-8")
            for event in batch.events
        ]
    except RuntimeError as exc:
        logger.exception("Relay evidence encryption failed before queue admission")
        raise HTTPException(
            status_code=503,
            detail="Relay evidence protection unavailable; relay must retain and retry",
        ) from exc
    raw_stream_bytes = sum(len(payload.encode("utf-8")) for payload in payloads)
    await _enforce_raw_stream_capacity(
        redis,
        incoming_entries=len(payloads),
        incoming_stream_bytes=raw_stream_bytes,
        incoming_redis_bytes=raw_stream_bytes,
    )
    try:
        admission = await _admit_batch(
            redis,
            relay_context,
            batch,
            batch_hash,
            payloads,
            quota_bytes=quota_bytes,
            payload_bytes=len(raw_body),
        )
    except Exception as exc:
        if "maxmemory" in str(exc).lower() or "out of memory" in str(exc).lower():
            raise HTTPException(
                status_code=503,
                detail="Ingest queue is under pressure; relay must retain and retry",
            ) from exc
        raise
    if admission == -4:
        raise HTTPException(status_code=429, detail="Tenant daily ingest quota exceeded")
    if admission == -5:
        raise HTTPException(status_code=503, detail="Ingest capacity is temporarily exhausted; relay must retain and retry")
    if admission == -3:
        raise HTTPException(status_code=503, detail="Ingest queue is under pressure; relay must retain and retry")
    if admission == -2:
        await redis.incr("warsoc_network_relay_batches_rejected_total")
        raise HTTPException(status_code=409, detail="Relay chain or key epoch mismatch")
    if admission == -1:
        await redis.incr("warsoc_network_relay_batches_rejected_total")
        raise HTTPException(status_code=409, detail="Relay batch sequence mismatch")
    try:
        outbox_uids = await persist_source_envelope(
            db,
            tenant_id=relay_context["tenant_id"],
            source_principal_type="network_relay",
            source_principal_id=relay_context["relay_id"],
            source_channel="network_relay",
            source_envelope_uid=f"{batch.chain_id}:{batch.key_epoch}:{batch.sequence}",
            source_payload=raw_body,
            dispatch_events=[
                {
                    "event_uid": event.event_uid,
                    "serialized_payload": payload,
                    "target_streams": [RAW_LOGS_QUEUE],
                }
                for event, payload in zip(batch.events, payloads)
            ],
            retention_class="SIEM",
            auth_metadata={
                "scheme": RELAY_SIGNATURE_VERSION,
                "signature_algorithm": "Ed25519",
                "signature": signature,
                "payload_hash": batch_hash,
                "signing_key_id": relay_context["relay"].get("signing_key_id"),
                "key_epoch": batch.key_epoch,
                "chain_id": batch.chain_id,
                "sequence": batch.sequence,
                "previous_batch_hash": batch.previous_batch_hash,
                "verification_version": "relay-batch-v1",
            },
            source_timestamp=batch.created_at,
        )
        await _persist_batch_receipt(db, relay_context, batch, batch_hash, now)
        await db["network_relays"].update_one(
            {"relay_id": relay_context["relay_id"]},
            {"$set": {"last_ip": request.client.host if request.client else None}},
        )
    except SourceEvidenceConflict as exc:
        logger.warning(
            "[SECURITY] Relay source evidence identity conflict: relay=%s sequence=%s",
            relay_context["relay_id"],
            batch.sequence,
        )
        raise HTTPException(status_code=409, detail="Source evidence identity conflict") from exc
    except Exception as exc:
        logger.exception("Relay source persistence failed before stream dispatch")
        raise HTTPException(
            status_code=503,
            detail="Relay evidence persistence unavailable; retain and retry",
        ) from exc

    try:
        published_count = await publish_source_outbox(
            db,
            redis,
            outbox_uids=outbox_uids,
            limit=len(outbox_uids),
        )
    except Exception:
        logger.exception("Relay source outbox inline dispatch failed; background retry retained")
        published_count = 0

    if admission == 2:
        await redis.incr("warsoc_network_relay_batches_duplicate_total")
        return ORJSONResponse(
            status_code=202,
            content={
                "status": "duplicate_acknowledged",
                "queued": 0,
                "dispatch_published": published_count,
                "sequence": batch.sequence,
            },
        )
    control_events = [event for event in batch.events if event.record_class == "control"]
    reported_drops = sum(
        int(event.normalized.get("dropped_events") or 0) for event in control_events
    )
    reported_dropped_bytes = sum(
        int(event.normalized.get("dropped_bytes") or 0) for event in control_events
    )
    await redis.pipeline(transaction=False).incr(
        "warsoc_network_relay_batches_accepted_total"
    ).incrby(
        "warsoc_network_relay_events_accepted_total", len(batch.events)
    ).incrby(
        "warsoc_network_relay_control_records_total", len(control_events)
    ).incrby(
        "warsoc_network_relay_reported_drops_total", reported_drops
    ).incrby(
        "warsoc_network_relay_reported_dropped_bytes_total",
        reported_dropped_bytes,
    ).execute()
    return ORJSONResponse(
        status_code=202,
        content={
            "status": "accepted",
            "queued": len(batch.events),
            "dispatch_published": published_count,
            "dispatch_pending": len(outbox_uids) - published_count,
            "sequence": batch.sequence,
        },
    )

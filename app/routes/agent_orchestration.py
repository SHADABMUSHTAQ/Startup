from fastapi import APIRouter, Depends, Request, HTTPException, Header
from pydantic import BaseModel, ConfigDict, Field
import base64
import hashlib
import json
import logging
import os
import uuid
import secrets
import ipaddress
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from typing import Any, Literal, Optional
from urllib.parse import urlparse
from fastapi.responses import RedirectResponse

from app.database import get_db
from app.routes.auth import get_current_user
from app.config.config import get_settings
from app.utils.rbac import RoleChecker
from app.utils.limiter import limiter
from app.utils.security_policy import effective_agent_limit
from app.utils.agent_lifecycle import (
    agent_lifecycle_is_active,
    agent_status_needs_lifecycle_migration,
    normalize_agent_lifecycle_status,
)
from app.utils.agent_crypto import parse_utc_timestamp, public_key_id
from app.utils.collection_profiles import (
    general_server_compatible,
    make_assignment,
    sanitize_host_facts,
    sanitize_profile_report,
    server_response_blocked,
)


router = APIRouter()
settings = get_settings()
logger = logging.getLogger(__name__)


ACTIVE_AGENT_QUERY = {"status": {"$nin": ["inactive", "revoked"]}}
INACTIVE_TENANT_STATUSES = {"inactive", "suspended", "cancelled", "canceled", "past_due"}
PLATFORM_ACTIVE_AGENT_LIMIT = max(
    1,
    int(os.getenv("PLATFORM_ACTIVE_AGENT_LIMIT", "50")),
)
PLATFORM_ACTIVE_COUNT_KEY = "warsoc:platform:active_agent_count"


def _tenant_accepts_agents(tenant: dict | None) -> bool:
    if not tenant:
        return False
    status = str(tenant.get("status") or "active").strip().lower()
    return bool(
        tenant.get("active", True) is not False
        and tenant.get("has_active_plan", True) is not False
        and status not in INACTIVE_TENANT_STATUSES
    )


async def _database_active_agent_count(db, tenant_id: str | None = None) -> int:
    query = dict(ACTIVE_AGENT_QUERY)
    if tenant_id:
        query["tenant_id"] = tenant_id
    return int(await db["agents"].count_documents(query))


async def _sync_active_count_floor(redis_client, count_key: str, database_count: int) -> int:
    script = """
    local current = tonumber(redis.call('GET', KEYS[1]) or '0')
    local floor = tonumber(ARGV[1])
    if current < floor then
        current = floor
        redis.call('SET', KEYS[1], current)
    end
    return current
    """
    return int(await redis_client.eval(script, 1, count_key, int(database_count)))

class ActivationResponse(BaseModel):
    activation_code: str
    expires_in_seconds: int

class ActivationValidateRequest(BaseModel):
    activation_code: str = Field(min_length=8, max_length=64)

class AgentRegisterRequest(BaseModel):
    activation_code: str
    public_key: str = Field(min_length=80, max_length=1000)  # PEM encoded Ed25519 public key
    host_facts: dict[str, Any] | None = None

class HeartbeatRequest(BaseModel):
    agent_id: str
    current_version: str
    timestamp: float = Field(..., allow_inf_nan=False)
    protocol_version: str = "heartbeat-v1"
    nonce: str | None = Field(default=None, min_length=16, max_length=128)
    agent_collection_time: str | None = Field(default=None, max_length=64)
    sensor_status: dict[str, Any] | None = None


class GeneralServerProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision: int = Field(ge=0, le=2147483646)
    enabled: bool = True
    environment: Literal["production", "staging", "development", "unknown"] = "unknown"
    criticality: Literal["low", "medium", "high", "critical"] = "medium"


def _heartbeat_clock_state(offset_seconds: float) -> str:
    absolute_offset = abs(float(offset_seconds))
    if absolute_offset <= 5:
        return "TRUSTED"
    if absolute_offset <= 60:
        return "DEGRADED"
    return "UNTRUSTED"


def _sanitize_sensor_status(raw_status: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(raw_status, dict):
        return {}

    channels = {}
    raw_channels = raw_status.get("channels")
    if isinstance(raw_channels, dict):
        for channel_name in ("Security", "System"):
            raw_channel = raw_channels.get(channel_name)
            if not isinstance(raw_channel, dict):
                continue
            status = str(raw_channel.get("status") or "unknown").strip().lower()
            if status not in {"ok", "degraded", "error", "unknown"}:
                status = "unknown"

            def _channel_cursor(name: str) -> int:
                try:
                    return max(0, int(raw_channel.get(name) or 0))
                except (TypeError, ValueError):
                    return 0

            channels[channel_name] = {
                "status": status,
                "last_checked_at": str(raw_channel.get("last_checked_at") or "")[:64],
                "last_event_at": str(raw_channel.get("last_event_at") or "")[:64],
                "last_error": str(raw_channel.get("last_error") or "")[:500] or None,
                "channel_epoch": str(raw_channel.get("channel_epoch") or "")[:128] or None,
                "watermark": _channel_cursor("watermark"),
                "latest_record_id": _channel_cursor("latest_record_id"),
            }

    pos_audit = raw_status.get("pos_audit_log")
    pos_audit = pos_audit if isinstance(pos_audit, dict) else {}
    nonce_key = None
    try:
        pos_sacl_path_count = int(raw_status.get("pos_sacl_path_count") or 0)
    except (TypeError, ValueError):
        pos_sacl_path_count = 0
    raw_counters = raw_status.get("counters") if isinstance(raw_status.get("counters"), dict) else {}
    counters = {}
    for counter_name in (
        "windows_parse_failures",
        "pos_jsonl_rejections",
        "channel_failures",
        "spool_write_failures",
        "spool_limit_hits",
    ):
        try:
            counters[counter_name] = max(0, int(raw_counters.get(counter_name) or 0))
        except (TypeError, ValueError):
            counters[counter_name] = 0
    raw_spool = raw_status.get("spool") if isinstance(raw_status.get("spool"), dict) else {}

    def _bounded_non_negative_int(name: str, maximum: int = 10 * 1024 * 1024 * 1024 * 1024) -> int:
        try:
            return max(0, min(int(raw_spool.get(name) or 0), maximum))
        except (TypeError, ValueError):
            return 0

    return {
        "telemetry_config_version": str(raw_status.get("telemetry_config_version") or "unknown")[:64],
        "audit_policy_status": str(raw_status.get("audit_policy_status") or "unknown")[:32],
        "pos_sacl_path_count": max(0, min(pos_sacl_path_count, 1000)),
        "channels": channels,
        "counters": counters,
        "spool": {
            "usage_bytes": _bounded_non_negative_int("usage_bytes"),
            "max_bytes": _bounded_non_negative_int("max_bytes"),
            "resume_bytes": _bounded_non_negative_int("resume_bytes"),
            "min_free_bytes": _bounded_non_negative_int("min_free_bytes"),
            "free_bytes": _bounded_non_negative_int("free_bytes"),
            "blocked": bool(raw_spool.get("blocked", False)),
            "reason": str(raw_spool.get("reason") or "")[:500] or None,
        },
        "pos_audit_log": {
            "configured": bool(pos_audit.get("configured", False)),
            "present": bool(pos_audit.get("present", False)),
        },
        "host_facts": sanitize_host_facts(raw_status.get("host_facts")),
        "server_monitoring": sanitize_profile_report(raw_status.get("server_monitoring")),
    }


def _is_valid_ip_or_cidr(value: str) -> bool:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_valid_agent_cdn_url(value: str) -> bool:
    parsed = urlparse(str(value or "").strip())
    return (
        parsed.scheme == "https"
        and bool(parsed.netloc)
        and parsed.path.lower().endswith(".exe")
    )


async def _get_tenant_enforce_bans(redis_client, tenant_id: str) -> list[str]:
    if not tenant_id:
        return []

    redis_key = f"warsoc:banned_ips:{tenant_id}"
    raw_banned_ips = await redis_client.smembers(redis_key)
    banned_ips: list[str] = []
    invalid_entries: list[str] = []

    for candidate in raw_banned_ips:
        value = candidate.decode("utf-8", errors="ignore") if isinstance(candidate, bytes) else str(candidate)
        value = value.strip()
        if _is_valid_ip_or_cidr(value):
            banned_ips.append(value)
        else:
            invalid_entries.append(value)

    if invalid_entries:
        try:
            await redis_client.srem(redis_key, *invalid_entries)
        except Exception:
            pass

    return sorted(set(banned_ips))

@router.post("/generate-activation", response_model=ActivationResponse)
@limiter.limit("60/minute")
async def generate_activation(
    request: Request,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["Admin"])),
    db = Depends(get_db)
):
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Not bound to a tenant")
        
    redis_client = getattr(request.app.state, "redis", None)
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")
        
    # Get tenant features
    features = await redis_client.get(f"tenant_features:{tenant_id}")
    if not features:
        features = "SIEM"
        
    tenant = await db["tenants"].find_one({"tenant_id": tenant_id})
    if not _tenant_accepts_agents(tenant):
        raise HTTPException(status_code=403, detail="Tenant contract is inactive")
        
    limit = effective_agent_limit(tenant.get("max_agents", tenant.get("agent_limit", 10)))
    count_key = f"tenant:{tenant_id}:active_count"
    database_count = await _database_active_agent_count(db, tenant_id)
    current_count = await _sync_active_count_floor(redis_client, count_key, database_count)
    if current_count >= limit:
        raise HTTPException(
            status_code=403, 
            detail=f"Agent contract limit ({limit}) reached. Contact WarSOC operations to increase the contracted agent limit."
        )
    platform_database_count = await _database_active_agent_count(db)
    platform_count = await _sync_active_count_floor(
        redis_client,
        PLATFORM_ACTIVE_COUNT_KEY,
        platform_database_count,
    )
    if platform_count >= PLATFORM_ACTIVE_AGENT_LIMIT:
        raise HTTPException(
            status_code=503,
            detail="The current deployment has reached its active endpoint capacity.",
        )

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    code = "WARSOC-" + "".join(secrets.choice(alphabet) for _ in range(8))
    
    payload = {
        "tenant_id": tenant_id,
        "features": features,
        "created_by": current_user.get("username")
    }
    
    ttl = 86400
    await redis_client.set(f"warsoc:activation:{code}", json.dumps(payload), ex=ttl)
    
    return ActivationResponse(activation_code=code, expires_in_seconds=ttl)

@router.post("/validate-activation")
@limiter.limit("120/minute")
async def validate_activation(
    request: Request,
    body: ActivationValidateRequest,
    db = Depends(get_db)
):
    redis_client = getattr(request.app.state, "redis", None)
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    activation_code = body.activation_code.strip()
    raw_payload = await redis_client.get(f"warsoc:activation:{activation_code}")
    if not raw_payload:
        raise HTTPException(status_code=401, detail="Invalid or expired activation code")

    if isinstance(raw_payload, bytes):
        raw_payload = raw_payload.decode("utf-8", errors="ignore")
    try:
        payload = json.loads(raw_payload)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired activation code") from exc

    tenant_id = payload.get("tenant_id")
    tenant = await db["tenants"].find_one({"tenant_id": tenant_id})
    if not _tenant_accepts_agents(tenant):
        raise HTTPException(status_code=401, detail="Invalid or expired activation code")

    ttl = await redis_client.ttl(f"warsoc:activation:{activation_code}")
    return {
        "status": "valid",
        "expires_in_seconds": max(int(ttl or 0), 0),
        "features": payload.get("features", "SIEM"),
    }

@router.post("/register")
@limiter.limit("60/minute")
async def register_agent(
    request: Request,
    body: AgentRegisterRequest,
    db = Depends(get_db)
):
    redis_client = getattr(request.app.state, "redis", None)
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    try:
        parsed_public_key = serialization.load_pem_public_key(body.public_key.encode("utf-8"))
        if not isinstance(parsed_public_key, ed25519.Ed25519PublicKey):
            raise ValueError("expected Ed25519 public key")
        canonical_public_key = parsed_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid Ed25519 public key") from exc
        
    key = f"warsoc:activation:{body.activation_code}"
    raw_payload = await redis_client.eval(
        """
        local value = redis.call('GET', KEYS[1])
        if value then
            redis.call('DEL', KEYS[1])
        end
        return value
        """,
        1,
        key,
    )
    
    if not raw_payload:
        raise HTTPException(status_code=401, detail="Invalid or expired activation code")
        
    payload = json.loads(raw_payload)
    tenant_id = payload.get("tenant_id")
    
    tenant = await db["tenants"].find_one({"tenant_id": tenant_id})
    if not _tenant_accepts_agents(tenant):
        raise HTTPException(status_code=401, detail="Activation code is not bound to an active tenant")
    limit = effective_agent_limit(tenant.get("max_agents", tenant.get("agent_limit", 10)))
    database_count = await _database_active_agent_count(db, tenant_id)
    platform_database_count = await _database_active_agent_count(db)
    
    lua_script = """
    local current_count = tonumber(redis.call('GET', KEYS[1]) or '0')
    local platform_count = tonumber(redis.call('GET', KEYS[2]) or '0')
    local tenant_limit = tonumber(ARGV[1])
    local platform_limit = tonumber(ARGV[2])
    local database_count = tonumber(ARGV[3])
    local platform_database_count = tonumber(ARGV[4])

    if current_count < database_count then
        current_count = database_count
        redis.call('SET', KEYS[1], current_count)
    end
    if platform_count < platform_database_count then
        platform_count = platform_database_count
        redis.call('SET', KEYS[2], platform_count)
    end

    if current_count >= tenant_limit then
        return -1
    end
    if platform_count >= platform_limit then
        return -2
    end

    redis.call('SET', KEYS[1], current_count + 1)
    redis.call('SET', KEYS[2], platform_count + 1)
    return 1
    """
    
    count_key = f"tenant:{tenant_id}:active_count"
    success = int(
        await redis_client.eval(
            lua_script,
            2,
            count_key,
            PLATFORM_ACTIVE_COUNT_KEY,
            limit,
            PLATFORM_ACTIVE_AGENT_LIMIT,
            database_count,
            platform_database_count,
        )
    )
    if success == -1:
        raise HTTPException(
            status_code=403, 
            detail=f"Agent contract limit ({limit}) reached. Registration denied."
        )
    if success == -2:
        raise HTTPException(
            status_code=503,
            detail="The current deployment has reached its active endpoint capacity.",
        )
    
    agent_id = f"WARSOC_AGENT_{uuid.uuid4().hex}"
    now = datetime.now(timezone.utc)
    registration_host_facts = sanitize_host_facts(body.host_facts)
    server_boundary = body.host_facts is not None and registration_host_facts["product_type"] != 1
    
    agent_doc = {
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "public_key": canonical_public_key,
        "status": "active",
        "key_rotation_status": "completed",
        "created_at": now,
        "last_seen": now,
        "last_ip": request.client.host,
        "features": payload.get("features", "SIEM"),
        # Registration is not signed yet. These facts may only reduce privileges;
        # a signed heartbeat establishes the authoritative observation.
        "registration_host_facts": registration_host_facts,
        "server_monitoring_required": server_boundary,
        "asset_class": "unclassified",
        "response_mode": "MONITOR_ONLY" if server_boundary else "LEGACY_ENDPOINT",
        "host_identity_status": "pending",
    }
    
    try:
        await db["agents"].insert_one(agent_doc)
    except Exception as exc:
        rollback_script = """
        local tenant_count = tonumber(redis.call('GET', KEYS[1]) or '0')
        local platform_count = tonumber(redis.call('GET', KEYS[2]) or '0')
        if tenant_count > 0 then
            redis.call('DECR', KEYS[1])
        end
        if platform_count > 0 then
            redis.call('DECR', KEYS[2])
        end
        return 1
        """
        rollback_failed = False
        try:
            await redis_client.eval(
                rollback_script,
                2,
                count_key,
                PLATFORM_ACTIVE_COUNT_KEY,
            )
        except Exception:
            rollback_failed = True
        detail = "Agent registration failed before completion; license seat was not consumed."
        if rollback_failed:
            detail = "Agent registration failed before completion; license seat rollback could not be confirmed."
        raise HTTPException(
            status_code=500,
            detail=detail
        ) from exc

    try:
        await redis_client.hset(
            f"warsoc:agent_cache:{agent_id}",
            mapping={
                "tenant_id": tenant_id,
                "public_key": canonical_public_key,
                "approved": "True",
                "status": "active"
            }
        )
        await redis_client.set(f"warsoc:agent_status:{agent_id}", "active")
        await redis_client.delete(f"warsoc:agent_revoked:{agent_id}")
    except Exception:
        pass
    
    from app.routes.auth import create_access_token, AGENT_TOKEN_EXPIRE_MINUTES
    from datetime import timedelta
    agent_jwt = create_access_token(
        data={"sub": agent_id, "type": "agent", "tenant_id": tenant_id},
        expires_delta=timedelta(minutes=AGENT_TOKEN_EXPIRE_MINUTES)
    )
    
    return {"agent_id": agent_id, "status": "active", "tenant_id": tenant_id, "agent_jwt": agent_jwt}

@router.post("/heartbeat")
async def agent_heartbeat(
    request: Request,
    body: HeartbeatRequest,
    x_warsoc_signature: str = Header(..., description="Hex encoded Ed25519 signature of the request body"),
    db = Depends(get_db)
):
    redis_client = getattr(request.app.state, "redis", None)
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    revoked_key = f"warsoc:agent_revoked:{body.agent_id}"
    status_key = f"warsoc:agent_status:{body.agent_id}"
    if await redis_client.exists(revoked_key):
        raise HTTPException(status_code=403, detail="Agent has been revoked")

    live_status = await redis_client.get(status_key)
    if isinstance(live_status, bytes):
        live_status = live_status.decode("utf-8", errors="ignore")
    if live_status and str(live_status).strip().lower() != "active":
        raise HTTPException(status_code=403, detail="Agent is inactive")

    tenant_id = None
    cached_agent = await redis_client.hgetall(f"warsoc:agent_cache:{body.agent_id}")
    if cached_agent and (cached_agent.get("public_key") or cached_agent.get(b"public_key")):
        public_key_pem = cached_agent.get("public_key") or cached_agent.get(b"public_key")
        if isinstance(public_key_pem, bytes):
            public_key_pem = public_key_pem.decode("utf-8", errors="ignore")
        tenant_id = cached_agent.get("tenant_id") or cached_agent.get(b"tenant_id")
        if isinstance(tenant_id, bytes):
            tenant_id = tenant_id.decode("utf-8", errors="ignore")
        cached_status = cached_agent.get("status") or cached_agent.get(b"status")
        if isinstance(cached_status, bytes):
            cached_status = cached_status.decode("utf-8", errors="ignore")
        if cached_status and str(cached_status).strip().lower() != "active":
            raise HTTPException(status_code=403, detail="Agent is inactive")
    else:
        agent = await db["agents"].find_one({"agent_id": body.agent_id})
        if not agent:
            raise HTTPException(status_code=401, detail="Agent not found")
        doc_status = normalize_agent_lifecycle_status(agent.get("status"))
        if not agent.get("approved", True) or not agent_lifecycle_is_active(doc_status):
            await redis_client.set(status_key, doc_status or "inactive")
            await redis_client.set(revoked_key, "1")
            raise HTTPException(status_code=403, detail="Agent is inactive")
        if agent_status_needs_lifecycle_migration(doc_status):
            await db["agents"].update_one(
                {"_id": agent["_id"]},
                {"$set": {"status": "active", "connectivity_status": doc_status}},
            )
            
        public_key_pem = agent.get("public_key")
        tenant_id = agent.get("tenant_id", "WARSOC_DEFAULT")
        if not public_key_pem:
            raise HTTPException(status_code=400, detail="Agent missing public key")
            
        await redis_client.hset(
            f"warsoc:agent_cache:{body.agent_id}",
            mapping={
                "public_key": public_key_pem,
                "tenant_id": tenant_id,
                "approved": "True",
                "status": "active",
            }
        )
        await redis_client.set(status_key, "active")
        
    try:
        raw_body = await request.body()
        signature_bytes = bytes.fromhex(x_warsoc_signature)
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise HTTPException(status_code=400, detail="Invalid key type, expected Ed25519")
            
        public_key.verify(signature_bytes, raw_body)
        
        protocol_version = str(body.protocol_version or "heartbeat-v1").strip().lower()
        if protocol_version not in {"heartbeat-v1", "heartbeat-v2"}:
            raise HTTPException(status_code=400, detail="Unsupported heartbeat protocol")

        now_ts = datetime.now(timezone.utc).timestamp()
        clock_offset_seconds = now_ts - body.timestamp
        accepted_skew = 30 if protocol_version == "heartbeat-v1" else 900
        if abs(clock_offset_seconds) > accepted_skew:
            raise HTTPException(status_code=401, detail="Heartbeat is outside the accepted time window")

        if protocol_version == "heartbeat-v2":
            if not body.nonce or not body.agent_collection_time:
                raise HTTPException(status_code=400, detail="Heartbeat v2 metadata is incomplete")
            collection_time = parse_utc_timestamp(body.agent_collection_time)
            if collection_time is None:
                raise HTTPException(status_code=400, detail="Heartbeat collection time is invalid")
            if abs(collection_time.timestamp() - body.timestamp) > 5:
                raise HTTPException(status_code=400, detail="Heartbeat time fields are inconsistent")

            nonce_key = f"warsoc:heartbeat_nonce:{body.agent_id}:{body.nonce}"
            if not await redis_client.set(nonce_key, "1", nx=True, ex=1800):
                raise HTTPException(status_code=409, detail="Heartbeat was already accepted")
                
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(
            "Agent heartbeat signature validation failed: agent_id=%s error_type=%s",
            body.agent_id,
            type(exc).__name__,
        )
        raise HTTPException(status_code=401, detail="Cryptographic verification failed") from exc
        
    authoritative_agent = await db["agents"].find_one(
        {"agent_id": body.agent_id, "tenant_id": tenant_id},
        {
            "agent_id": 1, "tenant_id": 1, "host_facts": 1,
            "host_identity_fingerprint": 1, "host_identity_status": 1,
            "server_monitoring_required": 1,
            "asset_class": 1, "monitoring_assignment": 1,
        },
    )
    if not authoritative_agent:
        raise HTTPException(status_code=401, detail="Agent identity is no longer active")

    raw_host_facts = (
        body.sensor_status.get("host_facts")
        if isinstance(body.sensor_status, dict) and isinstance(body.sensor_status.get("host_facts"), dict)
        else None
    )
    host_facts = sanitize_host_facts(raw_host_facts)
    prior_facts = sanitize_host_facts(authoritative_agent.get("host_facts"))
    established_fingerprint = str(
        authoritative_agent.get("host_identity_fingerprint")
        or prior_facts["machine_fingerprint"]
        or ""
    )
    if (
        raw_host_facts is not None
        and established_fingerprint
        and host_facts["machine_fingerprint"]
        and host_facts["machine_fingerprint"] != established_fingerprint
    ):
        await db["agents"].update_one(
            {"_id": authoritative_agent["_id"]},
            {"$set": {"host_identity_status": "conflict", "host_identity_conflict_at": datetime.now(timezone.utc)}},
        )
        raise HTTPException(status_code=409, detail="Host identity changed; re-enrollment is required")

    server_required = bool(authoritative_agent.get("server_monitoring_required"))
    if raw_host_facts is not None:
        server_required = server_required or host_facts["product_type"] != 1
        host_set = {
            "host_facts": host_facts,
            "host_identity_status": (
                "verified" if established_fingerprint or host_facts["machine_fingerprint"] else "pending"
            ),
            "server_monitoring_required": server_required,
        }
        if established_fingerprint or host_facts["machine_fingerprint"]:
            host_set["host_identity_fingerprint"] = (
                established_fingerprint or host_facts["machine_fingerprint"]
            )
        await db["agents"].update_one({"_id": authoritative_agent["_id"]}, {"$set": host_set})
        authoritative_agent.update(host_set)

    sensor_status = _sanitize_sensor_status(body.sensor_status)
    if tenant_id:
        received_at = datetime.now(timezone.utc)
        protocol_version = str(body.protocol_version or "heartbeat-v1").strip().lower()
        clock_offset_seconds = received_at.timestamp() - body.timestamp
        signed_body_hash = hashlib.sha256(raw_body).hexdigest()
        try:
            await db["agent_coverage_observations"].insert_one(
                {
                "tenant_id": tenant_id,
                "agent_id": body.agent_id,
                "agent_version": body.current_version,
                "protocol_version": protocol_version,
                "nonce": body.nonce,
                "agent_timestamp": datetime.fromtimestamp(body.timestamp, timezone.utc),
                "agent_collection_time": parse_utc_timestamp(body.agent_collection_time)
                if body.agent_collection_time
                else None,
                "server_received_time": received_at,
                "clock_offset_ms": int(clock_offset_seconds * 1000),
                "clock_state": _heartbeat_clock_state(clock_offset_seconds)
                if protocol_version == "heartbeat-v2"
                else "LEGACY",
                "sensor_status": sensor_status,
                "signed_body_sha256": signed_body_hash,
                "signed_body_b64": base64.b64encode(raw_body).decode("ascii"),
                "signature_algorithm": "Ed25519",
                "signature": x_warsoc_signature.lower(),
                "signing_key_id": public_key_id(public_key_pem),
                "source_ip": request.client.host if request.client else None,
                "created_at": received_at,
                }
            )
        except Exception:
            if nonce_key:
                await redis_client.delete(nonce_key)
            raise
        await redis_client.set(
            f"status:{tenant_id}:{body.agent_id}",
            received_at.isoformat(),
            ex=600,
        )
        await redis_client.set(
            f"warsoc:agent_sensor:{body.agent_id}",
            json.dumps(sensor_status),
            ex=600,
        )

    enforce_bans = []
    if tenant_id and not server_response_blocked(
        authoritative_agent,
        host_facts if raw_host_facts is not None else None,
    ):
        enforce_bans = await _get_tenant_enforce_bans(redis_client, tenant_id)

    # Rate limit DB updates to once every 60 seconds using Redis
    last_db_update = await redis_client.get(f"warsoc:agent_cache:db_update:{body.agent_id}")
    if not last_db_update:
        await db["agents"].update_one(
            {"agent_id": body.agent_id},
            {
                "$set": {
                    "last_seen": datetime.now(timezone.utc),
                    "version": body.current_version,
                    "last_ip": request.client.host,
                    "sensor_status": sensor_status,
                    "status": "active",
                    "connectivity_status": "online",
                }
            },
        )
        await redis_client.set(f"warsoc:agent_cache:db_update:{body.agent_id}", "1", ex=60)
    
    # Check OTA Updates
    auto_update_enabled = str(getattr(settings, "auto_update_enabled", "false")).lower() == "true"
    if auto_update_enabled:
        # OTA is intentionally fail-closed until a dedicated signed-agent URL
        # and release-signature verification contract are configured.
        logger.error("Agent auto-update was requested but signed OTA delivery is not configured")
            
    return {
        "status": "ok",
        "update_available": False,
        "enforce_bans": enforce_bans,
        # Bound to this accepted heartbeat so a cached response cannot apply a
        # stale profile. Monotonic revision checking is the second boundary.
        "control_nonce": body.nonce if protocol_version == "heartbeat-v2" else None,
        "monitoring_assignment": (
            authoritative_agent.get("monitoring_assignment") if server_required else None
        ),
    }


@router.get("/server-profiles")
async def list_server_profiles(
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "manager", "analyst", "auditor"])),
):
    """Expose the bounded engineering catalog without claiming broad support."""
    return {
        "engineering_enabled": os.getenv("WINDOWS_SERVER_MONITORING_ENABLED", "false").lower() == "true",
        "profiles": [
            {
                "profile_id": "general_server",
                "profile_version": 1,
                "qualification_target": "Windows Server 2022 Standard Desktop Experience (AMD64)",
                "customer_supported": False,
                "response_mode": "MONITOR_ONLY",
            }
        ],
    }


@router.put("/{agent_id}/server-profile")
async def assign_general_server_profile(
    agent_id: str,
    body: GeneralServerProfileRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin"])),
    db = Depends(get_db),
):
    if os.getenv("WINDOWS_SERVER_MONITORING_ENABLED", "false").lower() != "true":
        raise HTTPException(status_code=503, detail="Windows Server engineering is disabled")
    tenant_id = str(current_user.get("tenant_id") or "")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Not bound to a tenant")
    agent = await db["agents"].find_one(
        {"agent_id": agent_id, "tenant_id": tenant_id, **ACTIVE_AGENT_QUERY},
        {"agent_id": 1, "tenant_id": 1, "host_facts": 1, "monitoring_assignment": 1},
    )
    if not agent:
        raise HTTPException(status_code=404, detail="Active agent not found")
    current_revision = int((agent.get("monitoring_assignment") or {}).get("revision") or 0)
    if current_revision != body.expected_revision:
        raise HTTPException(status_code=409, detail="Monitoring profile revision changed; refresh and retry")
    if body.enabled and not general_server_compatible(agent.get("host_facts")):
        raise HTTPException(status_code=409, detail="Agent has not proven the General Server V1 qualification target")
    if not body.enabled and not agent.get("monitoring_assignment"):
        raise HTTPException(status_code=409, detail="No server monitoring profile is assigned")

    assignment = make_assignment(agent_id, tenant_id, current_revision + 1, enabled=body.enabled)
    operation_id = str(getattr(request.state, "request_id", "") or uuid.uuid4().hex)
    audit_query = {"operation_id": operation_id, "tenant_id": tenant_id}
    audit_document = {
        **audit_query,
        "action": "server_monitoring_profile_change",
        "status": "REQUESTED",
        "actor_id": str(
            current_user.get("user_id")
            or current_user.get("sub")
            or current_user.get("username")
            or "unknown"
        )[:128],
        "target_agent_id": agent_id,
        "requested_revision": assignment["revision"],
        "profile_id": "general_server",
        "profile_version": 1,
        "enabled": body.enabled,
        "requested_at": datetime.now(timezone.utc),
    }
    try:
        await db["management_audit"].insert_one(audit_document)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Monitoring profile change could not be audited") from exc

    revision_filter = (
        {"monitoring_assignment.revision": current_revision}
        if current_revision
        else {"monitoring_assignment": {"$exists": False}}
    )
    result = await db["agents"].update_one(
        {"agent_id": agent_id, "tenant_id": tenant_id, **ACTIVE_AGENT_QUERY, **revision_filter},
        {"$set": {
            "asset_class": "server",
            "server_role": "general_server",
            "environment": body.environment,
            "criticality": body.criticality,
            "response_mode": "MONITOR_ONLY",
            "server_monitoring_required": True,
            "monitoring_assignment": assignment,
            "monitoring_profile_operation_id": operation_id,
            "monitoring_profile_updated_at": datetime.now(timezone.utc),
        }},
    )
    if result.modified_count != 1:
        await db["management_audit"].update_one(audit_query, {"$set": {"status": "CONFLICT"}})
        raise HTTPException(status_code=409, detail="Monitoring profile revision changed; refresh and retry")
    try:
        await db["management_audit"].update_one(
            audit_query,
            {"$set": {"status": "APPLIED", "completed_at": datetime.now(timezone.utc)}},
        )
    except Exception:
        logger.exception("Server profile applied but audit completion update failed: operation_id=%s", operation_id)
    return {
        "status": "assigned",
        "agent_id": agent_id,
        "asset_class": "server",
        "server_role": "general_server",
        "response_mode": "MONITOR_ONLY",
        "monitoring_assignment": assignment,
        "operation_id": operation_id,
    }

@router.get("/download")
async def download_agent(
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["Admin"])),
):
    cdn_url = (settings.agent_cdn_url or "").strip()
    if not cdn_url:
        logger.error("Agent download unavailable: AGENT_CDN_URL is empty")
        raise HTTPException(status_code=503, detail="Agent download is temporarily unavailable.")
    if not _is_valid_agent_cdn_url(cdn_url):
        logger.error("Agent download unavailable: AGENT_CDN_URL failed validation")
        raise HTTPException(status_code=503, detail="Agent download is temporarily unavailable.")

    return RedirectResponse(
        url=cdn_url,
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
        },
    )

@router.post("/deregister")
async def deregister_agent(
    request: Request,
    body: HeartbeatRequest,
    x_warsoc_signature: str = Header(..., description="Hex encoded Ed25519 signature of the request body"),
    db = Depends(get_db)
):
    redis_client = getattr(request.app.state, "redis", None)
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    # 1. Fetch Agent
    agent = await db["agents"].find_one({"agent_id": body.agent_id})
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    public_key_pem = agent.get("public_key")
    if not public_key_pem:
        raise HTTPException(status_code=400, detail="Agent missing public key")
        
    # 2. Verify Signature
    try:
        raw_body = await request.body()
        signature_bytes = bytes.fromhex(x_warsoc_signature)
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise HTTPException(status_code=400, detail="Invalid key type")
        public_key.verify(signature_bytes, raw_body)
    except Exception as exc:
        logger.warning(
            "Agent revocation signature validation failed: agent_id=%s error_type=%s",
            body.agent_id,
            type(exc).__name__,
        )
        raise HTTPException(status_code=401, detail="Cryptographic verification failed") from exc
        
    # 3. Block the agent immediately in Redis, then free one seat once.
    tenant_id = agent.get("tenant_id")
    count_key = f"tenant:{tenant_id}:active_count"
    await redis_client.set(f"warsoc:agent_status:{body.agent_id}", "inactive")
    await redis_client.set(f"warsoc:agent_revoked:{body.agent_id}", "1")
    await redis_client.hset(
        f"warsoc:agent_cache:{body.agent_id}",
        mapping={
            "tenant_id": tenant_id,
            "public_key": public_key_pem,
            "approved": "False",
            "status": "inactive"
        }
    )

    # 4. Mark inactive once. Repeated deregistration must not free extra seats.
    result = await db["agents"].update_one(
        {"agent_id": body.agent_id, "status": {"$ne": "inactive"}},
        {"$set": {"status": "inactive", "deregistered_at": datetime.now(timezone.utc)}}
    )
    seat_freed = result.modified_count > 0
    if seat_freed:
        decrement_script = """
        local tenant_count = tonumber(redis.call('GET', KEYS[1]) or '0')
        local platform_count = tonumber(redis.call('GET', KEYS[2]) or '0')
        if tenant_count > 0 then
            redis.call('DECR', KEYS[1])
        end
        if platform_count > 0 then
            redis.call('DECR', KEYS[2])
        end
        return 1
        """
        await redis_client.eval(
            decrement_script,
            2,
            count_key,
            PLATFORM_ACTIVE_COUNT_KEY,
        )
    
    return {
        "status": "ok",
        "message": "Agent deregistered and quota freed" if seat_freed else "Agent already inactive; no quota change",
        "seat_freed": seat_freed,
    }

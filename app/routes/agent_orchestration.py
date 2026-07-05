from fastapi import APIRouter, Depends, Request, HTTPException, Header
from pydantic import BaseModel, Field
import json
import uuid
import secrets
import ipaddress
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from typing import Any, Optional
from urllib.parse import urlparse
from fastapi.responses import RedirectResponse

from app.database import get_db
from app.routes.auth import get_current_user
from app.config.config import get_settings
from app.utils.rbac import RoleChecker
from app.utils.limiter import limiter


router = APIRouter()
settings = get_settings()

class ActivationResponse(BaseModel):
    activation_code: str
    expires_in_seconds: int

class AgentRegisterRequest(BaseModel):
    activation_code: str
    public_key: str # PEM encoded Ed25519 public key

class HeartbeatRequest(BaseModel):
    agent_id: str
    current_version: str
    timestamp: float = None
    sensor_status: dict[str, Any] | None = None


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
            channels[channel_name] = {
                "status": status,
                "last_checked_at": str(raw_channel.get("last_checked_at") or "")[:64],
                "last_event_at": str(raw_channel.get("last_event_at") or "")[:64],
                "last_error": str(raw_channel.get("last_error") or "")[:500] or None,
            }

    pos_audit = raw_status.get("pos_audit_log")
    pos_audit = pos_audit if isinstance(pos_audit, dict) else {}
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
    ):
        try:
            counters[counter_name] = max(0, int(raw_counters.get(counter_name) or 0))
        except (TypeError, ValueError):
            counters[counter_name] = 0
    return {
        "telemetry_config_version": str(raw_status.get("telemetry_config_version") or "unknown")[:64],
        "audit_policy_status": str(raw_status.get("audit_policy_status") or "unknown")[:32],
        "pos_sacl_path_count": max(0, min(pos_sacl_path_count, 1000)),
        "channels": channels,
        "counters": counters,
        "pos_audit_log": {
            "configured": bool(pos_audit.get("configured", False)),
            "present": bool(pos_audit.get("present", False)),
        },
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
@limiter.limit("10/minute")
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
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
        
    limit = tenant.get("max_agents", tenant.get("agent_limit", 10))
    
    current_count = int(await redis_client.get(f"tenant:{tenant_id}:active_count") or 0)
    if current_count >= limit:
        raise HTTPException(
            status_code=403, 
            detail=f"Agent license limit ({limit}) reached. Please upgrade to deploy more agents."
        )

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    code = "WARSOC-" + "".join(secrets.choice(alphabet) for _ in range(8))
    
    payload = {
        "tenant_id": tenant_id,
        "features": features,
        "created_by": current_user.get("username")
    }
    
    ttl = 86400
    await redis_client.setex(f"warsoc:activation:{code}", ttl, json.dumps(payload))
    
    return ActivationResponse(activation_code=code, expires_in_seconds=ttl)

@router.post("/register")
@limiter.limit("10/minute")
async def register_agent(
    request: Request,
    body: AgentRegisterRequest,
    db = Depends(get_db)
):
    redis_client = getattr(request.app.state, "redis", None)
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")
        
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
    if not tenant:
        raise HTTPException(status_code=401, detail="Activation code is not bound to an active tenant")
    limit = tenant.get("max_agents", tenant.get("agent_limit", 10))
    
    lua_script = """
    local current_count = tonumber(redis.call('GET', KEYS[1]) or '0')
    local limit = tonumber(ARGV[1])

    if current_count < limit then
        redis.call('INCR', KEYS[1])
        return 1
    else
        return 0
    end
    """
    
    count_key = f"tenant:{tenant_id}:active_count"
    success = await redis_client.eval(lua_script, 1, count_key, limit)
    if not success:
        raise HTTPException(
            status_code=403, 
            detail=f"Agent license limit ({limit}) reached. Registration denied."
        )
    
    agent_id = f"WARSOC_AGENT_{uuid.uuid4().hex}"
    now = datetime.now(timezone.utc)
    
    agent_doc = {
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "public_key": body.public_key,
        "status": "active",
        "key_rotation_status": "completed",
        "created_at": now,
        "last_seen": now,
        "last_ip": request.client.host,
        "features": payload.get("features", "SIEM")
    }
    
    try:
        await db["agents"].insert_one(agent_doc)
    except Exception as exc:
        rollback_script = """
        local current_count = tonumber(redis.call('GET', KEYS[1]) or '0')
        if current_count > 0 then
            return redis.call('DECR', KEYS[1])
        end
        return 0
        """
        rollback_failed = False
        try:
            await redis_client.eval(rollback_script, 1, count_key)
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
                "public_key": body.public_key,
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
        doc_status = str(agent.get("status", "active")).strip().lower()
        if not agent.get("approved", True) or doc_status != "active":
            await redis_client.set(status_key, doc_status or "inactive")
            await redis_client.set(revoked_key, "1")
            raise HTTPException(status_code=403, detail="Agent is inactive")
            
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
        
        # 0-Mercy Nonce/Timestamp validation
        if body.timestamp is not None:
            now_ts = datetime.now(timezone.utc).timestamp()
            if abs(now_ts - body.timestamp) > 30:
                raise HTTPException(status_code=401, detail="Expired Signature: Timestamp is older than 30 seconds. Replay Attack Prevented.")
                
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Cryptographic verification failed: {repr(e)}")
        
    if tenant_id:
        sensor_status = _sanitize_sensor_status(body.sensor_status)
        await redis_client.set(
            f"status:{tenant_id}:{body.agent_id}",
            datetime.now(timezone.utc).isoformat(),
            ex=600,
        )
        await redis_client.set(
            f"warsoc:agent_sensor:{body.agent_id}",
            json.dumps(sensor_status),
            ex=600,
        )

    enforce_bans = await _get_tenant_enforce_bans(redis_client, tenant_id) if tenant_id else []

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
                    "sensor_status": _sanitize_sensor_status(body.sensor_status),
                }
            },
        )
        await redis_client.setex(f"warsoc:agent_cache:db_update:{body.agent_id}", 60, "1")
    
    # Check OTA Updates
    auto_update_enabled = getattr(settings, "auto_update_enabled", "false").lower() == "true"
    
    if auto_update_enabled:
        target_version = getattr(settings, "agent_target_version", "1.0.0")
        if body.current_version != target_version:
            return {
                "status": "ok",
                "update_available": True,
                "enforce_bans": enforce_bans,
                "target_version": target_version,
                "download_url": f"https://ota.warsoc.io/releases/windows/warsoc_agent_v{target_version}.exe",
                "release_signature": getattr(settings, "agent_release_signature", "mock_ed25519_signature_hex")
            }
            
    return {
        "status": "ok",
        "update_available": False,
        "enforce_bans": enforce_bans
    }

@router.get("/download")
async def download_agent(
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["Admin"])),
):
    cdn_url = (settings.agent_cdn_url or "").strip()
    if not cdn_url:
        raise HTTPException(status_code=503, detail="Agent installer URL is not configured.")
    if not _is_valid_agent_cdn_url(cdn_url):
        raise HTTPException(status_code=503, detail="Agent installer URL is misconfigured.")

    return RedirectResponse(url=cdn_url)

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
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Cryptographic verification failed: {e}")
        
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
        local current_count = tonumber(redis.call('GET', KEYS[1]) or '0')
        if current_count > 0 then
            return redis.call('DECR', KEYS[1])
        end
        return 0
        """
        await redis_client.eval(decrement_script, 1, count_key)
    
    return {
        "status": "ok",
        "message": "Agent deregistered and quota freed" if seat_freed else "Agent already inactive; no quota change",
        "seat_freed": seat_freed,
    }

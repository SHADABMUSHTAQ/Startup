import asyncio
import uuid
from fastapi import APIRouter, HTTPException, Depends, Request, Query
from pydantic import BaseModel, Field, ValidationError, parse_obj_as, validator, ConfigDict
from typing import Union, Optional, List
from datetime import datetime, timezone
import json
import hashlib
from ecdsa import VerifyingKey, BadSignatureError
import logging
import redis.asyncio as aioredis
from ipaddress import ip_address, ip_network
from app.config.config import get_settings, load_config

from app.database import get_db
# 🚨 Secures the Dashboard endpoints below
from app.routes.auth import get_current_user, verify_agent_token
from app.utils.agent_crypto import (
    build_event_signature_string,
    build_payload_hash,
    build_signable_event_payload,
    parse_utc_timestamp,
    timestamp_age_seconds,
)

router = APIRouter()
settings = get_settings()
logger = logging.getLogger("ingest_pulse")
RAW_LOGS_QUEUE = "raw_logs_queue"
RAW_LOGS_QUEUE_MAXLEN = 100000
RAW_RETENTION_ANCHOR_FIELD = "_retention_ts"
STATUS_KEY_PREFIX = "status"
STATUS_TTL_SECONDS = 86400
MAX_INGEST_BODY_BYTES = 5 * 1024 * 1024

# 🛡️ Load security configuration once
_security_config = None

def _get_security_config():
    global _security_config
    if _security_config is None:
        try:
            config = load_config("config.json")
            _security_config = config.get("agent_security", {})
        except Exception:
            _security_config = {}
    return _security_config

def _is_ip_whitelisted(client_ip: str, allowed_ips: list) -> bool:
    """Check if client IP is in whitelist (supports CIDR notation)."""
    try:
        client_addr = ip_address(client_ip)
        for allowed in allowed_ips:
            try:
                # Try as CIDR range first
                if "/" in allowed:
                    if client_addr in ip_network(allowed, strict=False):
                        return True
                # Try as exact IP
                elif client_addr == ip_address(allowed):
                    return True
                # Try as hostname (literal match for localhost)
                elif allowed == "localhost" and client_ip in ["127.0.0.1", "localhost", "::1"]:
                    return True
            except (ValueError, TypeError):
                continue
        return False
    except (ValueError, TypeError):
        # If client_ip is invalid, reject it
        return False

def _parse_timestamp_utc(timestamp_str: str) -> Optional[datetime]:
    """Parse ISO timestamp and normalize to UTC."""
    try:
        if not isinstance(timestamp_str, str):
            return None

        ts = timestamp_str.strip()
        if not ts:
            return None

        # Split timezone suffix so fractional normalization does not alter offset info.
        tz_suffix = ""
        ts_core = ts

        if ts_core.endswith("Z"):
            tz_suffix = "Z"
            ts_core = ts_core[:-1]
        elif (
            len(ts_core) >= 6
            and ts_core[-6] in "+-"
            and ts_core[-3] == ":"
            and ts_core[-5:-3].isdigit()
            and ts_core[-2:].isdigit()
        ):
            tz_suffix = ts_core[-6:]
            ts_core = ts_core[:-6]

        # Python 3.10 rejects 7-digit fractions from Windows/.NET ticks.
        if "." in ts_core:
            head, frac = ts_core.rsplit(".", 1)
            if frac.isdigit() and len(frac) == 7:
                ts_core = f"{head}.{frac[:6]}"

        normalized_ts = f"{ts_core}{tz_suffix}"
        log_time = datetime.fromisoformat(normalized_ts.replace("Z", "+00:00"))

        # For naive timestamps, assume UTC to avoid host-local clock ambiguity.
        if log_time.tzinfo is None:
            log_time = log_time.replace(tzinfo=timezone.utc)
        else:
            log_time = log_time.astimezone(timezone.utc)

        return log_time
    except (ValueError, TypeError):
        return None


def _timestamp_age_seconds(timestamp_str: str) -> Optional[int]:
    log_time = _parse_timestamp_utc(timestamp_str)
    if log_time is None:
        return None
    now = datetime.now(timezone.utc)
    return int((now - log_time).total_seconds())


async def _read_json_body_with_limit(request: Request, max_bytes: int = MAX_INGEST_BODY_BYTES):
    buffer = bytearray()
    async for chunk in request.stream():
        if not chunk:
            continue
        buffer.extend(chunk)
        if len(buffer) > max_bytes:
            raise HTTPException(status_code=413, detail="Payload too large")

    if not buffer:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    try:
        return json.loads(buffer.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc


def _classify_clock_integrity(
    timestamp_str: str,
    skew_warning_seconds: int,
    hard_drop_seconds: int,
) -> tuple[str, Optional[int]]:
    """
    Hybrid Skew Guard:
    - |delta| <= skew_warning_seconds -> allow
    - skew_warning_seconds < |delta| < hard_drop_seconds -> skew (ingest with metadata)
    - |delta| >= hard_drop_seconds or invalid timestamp -> drop
    """
    delta_seconds = _timestamp_age_seconds(timestamp_str)
    if delta_seconds is None:
        return "drop", None

    abs_delta = abs(delta_seconds)
    if abs_delta >= hard_drop_seconds:
        return "drop", delta_seconds
    if abs_delta > skew_warning_seconds:
        return "skew", delta_seconds
    return "allow", delta_seconds


class WindowsAgentPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    agent_id: str
    source_ip: str
    user: str
    event_id: int
    event_uid: str
    message: str
    timestamp: str
    raw_data: Union[dict, str] = Field(default_factory=dict)
    processed_data: Optional[dict] = None
    raw_event_data: Optional[Union[dict, str]] = None
    agent_signature: Optional[str] = None
    agent_hmac_signature: Optional[str] = None
    agent_version: str
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None

    @validator("raw_data", pre=True)
    def coerce_raw_data(cls, v):
        if isinstance(v, str):
            return {"raw": v}
        return v


async def _validate_signed_payload_batch(
    payload_items: list[tuple[WindowsAgentPayload, Optional[dict]]],
    request: Request,
    agent_context: dict,
    skew_warning_seconds: int,
    hard_drop_seconds: int,
) -> list[tuple[WindowsAgentPayload, Optional[dict]]]:
    redis_client = getattr(request.app.state, "redis", None)
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable for signature verification")

    verified_agent_id = agent_context["agent_id"]
    verified_tenant_id = agent_context["tenant_id"]
    public_key = agent_context.get("public_key")
    if not public_key:
        raise HTTPException(status_code=401, detail="Agent public key unavailable")

    verifying_key = VerifyingKey.from_pem(public_key)
    valid_payloads: list[tuple[WindowsAgentPayload, Optional[dict]]] = []

    for payload, _ in payload_items:
        if payload.agent_id != verified_agent_id:
            raise HTTPException(status_code=403, detail="Agent payload identity mismatch")

        # 🛡️ REPLAY GUARD: Read-only check to reject intercepted/duplicated payloads
        replay_key = f"warsoc:event_sig:{verified_tenant_id}:{verified_agent_id}:{payload.event_uid}"
        if await redis_client.exists(replay_key):
            raise HTTPException(status_code=401, detail="Replay detected for event_uid")

        signature = payload.agent_signature or payload.agent_hmac_signature
        if not signature:
            raise HTTPException(status_code=401, detail="Signed payload required")

        # Compatibility bridge: prefer ECDSA (`agent_signature`). Optionally reject
        # legacy HMAC-only payloads when configured via agent_security.reject_legacy_hmac.
        sec_cfg = _get_security_config()
        if payload.agent_hmac_signature and not payload.agent_signature:
            if sec_cfg.get("reject_legacy_hmac", False):
                raise HTTPException(status_code=401, detail="Legacy HMAC signatures are rejected; enroll agent with ECDSA")
            else:
                logger.warning(
                    "Legacy HMAC signature accepted for agent %s; consider enrolling ECDSA public key",
                    payload.agent_id,
                )
        if not payload.event_uid:
            raise HTTPException(status_code=401, detail="event_uid is required for signed ingest")

        timestamp = payload.timestamp or datetime.now(timezone.utc).isoformat()
        verdict, delta_seconds = _classify_clock_integrity(
            timestamp,
            skew_warning_seconds=skew_warning_seconds,
            hard_drop_seconds=hard_drop_seconds,
        )
        if verdict == "drop":
            raise HTTPException(status_code=401, detail="Signed payload timestamp outside allowed drift window")

        time_integrity = None
        if verdict == "skew":
            time_integrity = {
                "skewed": True,
                "skew_seconds": delta_seconds,
                "reason": "clock_drift",
            }

        signable_payload = build_signable_event_payload(payload.dict())
        payload_hash = build_payload_hash(signable_payload)
        canonical = build_event_signature_string(
            payload.agent_id,
            payload.timestamp,
            payload.event_uid,
            payload_hash,
        )

        try:
            verifying_key.verify(
                bytes.fromhex(signature),
                canonical.encode("utf-8"),
                hashfunc=hashlib.sha256,
            )
        except (BadSignatureError, ValueError):
            raise HTTPException(status_code=401, detail="Invalid signed payload")

        valid_payloads.append((payload, time_integrity))

    return valid_payloads

from app.utils.limiter import limiter

# ---------------------------------------------------------
# 📥 1. INGEST WINDOWS AGENT LOGS (BULK REDIS PIPELINE)
@router.post("/pulse")
@limiter.limit("300/second")
async def ingest_pulse_logs(
    request: Request,
    agent_context: dict = Depends(verify_agent_token)
):
    try:
        verified_tenant_id = agent_context["tenant_id"]
        verified_agent_id = agent_context["agent_id"]
        client_ip = request.client.host if request.client else "0.0.0.0"

        # 🛡️ BANNED IP CHECK AT API PERIMETER: Block malicious IPs before JSON parsing
        # Fast Redis EXISTS check prevents banned traffic from touching the queue
        redis_client = getattr(request.app.state, "redis", None)
        if redis_client:
            ban_key = f"warsoc:banned_ips:{verified_tenant_id}"
            is_banned = await redis_client.sismember(ban_key, client_ip)
            if is_banned:
                logger.warning(f"[SECURITY] Banned IP {client_ip} attempted ingest for tenant {verified_tenant_id}")
                raise HTTPException(
                    status_code=403,
                    detail=f"IP {client_ip} has been banned by tenant security policy"
                )

        # 🛡️ THE INGESTION THROTTLE: Strict Redis-backed Rate Limiter BEFORE JSON Parsing
        # This prevents FastAPI workers from getting DDoS'd by bad actors spoofing agent payloads (JSON memory exhaustion)
        redis_client = getattr(request.app.state, "redis", None)
        if redis_client:
            throttle_key = f"warsoc:throttle:tenant:{verified_tenant_id}"
            # Track requests per minute per tenant
            current_requests = await redis_client.incr(throttle_key)
            if current_requests == 1:
                await redis_client.expire(throttle_key, 60)
            
            # If a tenant blasts more than 5000 requests per minute, drop connection instantly
            if current_requests > 5000:
                raise HTTPException(
                    status_code=429,
                    detail=f"Tenant Rate Limit Exceeded: {verified_tenant_id} is sending too many requests (>5000/min)."
                )

        raw_payload = await _read_json_body_with_limit(request)

        if isinstance(raw_payload, dict):
            payloads = [raw_payload]
        elif isinstance(raw_payload, list):
            payloads = raw_payload
        else:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

        unpacked_payloads = []
        for payload in payloads:
            if "metrics" in payload and isinstance(payload["metrics"], list):
                for metric in payload["metrics"]:
                    fields = metric.get("fields", {})
                    tags = metric.get("tags", {})
                    unpacked_payloads.append({
                        "agent_id": tags.get("agent_id") or tags.get("tenant_id") or fields.get("agent_id") or fields.get("tenant_id", "UNKNOWN"),
                        "source_ip": fields.get("src_ip") or tags.get("src_ip", "0.0.0.0"),
                        "user": fields.get("user") or tags.get("user", "SYSTEM"),
                        "event_id": fields.get("event_id", 0),
                        "event_uid": str(fields.get("event_uid") or uuid.uuid4().hex),
                        "message": fields.get("message", "Unknown Event"),
                        "timestamp": fields.get("timestamp") or tags.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                        "raw_data": fields,
                        "raw_event_data": fields,
                        "processed_data": {},
                        "agent_signature": fields.get("agent_signature") or fields.get("agent_hmac_signature"),
                        "agent_version": "telegraf_polyglot",
                    })
            elif "fields" in payload:
                fields = payload.get("fields", {})
                tags = payload.get("tags", {})
                unpacked_payloads.append({
                    "agent_id": tags.get("agent_id") or tags.get("tenant_id") or fields.get("agent_id") or fields.get("tenant_id", "UNKNOWN"),
                    "source_ip": fields.get("src_ip") or tags.get("src_ip", "0.0.0.0"),
                    "user": fields.get("user") or tags.get("user", "SYSTEM"),
                    "event_id": fields.get("event_id", 0),
                    "event_uid": str(fields.get("event_uid") or uuid.uuid4().hex),
                    "message": fields.get("message", "Unknown Event"),
                    "timestamp": fields.get("timestamp") or tags.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                    "raw_data": fields,
                    "raw_event_data": fields,
                    "processed_data": {},
                    "agent_signature": fields.get("agent_signature") or fields.get("agent_hmac_signature"),
                    "agent_version": "telegraf_polyglot",
                })
            else:
                candidate = dict(payload)
                candidate.setdefault("event_uid", uuid.uuid4().hex)
                unpacked_payloads.append(candidate)

        sanitized_payloads = []
        for payload in unpacked_payloads:
            if not isinstance(payload, dict):
                continue
            event_id = payload.get("event_id")
            if isinstance(event_id, bool):
                continue
            try:
                if event_id is None or str(event_id).strip() == "":
                    continue
                payload["event_id"] = int(event_id)
                sanitized_payloads.append(payload)
            except (TypeError, ValueError):
                continue

        if not sanitized_payloads:
            raise HTTPException(status_code=400, detail="No valid events found in payload")

        try:
            parsed_payloads = parse_obj_as(List[WindowsAgentPayload], sanitized_payloads)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=exc.errors()) from exc

        payload_items = [(payload, None) for payload in parsed_payloads]
        security_config = _get_security_config()
        redis_client = getattr(request.app.state, "redis", None)

        if redis_client:
            rate_key = f"warsoc:ratelimit:tenant:{verified_tenant_id}"
            current_usage = await redis_client.incrby(rate_key, len(payload_items))
            if current_usage == len(payload_items):
                await redis_client.expire(rate_key, 60)
            if current_usage > 5000:
                raise HTTPException(
                    status_code=429,
                    detail=f"Tenant Rate Limit Exceeded: {verified_tenant_id} is sending too many logs (>5000/min).",
                )

        if security_config.get("enforce_ip_whitelist", True):
            client_ip = request.client.host if request.client else "0.0.0.0"
            allowed_ips = security_config.get("allowed_ips", ["127.0.0.1", "localhost"])
            if not _is_ip_whitelisted(client_ip, allowed_ips):
                raise HTTPException(status_code=403, detail=f"Unrecognized Agent IP: {client_ip} is not in whitelist")

        if security_config.get("enforce_payload_size", True):
            max_payload_bytes = security_config.get("max_payload_bytes", MAX_INGEST_BODY_BYTES)
            if len(json.dumps(raw_payload, default=str).encode("utf-8")) > max_payload_bytes:
                raise HTTPException(status_code=413, detail=f"Payload too large: {max_payload_bytes} bytes max")

        skew_warning_seconds = int(security_config.get("clock_skew_warning_seconds", 60))
        hard_drop_seconds = int(security_config.get("max_log_age_seconds", 300))
        if hard_drop_seconds <= skew_warning_seconds:
            hard_drop_seconds = skew_warning_seconds + 1

        payload_items = await _validate_signed_payload_batch(
            payload_items,
            request,
            agent_context,
            skew_warning_seconds=skew_warning_seconds,
            hard_drop_seconds=hard_drop_seconds,
        )

        redis = request.app.state.redis
        if not redis:
            raise HTTPException(status_code=503, detail="Redis unavailable for ingest queue")

        status_updates = []
        async with redis.pipeline(transaction=True) as pipe:
            for payload, time_integrity in payload_items:
                log_data = payload.dict()
                if not log_data.get("timestamp"):
                    log_data["timestamp"] = datetime.now(timezone.utc).isoformat()

                log_data["tenant_id"] = verified_tenant_id
                log_data["agent_id"] = verified_agent_id
                log_data["agent_signature"] = payload.agent_signature or payload.agent_hmac_signature
                log_data.pop("agent_hmac_signature", None)

                if time_integrity is not None:
                    log_data["time_integrity"] = time_integrity

                payload_to_stream = {"payload": json.dumps(log_data, default=str)}
                replay_key = f"warsoc:event_sig:{verified_tenant_id}:{verified_agent_id}:{payload.event_uid}"
                await pipe.xadd(
                    RAW_LOGS_QUEUE,
                    payload_to_stream,
                    maxlen=RAW_LOGS_QUEUE_MAXLEN,
                    approximate=True,
                )
                await pipe.set(replay_key, "1", ex=hard_drop_seconds, nx=True)
                status_updates.append((verified_tenant_id, verified_agent_id))

            await pipe.execute()

        current_utc_timestamp = datetime.now(timezone.utc).isoformat()
        for tenant_id, agent_id in set(status_updates):
            asyncio.create_task(
                redis.set(
                    f"{STATUS_KEY_PREFIX}:{tenant_id}:{agent_id}",
                    current_utc_timestamp,
                    ex=STATUS_TTL_SECONDS,
                )
            )

        return {
            "status": "success",
            "queued": len(payload_items),
            "rejected": 0,
            "message": f"Successfully queued {len(payload_items)} signed logs in Redis Stream.",
            "action": "ALLOW",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Bulk ingestion error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to queue log batch")

# ---------------------------------------------------------
# 💓 1.5 AGENT HEARTBEAT (DEAD AIR DETECTION)
# ---------------------------------------------------------
@router.post("/heartbeat")
@limiter.limit("5/minute")
async def ingest_heartbeat(
    request: Request,
    agent_context: dict = Depends(verify_agent_token)
):
    """
    Lightweight endpoint for Windows Agent to declare it is alive.
    Maintains a 10-minute TTL in Redis.
    """
    redis_client = getattr(request.app.state, "redis", None)
    if not redis_client:
        return {"status": "degraded", "message": "Heartbeat received but Redis is down"}

    verified_tenant_id = agent_context["tenant_id"]
    verified_agent_id = agent_context["agent_id"]
    key = f"LAST_HEARTBEAT:{verified_tenant_id}:{verified_agent_id}"
    await redis_client.set(key, datetime.now(timezone.utc).isoformat(), ex=600)

    return {"status": "success", "message": "Heartbeat recorded"}

# ---------------------------------------------------------
# 📜 2. FETCH MITIGATED ALERTS HISTORY
# ---------------------------------------------------------
@router.get("/alerts/history")
async def get_alert_history(
    db = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Securely fetches history, strictly isolated by Tenant ID"""
    secure_tenant_id = current_user.get("tenant_id")
    try:
        alert_query = {"tenant_id": secure_tenant_id}
        fresh_start_at = current_user.get("agent_issued_at")
        if fresh_start_at:
            alert_query["timestamp"] = {"$gte": fresh_start_at}

        cursor = db["security_alerts"].find(alert_query).sort("timestamp", -1).limit(50)
        history = await cursor.to_list(length=50)
        for doc in history:
            doc["_id"] = str(doc["_id"])
        return history
    except Exception as e:
        logger.warning("Alert history fetch failed: %s", e)
        return []

# ---------------------------------------------------------
# 📊 3. FETCH LIVE AGENT LOGS FOR DASHBOARD 
# ---------------------------------------------------------
@router.get("/logs")
async def fetch_agent_logs(
    limit: int = Query(10, le=100),
    db = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Securely fetches raw logs, strictly isolated by Tenant ID"""
    secure_tenant_id = current_user.get("tenant_id")
    if not secure_tenant_id:
        raise HTTPException(status_code=403, detail="Critical: User lacks tenant assignment.")

    try:
        cursor = db["logs"].find({"tenant_id": secure_tenant_id}).sort("timestamp", -1).limit(limit)
        logs = await cursor.to_list(length=limit)
        for doc in logs:
            doc["_id"] = str(doc["_id"])
            doc.pop(RAW_RETENTION_ANCHOR_FIELD, None)
        return {"status": "success", "data": logs}
    except Exception as e:
        logger.warning("Agent logs fetch failed: %s", e)
        return {"status": "success", "data": []}

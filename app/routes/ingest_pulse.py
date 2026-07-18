import asyncio
import uuid
import orjson
from fastapi import APIRouter, HTTPException, Depends, Request, Query
from fastapi.responses import ORJSONResponse
from pydantic import BaseModel, Field, validator, ConfigDict
from typing import Union, Optional
from datetime import datetime, timezone
import json
import logging
import os
import re
import redis.asyncio as aioredis
from ipaddress import ip_address, ip_network
from app.config.config import get_settings, load_config
from app.utils.siem_catalog import SIEM_RULES
from app.utils.security_policy import effective_agent_limit

from app.database import get_db
#  Secures the Dashboard endpoints below
from app.routes.auth import get_current_user, verify_agent_token
from app.utils.agent_crypto import parse_utc_timestamp, timestamp_age_seconds

router = APIRouter()
settings = get_settings()
logger = logging.getLogger("ingest_pulse")
RAW_LOGS_QUEUE = "raw_logs_queue"
SIEM_HOT_QUEUE = "siem_hot_queue"
RAW_RETENTION_ANCHOR_FIELD = "_retention_ts"
STATUS_KEY_PREFIX = "status"
STATUS_TTL_SECONDS = 600
MAX_INGEST_BODY_BYTES = 5 * 1024 * 1024
DEFAULT_AGENT_LIMIT_FOR_QUOTA = 10
DEFAULT_DAILY_INGEST_BYTES_PER_AGENT = int(os.getenv("INGEST_DAILY_BYTES_PER_AGENT", str(50 * 1024 * 1024)))
DEFAULT_DAILY_INGEST_BYTES_FLOOR = int(os.getenv("INGEST_DAILY_BYTES_FLOOR", str(1024 * 1024 * 1024)))
MAX_DAILY_INGEST_BYTES = int(os.getenv("INGEST_DAILY_BYTES_MAX", str(3 * 1024 * 1024 * 1024)))
INGEST_DAILY_QUOTA_TTL_SECONDS = int(os.getenv("INGEST_DAILY_QUOTA_TTL_SECONDS", str(3 * 24 * 60 * 60)))
RAW_STREAM_MAX_ENTRIES = int(os.getenv("RAW_STREAM_MAX_ENTRIES", "500000"))

_GENERIC_HIGH_SIGNAL_KEYWORDS = {
    "../",
    "..\\",
    "<script",
    "authentication failure",
    "certutil",
    "clear-eventlog",
    "cobalt strike",
    "drop table",
    "failed password",
    "hashcat",
    "javascript:",
    "login failed",
    "meterpreter",
    "mimikatz",
    "powershell",
    "rubeus",
    "union select",
    "vssadmin",
    "wevtutil",
    "xp_cmdshell",
}


def _siem_hot_event_ids() -> set[str]:
    event_ids = {str(event_id) for event_id in (SIEM_RULES.get("event_id_map", {}) or {}).keys()}
    for source_cfg in (SIEM_RULES.get("source_classification", {}) or {}).values():
        event_ids.update(str(event_id) for event_id in source_cfg.get("trigger_event_ids", []))
    return event_ids


def _siem_interest_keywords() -> set[str]:
    keywords = set(_GENERIC_HIGH_SIGNAL_KEYWORDS)
    for source_cfg in (SIEM_RULES.get("source_classification", {}) or {}).values():
        for keyword in (source_cfg.get("severity_by_keyword", {}) or {}).keys():
            text = str(keyword or "").strip().lower()
            if len(text) >= 3:
                keywords.add(text)
    return keywords


SIEM_HOT_EVENT_IDS = _siem_hot_event_ids()
SIEM_INTEREST_KEYWORDS = _siem_interest_keywords()


def _is_siem_hot_event(log_data: dict) -> bool:
    event_id = str(log_data.get("event_id") or "").strip()
    if event_id in SIEM_HOT_EVENT_IDS:
        return True

    message = str(log_data.get("message") or "").lower()
    if not message:
        return False

    return any(keyword in message for keyword in SIEM_INTEREST_KEYWORDS)

#  Load security configuration once
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


def _agent_ingress_whitelist_enabled(security_config: dict) -> bool:
    """
    Agent auth, signed heartbeats, replay protection, and rate limits are the
    default production controls. IP allow-listing is opt-in for closed pilots.
    """
    override = os.getenv("AGENT_ENFORCE_IP_WHITELIST")
    if override is not None and override.strip():
        return override.strip().lower() in {"1", "true", "yes", "on"}
    return bool(security_config.get("enforce_ip_whitelist", False))

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


def _redis_text(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _positive_int(value, default: int = 0) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


async def _resolve_daily_ingest_quota_bytes(redis_client, tenant_id: str) -> int:
    tenant_override = _redis_text(await redis_client.get(f"tenant_ingest_quota_bytes:{tenant_id}"))
    override_quota = _positive_int(tenant_override)
    if override_quota:
        return min(override_quota, MAX_DAILY_INGEST_BYTES) if MAX_DAILY_INGEST_BYTES > 0 else override_quota

    cached_limit = _redis_text(await redis_client.get(f"tenant_agent_limit:{tenant_id}"))
    agent_limit = effective_agent_limit(
        _positive_int(cached_limit, DEFAULT_AGENT_LIMIT_FOR_QUOTA),
        DEFAULT_AGENT_LIMIT_FOR_QUOTA,
    )
    quota = max(
        DEFAULT_DAILY_INGEST_BYTES_FLOOR,
        agent_limit * max(1, DEFAULT_DAILY_INGEST_BYTES_PER_AGENT),
    )
    return min(quota, MAX_DAILY_INGEST_BYTES) if MAX_DAILY_INGEST_BYTES > 0 else quota


async def _enforce_daily_ingest_quota(redis_client, tenant_id: str, payload_bytes: int) -> None:
    if payload_bytes <= 0:
        return

    try:
        quota_bytes = await _resolve_daily_ingest_quota_bytes(redis_client, tenant_id)
        day_bucket = datetime.now(timezone.utc).strftime("%Y%m%d")
        quota_key = f"warsoc:ingest:bytes:{tenant_id}:{day_bucket}"
        script = """
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local increment = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
if current + increment > limit then
  return {0, current, limit}
end
local updated = redis.call('INCRBY', KEYS[1], increment)
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
return {1, updated, limit}
"""
        result = await redis_client.eval(
            script,
            1,
            quota_key,
            int(payload_bytes),
            int(quota_bytes),
            int(INGEST_DAILY_QUOTA_TTL_SECONDS),
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Tenant ingest quota check failed for %s: %s", tenant_id, exc)
        raise HTTPException(status_code=503, detail="Ingest quota service unavailable") from exc

    allowed = int(result[0]) if result else 0
    if allowed != 1:
        used = int(result[1]) if len(result) > 1 else 0
        quota = int(result[2]) if len(result) > 2 else 0
        logger.warning(
            "Tenant daily ingest quota exceeded: tenant=%s used=%s quota=%s attempted=%s",
            tenant_id,
            used,
            quota,
            payload_bytes,
        )
        raise HTTPException(
            status_code=429,
            detail="Tenant daily ingest quota exceeded. Contact WarSOC support to raise the contracted ingest limit.",
        )


async def _enforce_raw_stream_capacity(redis_client) -> None:
    if RAW_STREAM_MAX_ENTRIES <= 0:
        return
    try:
        stream_length = int(await redis_client.xlen(RAW_LOGS_QUEUE))
    except Exception as exc:
        logger.error("Raw ingest stream capacity check failed: %s", exc)
        raise HTTPException(status_code=503, detail="Ingest queue capacity check unavailable") from exc
    if stream_length >= RAW_STREAM_MAX_ENTRIES:
        logger.error(
            "Raw ingest stream reached its admission limit: length=%s limit=%s",
            stream_length,
            RAW_STREAM_MAX_ENTRIES,
        )
        raise HTTPException(
            status_code=503,
            detail="Ingest queue is under pressure. Agent must retain and retry the batch.",
        )


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


def _normalize_stream_payloads(raw_payload, agent_context: dict) -> list[dict]:
    tenant_id = agent_context["tenant_id"]
    agent_id = agent_context["agent_id"]
    public_key = agent_context.get("public_key")
    normalized_payloads: list[dict] = []

    if isinstance(raw_payload, dict):
        payloads = [raw_payload]
    elif isinstance(raw_payload, list):
        payloads = raw_payload
    else:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    for payload in payloads:
        if not isinstance(payload, dict):
            continue

        if "metrics" in payload and isinstance(payload["metrics"], list):
            metric_source = payload["metrics"]
        else:
            metric_source = [payload]

        for metric in metric_source:
            if not isinstance(metric, dict):
                continue

            fields = metric.get("fields") if isinstance(metric.get("fields"), dict) else metric
            tags = metric.get("tags") if isinstance(metric.get("tags"), dict) else {}
            raw_event_id = fields.get("event_id", payload.get("event_id"))
            candidate = {
                "agent_id": tags.get("agent_id") or tags.get("tenant_id") or fields.get("agent_id") or agent_id,
                "source_ip": fields.get("src_ip") or tags.get("src_ip") or payload.get("source_ip") or "0.0.0.0",
                "user": fields.get("user") or tags.get("user") or payload.get("user") or "SYSTEM",
                "event_id": "" if raw_event_id is None else str(raw_event_id).strip(),
                "event_type": fields.get("event_type") or payload.get("event_type") or "",
                "event_uid": str(fields.get("event_uid") or payload.get("event_uid") or uuid.uuid4().hex),
                "message": fields.get("message", payload.get("message", "Unknown Event")),
                "timestamp": fields.get("timestamp") or tags.get("timestamp") or payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                "raw_data": payload.get("raw_data") or fields,
                "raw_event_data": payload.get("raw_event_data") or fields,
                "processed_data": payload.get("processed_data") or {},
                # Signatures removed from worker ingest per CTO directive; strip any provided values.
                "agent_signature": None,
                "agent_version": payload.get("agent_version") or "telegraf_polyglot",
                "tenant_id": tenant_id,
                "public_key": payload.get("public_key") or public_key,
            }

            if not candidate["event_id"]:
                continue

            normalized_payloads.append(candidate)

    return normalized_payloads


async def _consume_agent_ingest_envelope(raw_payload, agent_id: str, redis_client):
    """Validate and atomically consume the required anti-replay envelope."""
    if not isinstance(raw_payload, dict) or set(raw_payload) != {
        "nonce",
        "timestamp",
        "payload",
    }:
        raise HTTPException(
            status_code=422,
            detail="Agent ingest requires nonce, timestamp, and payload fields",
        )

    nonce = str(raw_payload.get("nonce") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce):
        raise HTTPException(status_code=400, detail="Invalid nonce format in wrapper")
    try:
        agent_ts = int(raw_payload.get("timestamp"))
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid timestamp format in wrapper") from exc

    now_ts = int(datetime.now(timezone.utc).timestamp())
    if abs(now_ts - agent_ts) > 300:
        logger.warning(
            "[SECURITY] Agent envelope timestamp is outside the allowed window: agent=%s",
            agent_id,
        )
        raise HTTPException(
            status_code=400,
            detail="Payload timestamp out of acceptable 5-minute window",
        )
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable for replay protection")

    nonce_key = f"warsoc:nonce:{agent_id}:{nonce}"
    nonce_accepted = await redis_client.set(
        nonce_key,
        "consumed",
        nx=True,
        ex=300,
    )
    if not nonce_accepted:
        logger.warning("[SECURITY] Replay attack blocked for agent %s", agent_id)
        raise HTTPException(
            status_code=409,
            detail="Conflict: Replay attack detected (Nonce already consumed)",
        )

    events_data = raw_payload.get("payload")
    if isinstance(events_data, dict):
        return [events_data]
    if not isinstance(events_data, list):
        raise HTTPException(status_code=422, detail="Envelope payload must be an event or list")
    return events_data


from app.utils.limiter import limiter

from app.utils.rate_limiter import redis_ingest_rate_limit

# ---------------------------------------------------------
# 📥 1. INGEST WINDOWS AGENT LOGS (BULK REDIS PIPELINE)
@router.post("/pulse", status_code=202, response_class=ORJSONResponse)
@limiter.limit("300/second")
async def ingest_pulse_logs(
    request: Request,
    agent_context: dict = Depends(verify_agent_token),
    _rate_limit=Depends(redis_ingest_rate_limit)
):
    try:
        verified_tenant_id = agent_context["tenant_id"]
        verified_agent_id = agent_context["agent_id"]
        client_ip = request.client.host if request.client else "0.0.0.0"

        #  BANNED IP CHECK AT API PERIMETER: Block malicious IPs before JSON parsing
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

        #  THE INGESTION THROTTLE: Handled by Depends(redis_ingest_rate_limit) middleware

        raw_payload = await _read_json_body_with_limit(request)
        raw_payload_bytes = len(orjson.dumps(raw_payload))

        await _enforce_raw_stream_capacity(redis_client)

        raw_events = await _consume_agent_ingest_envelope(
            raw_payload,
            verified_agent_id,
            redis_client,
        )
        original_raw_payload = raw_payload
        await _enforce_daily_ingest_quota(
            redis_client,
            verified_tenant_id,
            raw_payload_bytes,
        )

        sanitized_payloads = _normalize_stream_payloads(raw_events, agent_context)

        if not sanitized_payloads:
            raise HTTPException(status_code=400, detail="No valid events found in payload")

        payload_items = sanitized_payloads



        security_config = _get_security_config()

        if _agent_ingress_whitelist_enabled(security_config):
            client_ip = request.client.host if request.client else "0.0.0.0"
            allowed_ips = security_config.get("allowed_ips", ["127.0.0.1", "localhost"])
            if not _is_ip_whitelisted(client_ip, allowed_ips):
                raise HTTPException(status_code=403, detail=f"Unrecognized Agent IP: {client_ip} is not in whitelist")

        if security_config.get("enforce_payload_size", True):
            max_payload_bytes = security_config.get("max_payload_bytes", MAX_INGEST_BODY_BYTES)
            if len(orjson.dumps(original_raw_payload)) > max_payload_bytes:
                raise HTTPException(status_code=413, detail=f"Payload too large: {max_payload_bytes} bytes max")

        redis = request.app.state.redis
        if not redis:
            raise HTTPException(status_code=503, detail="Redis unavailable for ingest queue")

        status_updates = []
        async with redis.pipeline(transaction=True) as pipe:
            for log_data in payload_items:
                log_data.setdefault("timestamp", datetime.now(timezone.utc).isoformat())

                # Ensure tenant/agent identity; strip any signature fields for workers.
                log_data["tenant_id"] = verified_tenant_id
                log_data["agent_id"] = verified_agent_id
                log_data.pop("agent_hmac_signature", None)
                # Do not forward agent signatures into the stream (removed by policy)
                log_data["agent_signature"] = None
                siem_hot_event = _is_siem_hot_event(log_data)
                if siem_hot_event:
                    log_data["siem_hot_enqueued"] = True

                payload_to_stream = {"payload": orjson.dumps(log_data).decode("utf-8")}

                await pipe.xadd(
                    RAW_LOGS_QUEUE,
                    payload_to_stream,
                )
                if siem_hot_event:
                    await pipe.xadd(
                        SIEM_HOT_QUEUE,
                        payload_to_stream,
                    )
                status_updates.append((verified_tenant_id, verified_agent_id))

            await pipe.execute()

        current_utc_timestamp = datetime.now(timezone.utc).isoformat()
        for tenant_id, agent_id in set(status_updates):
            await redis.set(
                f"{STATUS_KEY_PREFIX}:{tenant_id}:{agent_id}",
                current_utc_timestamp,
                ex=STATUS_TTL_SECONDS,
            )

        return ORJSONResponse({
            "status": "success",
            "queued": len(payload_items),
            "rejected": 0,
            "message": f"Successfully queued {len(payload_items)} logs in Redis Stream.",
            "action": "ALLOW",
        })
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Bulk ingestion error: %r", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to queue log batch")

# ---------------------------------------------------------
# 💓 1.5 AGENT HEARTBEAT (DEAD AIR DETECTION)
# ---------------------------------------------------------
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
        cursor = db["siem_cold_vault"].find({"tenant_id": secure_tenant_id}).sort("timestamp", -1).limit(limit)
        logs = await cursor.to_list(length=limit)
        for doc in logs:
            doc["_id"] = str(doc["_id"])
            doc.pop(RAW_RETENTION_ANCHOR_FIELD, None)
        return {"status": "success", "data": logs}
    except Exception as e:
        logger.warning("Agent logs fetch failed: %s", e)
        return {"status": "success", "data": []}

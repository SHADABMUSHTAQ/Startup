import asyncio
from fastapi import APIRouter, HTTPException, Depends, Request, Query
from pydantic import BaseModel, Field, ValidationError, parse_obj_as, validator
from typing import Union, Optional, List
from datetime import datetime, timezone
import json
import redis.asyncio as aioredis
from ipaddress import ip_address, ip_network
from app.config.config import get_settings, load_config

from app.database import get_db
# 🚨 Secures the Dashboard endpoints below
from app.routes.auth import get_current_user, verify_agent_token

router = APIRouter()
settings = get_settings()
RAW_LOGS_QUEUE = "raw_logs_queue"
RAW_LOGS_QUEUE_MAXLEN = 100000
RAW_RETENTION_ANCHOR_FIELD = "_retention_ts"
STATUS_KEY_PREFIX = "status"
STATUS_TTL_SECONDS = 86400

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
    agent_id: str
    source_ip: str
    user: str
    event_id: int
    message: str
    timestamp: str
    raw_data: Union[dict, str] = Field(default_factory=dict)
    processed_data: Optional[dict] = None
    raw_event_data: Optional[Union[dict, str]] = None
    agent_version: str

    @validator("raw_data", pre=True)
    def coerce_raw_data(cls, v):
        if isinstance(v, str):
            return {"raw": v}
        return v

from app.utils.limiter import limiter

# ---------------------------------------------------------
# 📥 1. INGEST WINDOWS AGENT LOGS (BULK REDIS PIPELINE)
# ---------------------------------------------------------
@router.post("/windows")
@limiter.limit("10/second")
async def ingest_pulse_logs(
    payloads: Union[List[dict], dict],
    request: Request,
    verified_tenant_id: str = Depends(verify_agent_token)
):
    try:
        # Enforce API treaty: ingest accepts a list of logs only.
        if isinstance(payloads, dict):
            raise HTTPException(
                status_code=400,
                detail="Contract Violation: Wrap logs in a list [].",
            )

        try:
            payloads = parse_obj_as(List[WindowsAgentPayload], payloads)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=exc.errors()) from exc

        payload_items = [(payload, None) for payload in payloads]

        # 🛡️ IRONCLAD INGESTION: 4-Layer Defense in Depth
        security_config = _get_security_config()

        # 🔐 LAYER 1: IP WHITELIST VALIDATION
        if security_config.get("enforce_ip_whitelist", True):
            client_ip = request.client.host if request.client else "0.0.0.0"
            allowed_ips = security_config.get("allowed_ips", ["127.0.0.1", "localhost"])

            if not _is_ip_whitelisted(client_ip, allowed_ips):
                raise HTTPException(
                    status_code=403,
                    detail=f"Unrecognized Agent IP: {client_ip} is not in whitelist"
                )

        # 🔐 LAYER 2: PAYLOAD SIZE VALIDATION
        if security_config.get("enforce_payload_size", True):
            max_payload_bytes = security_config.get("max_payload_bytes", 1048576)
            content_length = request.headers.get("content-length")

            if content_length:
                try:
                    if int(content_length) > max_payload_bytes:
                        raise HTTPException(
                            status_code=413,
                            detail=f"Payload too large: {content_length} > {max_payload_bytes} bytes"
                        )
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid Content-Length header")

        # 🔐 LAYER 3: TIMESTAMP VALIDATION (Hybrid Skew Guard, live ingest only)
        if security_config.get("enforce_timestamp_validation", True):
            skew_warning_seconds = int(security_config.get("clock_skew_warning_seconds", 300))
            hard_drop_seconds = int(security_config.get("max_log_age_seconds", 86400))
            if hard_drop_seconds <= skew_warning_seconds:
                hard_drop_seconds = skew_warning_seconds + 1

            valid_payloads = []
            for payload, _ in payload_items:
                timestamp = payload.timestamp or datetime.now(timezone.utc).isoformat()
                verdict, delta_seconds = _classify_clock_integrity(
                    timestamp,
                    skew_warning_seconds=skew_warning_seconds,
                    hard_drop_seconds=hard_drop_seconds,
                )

                if verdict == "drop":
                    continue

                time_integrity = None
                if verdict == "skew":
                    time_integrity = {
                        "skewed": True,
                        "skew_seconds": delta_seconds,
                        "reason": "clock_drift",
                    }

                valid_payloads.append((payload, time_integrity))

            payload_items = valid_payloads

        # ✅ MASTER BUILD: Bulk Ingestion Pipeline (7-Tier CTDISR-2025)
        # We use a Redis Pipeline to ensure all logs in the batch are queued in a single network burst.
        redis = request.app.state.redis

        if payload_items:
            status_updates = []
            async with redis.pipeline(transaction=True) as pipe:
                for payload, time_integrity in payload_items:
                    log_data = payload.dict()
                    if not log_data.get("timestamp"):
                        log_data["timestamp"] = datetime.now(timezone.utc).isoformat()

                    tenant_id = verified_tenant_id
                    agent_id = str(payload.agent_id or verified_tenant_id).strip() or verified_tenant_id
                    status_updates.append((tenant_id, agent_id))

                    # 🔐 Enterprise Isolation: Hardcode the verified Tenant ID into every log in the batch
                    log_data["tenant_id"] = verified_tenant_id
                    # Preserve payload-derived agent identity; do not collapse to tenant_id.
                    log_data["agent_id"] = agent_id

                    if time_integrity is not None:
                        log_data["time_integrity"] = time_integrity

                    payload_to_stream = {"payload": json.dumps(log_data, default=str)}

                    # 🛡️ Memory Safety: approximate MAXLEN (~100000) keeps Redis bounded at scale.
                    await pipe.xadd(
                        RAW_LOGS_QUEUE,
                        payload_to_stream,
                        maxlen=RAW_LOGS_QUEUE_MAXLEN,
                        approximate=True,
                    )

                try:
                    result = await pipe.execute()
                    current_utc_timestamp = datetime.now(timezone.utc).isoformat()
                    for tenant_id, agent_id in set(status_updates):
                        asyncio.create_task(
                            redis.set(
                                f"{STATUS_KEY_PREFIX}:{tenant_id}:{agent_id}",
                                current_utc_timestamp,
                                ex=STATUS_TTL_SECONDS,
                            )
                        )
                    print(f"✅ [Redis] Queued {len(payload_items)} logs, pipeline result: {len(result)} commands executed")
                except Exception as e:
                    print(f"❌ [Redis] Pipeline execute failed: {e}")
                    raise
        else:
            print("✅ [Redis] Queued 0 logs, all records filtered by Hybrid Skew Guard")

        return {
            "status": "success",
            "message": f"Successfully queued {len(payload_items)} logs in Redis Stream for 7-Tier processing.",
            "action": "ALLOW"
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Bulk Ingestion Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to queue log batch")

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
        print(f" History Fetch Error: {e}")
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
        print(f" Fetch Agent Logs Error: {e}")
        return {"status": "success", "data": []}

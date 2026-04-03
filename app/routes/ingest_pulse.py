from fastapi import APIRouter, HTTPException, Depends, Request, Query
from pydantic import BaseModel, Field, validator
from typing import Union
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

def _validate_timestamp(timestamp_str: str, max_age_seconds: int) -> bool:
    """Check if timestamp is not older than max_age_seconds."""
    try:
        log_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        age_seconds = (now - log_time).total_seconds()
        return 0 <= age_seconds <= max_age_seconds
    except (ValueError, TypeError):
        # Invalid timestamp format, reject it
        return False


class WindowsAgentPayload(BaseModel):
    agent_id: str
    source_ip: str
    user: str
    event_id: int
    message: str
    timestamp: str
    raw_data: Union[dict, str] = Field(default_factory=dict)
    agent_version: str

    @validator("raw_data", pre=True)
    def coerce_raw_data(cls, v):
        if isinstance(v, str):
            return {"raw": v}
        return v

from typing import List, Union

from app.utils.limiter import limiter

# ---------------------------------------------------------
# 📥 1. INGEST WINDOWS AGENT LOGS (BULK REDIS PIPELINE)
# ---------------------------------------------------------
@router.post("/windows")
@limiter.limit("10/second")
async def ingest_pulse_logs(
    payloads: List[WindowsAgentPayload],
    request: Request,
    verified_tenant_id: str = Depends(verify_agent_token)
):
    try:
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

        # 🔐 LAYER 3: TIMESTAMP VALIDATION (per-log check)
        if security_config.get("enforce_timestamp_validation", True):
            max_log_age_seconds = security_config.get("max_log_age_seconds", 300)

            for idx, payload in enumerate(payloads):
                timestamp = payload.timestamp or datetime.now(timezone.utc).isoformat()

                if not _validate_timestamp(timestamp, max_log_age_seconds):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Log {idx}: Timestamp is too old or invalid (max age: {max_log_age_seconds}s)"
                    )

        # ✅ MASTER BUILD: Bulk Ingestion Pipeline (7-Tier CTDISR-2025)
        # We use a Redis Pipeline to ensure all logs in the batch are queued in a single network burst.
        redis = request.app.state.redis

        async with redis.pipeline(transaction=True) as pipe:
            for payload in payloads:
                log_data = payload.dict()
                if not log_data.get("timestamp"):
                    log_data["timestamp"] = datetime.now(timezone.utc).isoformat()

                # 🔐 Enterprise Isolation: Hardcode the verified Tenant ID into every log in the batch
                log_data["tenant_id"] = verified_tenant_id
                log_data["agent_id"] = verified_tenant_id

                payload_to_stream = {"payload": json.dumps(log_data, default=str)}

                # 🛡️ Memory Safety: maxlen=100000 ensures Redis doesn't OOM if workers lag.
                await pipe.xadd("raw_logs_queue", payload_to_stream, maxlen=100000)

            try:
                result = await pipe.execute()
                print(f"✅ [Redis] Queued {len(payloads)} logs, pipeline result: {len(result)} commands executed")
            except Exception as e:
                print(f"❌ [Redis] Pipeline execute failed: {e}")
                raise

        return {
            "status": "success",
            "message": f"Successfully queued {len(payloads)} logs in Redis Stream for 7-Tier processing.",
            "action": "ALLOW"
        }
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
        print(f"❌ History Fetch Error: {e}")
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
        return {"status": "success", "data": logs}
    except Exception as e:
        print(f"❌ Fetch Agent Logs Error: {e}")
        return {"status": "success", "data": []}
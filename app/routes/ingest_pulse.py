from fastapi import APIRouter, HTTPException, Depends, Request, Query
from pydantic import BaseModel, Field, validator
from typing import Union
from datetime import datetime, timezone
import json
import redis.asyncio as aioredis
from app.config.config import get_settings

from app.database import get_db
# 🚨 Secures the Dashboard endpoints below
from app.routes.auth import get_current_user, verify_agent_token

router = APIRouter()
settings = get_settings()

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

# ---------------------------------------------------------
# 📥 1. INGEST WINDOWS AGENT LOGS (DECOUPLED REDIS PIPELINE)
# ---------------------------------------------------------
@router.post("/windows")
async def ingest_pulse_logs(
    payload: WindowsAgentPayload,
    request: Request,
    verified_tenant_id: str = Depends(verify_agent_token)
):
    try:
        job_data = payload.dict()
        if not job_data.get("timestamp"):
            job_data["timestamp"] = datetime.now(timezone.utc).isoformat()

        # 🔐 Enterprise Isolation: Hardcode the verified Tenant ID into the payload
        job_data["tenant_id"] = verified_tenant_id
        job_data["agent_id"] = verified_tenant_id

        # ✅ Use the global Redis connection pool and cap the queue
        redis = request.app.state.redis
        async with redis.pipeline(transaction=True) as pipe:
            await pipe.rpush("pulse_jobs", json.dumps(job_data))
            await pipe.ltrim("pulse_jobs", -100000, -1)
            await pipe.execute()

        return {
            "status": "success",
            "message": "Log securely queued in Redis for processing",
            "action": "ALLOW"
        }
    except Exception as e:
        print(f"❌ Ingestion Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to queue log")

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
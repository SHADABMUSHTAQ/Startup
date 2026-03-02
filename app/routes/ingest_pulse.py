from fastapi import APIRouter, HTTPException, Depends, Request, Query
from pydantic import BaseModel
from datetime import datetime, timezone
import redis.asyncio as aioredis
import json
from app.config.config import get_settings
from app.database import get_db_context 

# 🚨 Secures the Dashboard endpoints below
from app.routes.auth import get_current_user

router = APIRouter()
settings = get_settings()

class WindowsAgentPayload(BaseModel):
    agent_id: str
    source_ip: str
    user: str
    event_id: int
    message: str
    timestamp: str
    raw_data: str
    agent_version: str

# ---------------------------------------------------------
# 📥 1. INGEST WINDOWS AGENT LOGS (DECOUPLED REDIS PIPELINE)
# ---------------------------------------------------------
@router.post("/windows")
async def ingest_pulse_logs(payload: WindowsAgentPayload, request: Request):
    from app.routes.auth import verify_agent_token
    
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    
    token = auth_header.split(" ")[1]
    
    # Cryptographically verify the token and get the true Tenant ID
    verified_id = await verify_agent_token(token)

    try:
        job_data = payload.dict()
        if not job_data.get("timestamp"):
            job_data["timestamp"] = datetime.now(timezone.utc).isoformat()

        # 🔐 Enterprise Isolation: Hardcode the verified Tenant ID into the payload
        job_data["tenant_id"] = verified_id 
        job_data["agent_id"] = verified_id 

        # Push to Redis Queue (Decoupled Message Broker)
        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
        await redis_client.rpush("pulse_jobs", json.dumps(job_data))
        await redis_client.aclose()
        
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
async def get_alert_history(current_user: dict = Depends(get_current_user)):
    """Securely fetches history, strictly isolated by Tenant ID"""
    secure_tenant_id = current_user.get("tenant_id")
    try:
        async with get_db_context() as database:
            cursor = database.db["security_alerts"].find({"tenant_id": secure_tenant_id}).sort("timestamp", -1).limit(50)
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
    current_user: dict = Depends(get_current_user)
):
    """Securely fetches raw logs, strictly isolated by Tenant ID"""
    secure_tenant_id = current_user.get("tenant_id")
    if not secure_tenant_id:
        raise HTTPException(status_code=403, detail="Critical: User lacks tenant assignment.")

    try:
        async with get_db_context() as database:
            cursor = database.db["logs"].find({"tenant_id": secure_tenant_id}).sort("timestamp", -1).limit(limit)
            logs = await cursor.to_list(length=limit)
            
            for doc in logs:
                doc["_id"] = str(doc["_id"]) 
            return logs
    except Exception as e:
        print(f"❌ Fetch Agent Logs Error: {e}")
        return []
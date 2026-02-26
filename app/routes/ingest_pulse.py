from fastapi import APIRouter, HTTPException, Depends, Request, Query
from pydantic import BaseModel
from datetime import datetime, timezone
import redis.asyncio as aioredis
import json
from app.config.config import get_settings
from app.database import get_db_context 

# 🚨 CTO FIX: Import the user verification so we can secure the dashboard route
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
# 📥 1. INGEST WINDOWS AGENT LOGS
# ---------------------------------------------------------
@router.post("/windows")
async def ingest_pulse_logs(payload: WindowsAgentPayload, request: Request):
    from app.routes.auth import verify_agent_token
    
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    
    token = auth_header.split(" ")[1]
    
    # verify_agent_token is returning a STRING (the tenant_id/agent_id)
    verified_id = await verify_agent_token(token)

    try:
        job_data = payload.dict()
        if not job_data.get("timestamp"):
            job_data["timestamp"] = datetime.now(timezone.utc).isoformat()

        # 🔐 THE STAMP: Assign the string we got to both fields
        job_data["tenant_id"] = verified_id 
        job_data["agent_id"] = verified_id 

        async with aioredis.from_url(settings.redis_url, decode_responses=True) as r:
            await r.rpush("pulse_jobs", json.dumps(job_data))
        
        return {
            "status": "success", 
            "message": "Log queued for detection pipeline",
            "action": "ALLOW"
        }
    except Exception as e:
        print(f"❌ Ingestion Error: {e}") 
        raise HTTPException(status_code=500, detail="Failed to queue log")

# ---------------------------------------------------------
# 📜 2. FETCH MITIGATED ALERTS HISTORY
# ---------------------------------------------------------
@router.get("/alerts/history")
async def get_alert_history():
    """Fetches the last 50 mitigated security alerts for the Dashboard refresh."""
    try:
        async with get_db_context() as db:
            # 🚨 CTO FIX: Restored this to point to the correct 'security_alerts' collection
            cursor = db.db["security_alerts"].find().sort("timestamp", -1).limit(50)
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
    """Securely fetches the raw Windows agent logs for the live dashboard feed."""
    secure_tenant_id = current_user.get("tenant_id")
    if not secure_tenant_id:
        raise HTTPException(status_code=403, detail="Critical: User lacks tenant assignment.")

    try:
        async with get_db_context() as db:
            # 🚨 CTO FIX: Pointing exactly to your "logs" collection and enforcing Tenant Isolation
            cursor = db.db["logs"].find({"tenant_id": secure_tenant_id}).sort("timestamp", -1).limit(limit)
            logs = await cursor.to_list(length=limit)
            
            for doc in logs:
                doc["_id"] = str(doc["_id"]) 
            return logs
    except Exception as e:
        print(f"❌ Fetch Agent Logs Error: {e}")
        return []
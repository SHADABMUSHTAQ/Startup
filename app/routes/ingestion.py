import json
from fastapi import APIRouter, Request, Depends, HTTPException, status
from redis.asyncio import Redis
from app.routes.auth import verify_agent_token

# 🏗️ MASTER BUILD: Ingestion Pipeline
# This router is strictly decoupled and designed for hyper-fast data entry.

router = APIRouter()
RAW_LOGS_QUEUE = "raw_logs_queue"
RAW_LOGS_QUEUE_MAXLEN = 100000

@router.post("/ingest", status_code=status.HTTP_200_OK)
async def ingest_log(
    request: Request,
    tenant_id: str = Depends(verify_agent_token)
):
    """
    MASTER BUILD: Receives a raw JSON log, adds tenant_id, and pushes it to 
    the raw_logs_queue Redis Stream. Returns 200 OK immediately.
    
    NO DATABASE WRITES PERMITTED HERE.
    """
    try:
        # Standard ASCII print for console monitoring
        print(f"[*] Ingesting log for tenant: {tenant_id}")
        
        log_data = await request.json()

        # Enforce Tenant Identity
        log_data["tenant_id"] = tenant_id

        # Wrap for Redis Stream
        payload_to_stream = {"payload": json.dumps(log_data, default=str)}

        # Get the global Redis connection pool from app.state
        redis: Redis = request.app.state.redis
        
        # ⚡ XADD for asynchronous streaming architecture
        # Approximate trimming (~) avoids extra CPU overhead during burst traffic.
        await redis.xadd(
            RAW_LOGS_QUEUE,
            payload_to_stream,
            maxlen=RAW_LOGS_QUEUE_MAXLEN,
            approximate=True,
        )
        
        return {"status": "ok"}
        
    except json.JSONDecodeError:
        print("[!] Ingestion crash: Invalid JSON")
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")
    except Exception as e:
        # Prevent terminal hangs by ensuring fast failure
        print(f"[!] Ingestion error: {str(e)}")
        raise HTTPException(status_code=500, detail="Backbone ingestion failure.")

@router.get("/status")
def get_ingestion_status():
    return {"status": "Ingestion Gateway Online"}

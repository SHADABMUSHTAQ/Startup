import json
from fastapi import APIRouter, Request, Depends, HTTPException, status
from redis.asyncio import Redis
from app.routes.auth import verify_agent_token

# ðŸ—ï¸ MASTER BUILD: Ingestion Pipeline
# This router is strictly decoupled and designed for hyper-fast data entry.

router = APIRouter()
RAW_LOGS_QUEUE = "raw_logs_queue"
RAW_LOGS_QUEUE_MAXLEN = 100000

@router.post("/ingest", status_code=status.HTTP_200_OK)
async def ingest_log(
    request: Request,
    agent_context: dict = Depends(verify_agent_token)
):
    """
    MASTER BUILD: Receives a raw JSON log, adds tenant_id, and pushes it to
    the raw_logs_queue Redis Stream. Returns 200 OK immediately.

    NO DATABASE WRITES PERMITTED HERE.
    """
    try:
        tenant_id = agent_context["tenant_id"]
        # Standard ASCII print for console monitoring
        print(f"[*] Ingesting log for tenant: {tenant_id}")

        log_data = await request.json()

        # Enforce Tenant Identity
        log_data["tenant_id"] = tenant_id
        if "agent_id" in agent_context and "agent_id" not in log_data:
            log_data["agent_id"] = agent_context["agent_id"]

        # Get the global Redis connection pool from app.state
        redis: Redis = request.app.state.redis

        # ðŸ” LAYER 0: TENANT RATE LIMITING (B2B SaaS Protection)
        rate_key = f"warsoc:ratelimit:tenant:{tenant_id}"
        usage = await redis.incr(rate_key)
        if usage == 1:
            await redis.expire(rate_key, 60)

        if usage > 5000:
            print(f"ðŸ›‘ [RATE LIMIT] Tenant {tenant_id} exceeded 5000 logs/min")
            raise HTTPException(status_code=429, detail="Tenant Rate Limit Exceeded (>5000/min).")

        # Wrap for Redis Stream
        payload_to_stream = {"payload": json.dumps(log_data, default=str)}

        # âš¡ XADD for asynchronous streaming architecture
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

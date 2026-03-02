import asyncio
import json
import logging
import redis.asyncio as aioredis
from datetime import datetime, timezone
from app.database import get_db_context, init_db
from app.config.config import get_settings

# Enterprise-grade logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("WarSOC-Worker")

settings = get_settings()

def normalize_log(log_data):
    """Standardizes raw log data for the SIEM database."""
    
    event_id = log_data.get("event_id")
    
    # 🚨 TRIAGE FIX: Auto-level critical Windows events so the React table shows them!
    severity = "INFO"
    if event_id == 1102:
        severity = "CRITICAL" # Log Cleared
    elif event_id == 4625:
        severity = "HIGH"     # Failed Login
    elif event_id == 4672:
        severity = "MEDIUM"   # Special Privileges
        
    return {
        "timestamp": log_data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "source_ip": log_data.get("source_ip", "0.0.0.0"),
        "user": log_data.get("user", "system"),
        "event_id": event_id,
        "message": log_data.get("message", "No message provided"),
        "severity": severity,
        "engine_source": "Agent",
        "raw_data": log_data
    }

async def process_pulse_jobs(redis_client):
    logger.info("⚡ WarSOC Worker: Atomic Pipeline Active and consuming...")
    
    while True:
        try:
            # Atomic pop from Redis with a timeout to allow for loop breaks
            job = await redis_client.blpop("pulse_jobs", timeout=2)
            if not job:
                continue

            logger.info("✅ Job retrieved from Redis queue")
            log_data = json.loads(job[1])
            
            # Multi-tenant identity verification
            tenant_id = log_data.get("tenant_id") or log_data.get("agent_id")
            if not tenant_id:
                logger.warning("⚠️ Dropped log: Missing identity keys (tenant_id)")
                continue

            # Data normalization
            normalized = normalize_log(log_data)
            normalized["tenant_id"] = tenant_id

            # Persistence layer
            async with get_db_context() as db:
                if db.db is not None:
                    try:
                        result = await db.db["logs"].insert_one(normalized)
                        logger.info(f"✅ Log persisted to MongoDB | ID: {result.inserted_id}")
                    except Exception as db_err:
                        logger.error(f"❌ MongoDB Insert Failed: {db_err}")
                else:
                    logger.error("❌ Database manager connection is unavailable")

        except Exception as e:
            logger.error(f"❌ Pipeline Processing Error: {e}")
            await asyncio.sleep(1)

async def main():
    logger.info("🚀 WarSOC SIEM Backbone Starting...")
    
    # Initialize global database connection
    await init_db()
    
    # Initialize background detection tasks (Non-blocking)
    # asyncio.create_task(stateful_engine.start(settings.redis_url))
    # logger.info("🔄 Stateful Detection Engine running in background task")
    
    # Initialize Redis connection
    redis_client = await aioredis.from_url(settings.redis_url, decode_responses=True)
    
    try:
        await process_pulse_jobs(redis_client)
    except asyncio.CancelledError:
        logger.info("🛑 Worker shutdown signal received")
    finally:
        await redis_client.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
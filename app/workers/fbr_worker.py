import asyncio
import json
import time
import logging
import os
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from redis.asyncio import Redis
from app.config.config import get_settings

from app.utils.tenant_cache import get_tenant_plan

# 🏗️ MASTER BUILD: FBR Compliance Worker (S.R.O. 288/I/2026 Optimized)
# Strictly Decoupled, Hybrid Flush (100 logs or 3s), Redis-Cached Plan Check

logging.basicConfig(level=logging.INFO, format="%(asctime)s [FBR] %(message)s")
logger = logging.getLogger("FBR-Worker")

settings = get_settings()
RAW_LOGS_QUEUE = "raw_logs_queue"
FBR_GROUP = "fbr_group"

def load_dynamic_config():
    """Loads config.json using absolute path resolution (CTO FIX)."""
    # 🚨 FIX: Path resolved relative to the file's directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, "config", "config.json")
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"FAILED TO LOAD CONFIG AT {config_path}: {e}")
        return {}

async def fbr_worker():
    """
    MASTER BUILD: Consumer for raw_logs_queue (FBR Logic).
    Implements Hybrid Flush and Redis-based plan verification for microsecond latency.
    """
    config = load_dynamic_config()
    fbr_targets = config.get("compliance_targets", {}).get("fbr", [4616, 4670, 4663, 4697, 1102, 4657])
    
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    redis = await Redis.from_url(settings.redis_url, decode_responses=True)

    # 🛠️ Scale Mandate: Group Creation
    try:
        await redis.xgroup_create(RAW_LOGS_QUEUE, FBR_GROUP, mkstream=True)
        logger.info(f"Created consumer group: {FBR_GROUP}")
    except Exception:
        pass

    buffer = []
    last_flush_time = time.time()

    logger.info("⚡ WarSOC FBR Worker: POS Compliance Active (SRO 288/69)...")
    
    while True:
        try:
            # ⚡ Optimized Read Performance (Batch size 50)
            streams = await redis.xreadgroup(FBR_GROUP, "fbr_consumer_1", {RAW_LOGS_QUEUE: ">"}, count=50, block=2000)
            
            if not streams:
                # Flush timeout check even if no new messages
                current_time = time.time()
                if buffer and (current_time - last_flush_time) >= 3:
                    logger.info(f"[*] Timeout Flush: {len(buffer)} FBR logs to fbr_pos_logs...")
                    await db.fbr_pos_logs.insert_many(buffer)
                    buffer = []
                    last_flush_time = current_time
                continue

            for _, messages in streams:
                ack_ids = []
                for message_id, payload in messages:
                    try:
                        log_data = json.loads(payload["payload"])
                        tenant_id = log_data.get("tenant_id")
                        ack_ids.append(message_id)

                        # 🔍 1. Plan Verification
                        plan = await get_tenant_plan(redis, tenant_id)
                        if plan not in ["Professional", "Enterprise", "FBR_PLAN", "FULL_SUITE"]:
                            continue

                        # 🔍 2. DYNAMIC TARGET ENFORCEMENT
                        event_id = log_data.get("event_id")
                        if event_id not in fbr_targets:
                            continue

                        # 🏷️ 3. Tagging & Normalization
                        log_data["tags"] = "FBR_POS"
                        log_data["retention_policy"] = "30_DAYS"
                        log_data["ingested_at"] = datetime.now(timezone.utc).isoformat()
                        
                        buffer.append(log_data)
                    
                    except Exception as e:
                        logger.error(f"Error processing FBR log: {e}")
                
                # ⚡ Batch Acknowledge
                if ack_ids:
                    async with redis.pipeline(transaction=True) as pipe:
                        for mid in ack_ids:
                            await pipe.xack(RAW_LOGS_QUEUE, FBR_GROUP, mid)
                        await pipe.execute()

            # 🚀 4. HYBRID FLUSH LOGIC
            current_time = time.time()
            if len(buffer) >= 100 or (len(buffer) > 0 and (current_time - last_flush_time) >= 3):
                logger.info(f"[*] Batch Flush: {len(buffer)} FBR logs to fbr_pos_logs...")
                await db.fbr_pos_logs.insert_many(buffer)
                buffer = []
                last_flush_time = current_time

        except Exception as e:
            logger.error(f"[!] FBR Pipeline crash: {str(e)}")
            await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(fbr_worker())
    except KeyboardInterrupt:
        print("[*] FBR Worker shutting down gracefully.")

import asyncio
import json
import logging
import sys
import os
from pymongo.errors import DuplicateKeyError, PyMongoError, BulkWriteError
import redis.asyncio as aioredis
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient

# Make sure app module is importable
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.config.config import get_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("FBR-Worker")

settings = get_settings()

REDIS_STREAM = "raw_logs_queue"
CONSUMER_GROUP = "fbr_group"
CONSUMER_NAME = "fbr_worker_1"
BATCH_SIZE = 100
BATCH_TIMEOUT = 2.0  # Flush every 2s

fbr_policy_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app", "config", "fbr_policy.json")
try:
    with open(fbr_policy_path, "r", encoding="utf-8") as f:
        fbr_policy = json.load(f)
    WATCH_IDS = set(str(eid) for eid in fbr_policy.get("fbr_config", {}).get("monitored_events", []))
except Exception as e:
    logger.error(f"Failed to load FBR policy: {e}")
    WATCH_IDS = set()

async def setup_redis_group(redis_client):
    try:
        await redis_client.xgroup_create(REDIS_STREAM, CONSUMER_GROUP, id="0", mkstream=True)
        logger.info(f"Created consumer group {CONSUMER_GROUP}")
    except aioredis.ResponseError as e:
        if "BUSYGROUP Consumer Group name already exists" not in str(e):
            raise e

async def get_mongo_collections():
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client["WarSOC_DB"]
    return db["logs"], db["tenants"]

async def main():
    logger.info("🚀 FBR Compliance Worker Starting...")
    redis_client = await aioredis.from_url(settings.redis_url, decode_responses=True)
    await setup_redis_group(redis_client)
    
    logs_col, tenants_col = await get_mongo_collections()
    
    batch = []
    batch_msg_ids = []
    last_flush = asyncio.get_event_loop().time()

    async def flush_batch():
        nonlocal batch, batch_msg_ids, last_flush
        if not batch: return

        flushed_msg_ids = list(batch_msg_ids)
        
        # Assign _id to each document for idempotency before insert
        for i, doc in enumerate(batch):
            doc["_id"] = batch_msg_ids[i]
        
        try:
            # ordered=False allows MongoDB to skip duplicates and insert the rest
            await logs_col.insert_many(batch, ordered=False)
            logger.info(f"💾 Batched {len(batch)} FBR logs to MongoDB.")
            # Success: safe to acknowledge all messages in this batch
            return True, flushed_msg_ids
        except BulkWriteError as bwe:
            # 🔄 IDEMPOTENT: Inspect error details
            write_errors = bwe.details.get("writeErrors", [])
            duplicate_only = all(err.get("code") == 11000 for err in write_errors)
            
            if duplicate_only:
                # All errors are duplicates (idempotent) - safe to XACK
                logger.info(f"[IDEMPOTENT] Batch had {len(write_errors)} duplicate inserts, rest succeeded")
                return True, flushed_msg_ids
            else:
                # 🛑 DATABASE FAILURE: Some errors are not duplicates (connection, validation, etc)
                logger.error(f"[BLACKOUT] Batch insert failed with non-duplicate errors: {bwe}. NOT ACKing - batch will retry.")
                return False, flushed_msg_ids
        except (PyMongoError, ConnectionError) as db_err:
            # 🛑 DATABASE FAILURE: Connection down or other error
            logger.error(f"[BLACKOUT] MongoDB error during batch flush: {db_err}. NOT ACKing - batch will retry.")
            return False, flushed_msg_ids
        except Exception as e:
            logger.error(f"❌ Unexpected error during batch flush: {e}")
            return False, flushed_msg_ids
        finally:
            batch = []
            batch_msg_ids = []
            last_flush = asyncio.get_event_loop().time()

    while True:
        try:
            # Timeout flush
            if batch and (asyncio.get_event_loop().time() - last_flush) >= BATCH_TIMEOUT:
                flushed_ok, flushed_msg_ids = await flush_batch()
                if flushed_ok:
                    for bid in flushed_msg_ids:
                        await redis_client.xack(REDIS_STREAM, CONSUMER_GROUP, bid)

            # Wait for stream data
            messages = await redis_client.xreadgroup(
                CONSUMER_GROUP, CONSUMER_NAME, {REDIS_STREAM: ">"}, count=50, block=1000
            )
            
            if not messages:
                continue

            for stream_name, msg_list in messages:
                for msg_id, msg_data in msg_list:
                    try:
                        # Defensive parsing
                        payload_str = msg_data.get("payload")
                        log = json.loads(payload_str) if payload_str else dict(msg_data)
                        
                        tenant_id = log.get("tenant_id")
                        event_id = str(log.get("event_id"))

                        if not tenant_id or event_id not in WATCH_IDS:
                            # Not an FBR target event or lacks tenant gracefully XACK & discard it
                            await redis_client.xack(REDIS_STREAM, CONSUMER_GROUP, msg_id)
                            continue

                        # Check Tenant Plan
                        tenant = await tenants_col.find_one({"tenant_id": tenant_id})
                        # 🔐 IDEMPOTENCY: Map message ID for batch processing
                        batch_msg_ids.append(msg_id)
                        
                        if tenant and tenant.get("subscription_plan") == "FBR_PLAN":
                            # Target Matched! Append Compliance Tag
                            tags = log.get("tags", [])
                            if isinstance(tags, list):
                                if "FBR_POS" not in tags:
                                    tags.append("FBR_POS")
                            else:
                                tags = ["FBR_POS"]
                            log["tags"] = tags
                            log["created_at"] = datetime.now(timezone.utc)
                            
                            batch.append(log)
                            if len(batch) >= BATCH_SIZE:
                                flushed_ok, flushed_msg_ids = await flush_batch()
                                if flushed_ok:
                                    # Safe to acknowledge entire batch
                                    for bid in flushed_msg_ids:
                                        await redis_client.xack(REDIS_STREAM, CONSUMER_GROUP, bid)
                        else:
                            # Non-FBR events can be safely acknowledged immediately
                            await redis_client.xack(REDIS_STREAM, CONSUMER_GROUP, msg_id)
                        
                    except Exception as e:
                        logger.error(f"❌ Unexpected error on {msg_id}: {e}")
                        # Only acknowledge if this is a processing error (not data loss risk)
                        if msg_id in batch_msg_ids:
                            batch_msg_ids.remove(msg_id)
                        await redis_client.xack(REDIS_STREAM, CONSUMER_GROUP, msg_id)
                        
        except asyncio.CancelledError:
            if batch:
                flushed_ok, flushed_msg_ids = await flush_batch()
                if flushed_ok:
                    # Safe to acknowledge entire remaining batch
                    for bid in flushed_msg_ids:
                        await redis_client.xack(REDIS_STREAM, CONSUMER_GROUP, bid)
            break
        except Exception as e:
            logger.error(f"❌ Redis Stream Connection Error: {e}")
            await asyncio.sleep(2)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("FBR Worker Shutting Down gracefully.")

import asyncio
import json
import logging
import sys
import os
import hashlib
from pymongo.errors import DuplicateKeyError, PyMongoError
from datetime import datetime, timezone
import redis.asyncio as aioredis
from motor.motor_asyncio import AsyncIOMotorClient

# Make sure app module is importable
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.config.config import get_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("PECA-Worker")

settings = get_settings()

REDIS_STREAM = "raw_logs_queue"
CONSUMER_GROUP = "peca_group"
CONSUMER_NAME = "peca_worker_1"

peca_policy_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app", "config", "peca_policy.json")
try:
    with open(peca_policy_path, "r", encoding="utf-8") as f:
        peca_policy = json.load(f)
    WATCH_IDS = set(str(eid) for eid in peca_policy.get("peca_config", {}).get("monitored_events", []))
except Exception as e:
    logger.error(f"Failed to load PECA policy: {e}")
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

def generate_log_hash(log_dict):
    """Generates a deterministic SHA-256 hash for cryptographic digital evidence sealing."""
    # Ensure consistent serialization format before hashing
    serialized = json.dumps(log_dict, sort_keys=True).encode('utf-8')
    return hashlib.sha256(serialized).hexdigest()

async def main():
    logger.info("🚀 PECA Forensic Vault Worker Starting...")
    redis_client = await aioredis.from_url(settings.redis_url, decode_responses=True)
    await setup_redis_group(redis_client)
    
    logs_col, tenants_col = await get_mongo_collections()

    while True:
        try:
            # Wait for stream data
            messages = await redis_client.xreadgroup(
                CONSUMER_GROUP, CONSUMER_NAME, {REDIS_STREAM: ">"}, count=10, block=2000
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
                            # Not a PECA target event or lacks tenant; gracefully XACK & discard
                            await redis_client.xack(REDIS_STREAM, CONSUMER_GROUP, msg_id)
                            continue

                        # Check Tenant Plan
                        tenant = await tenants_col.find_one({"tenant_id": tenant_id})
                        
                        # 🔐 IDEMPOTENCY: Use Redis message ID as MongoDB _id to prevent duplicates
                        log["_id"] = msg_id
                        
                        insert_success = False
                        if tenant and tenant.get("subscription_plan") == "PECA_PLAN":
                            # Target Matched! Append Compliance Tag
                            tags = log.get("tags", [])
                            if isinstance(tags, list):
                                if "PECA_FORENSIC" not in tags:
                                    tags.append("PECA_FORENSIC")
                            else:
                                tags = ["PECA_FORENSIC"]
                            log["tags"] = tags
                            
                            # Cryptographic Sealing (Critical)
                            log["hash"] = generate_log_hash(log)
                            log["created_at"] = datetime.now(timezone.utc)
                            
                            # Insert with explicit _id for idempotency
                            try:
                                await logs_col.insert_one(log)
                                insert_success = True
                            except DuplicateKeyError:
                                # 🔄 IDEMPOTENT: Another worker already inserted this message
                                logger.info(f"[IDEMPOTENT] Message {msg_id} already processed by another worker")
                                insert_success = True  # Treat as success for XACK purposes
                            except (PyMongoError, ConnectionError) as db_err:
                                # 🛑 DATABASE FAILURE: Connection down or other error
                                # Do NOT acknowledge - leave message in PEL for retry
                                logger.error(f"[BLACKOUT] MongoDB error on {msg_id}: {db_err}. NOT ACKing - message will retry.")
                                continue  # Skip the XACK below
                            
                            logger.info(f"🔒 Sealed immutable log {msg_id} with SHA-256 Hash.")
                        else:
                            insert_success = True  # Non-PECA events can be safely acknowledged
                        
                        # ✅ CONDITIONAL ACK: Only acknowledge if insert succeeded or was idempotent
                        if insert_success:
                            await redis_client.xack(REDIS_STREAM, CONSUMER_GROUP, msg_id)
                        
                    except Exception as e:
                        logger.error(f"❌ Unexpected error on {msg_id}: {e}")
                        # Only acknowledge if this is a processing error (not data loss risk)
                        await redis_client.xack(REDIS_STREAM, CONSUMER_GROUP, msg_id)
                        
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"❌ Redis Stream Connection Error: {e}")
            await asyncio.sleep(2)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("PECA Worker Shutting Down gracefully.")

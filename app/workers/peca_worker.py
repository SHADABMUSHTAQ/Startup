import asyncio
import json
import hashlib
import logging
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from redis.asyncio import Redis
from app.config.config import get_settings

from app.utils.tenant_cache import get_tenant_plan

import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# 🏗️ MASTER BUILD: PECA Compliance Worker (PECA 2016 Section 46)
# Strictly Decoupled, RSA-2048 Digital Signing, Senior Architect Hardened

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PECA] %(message)s")
logger = logging.getLogger("PECA-Worker")

settings = get_settings()
RAW_LOGS_QUEUE = "raw_logs_queue"
PECA_GROUP = "peca_group"
SIGNER_ID = "WarSOC-PK-2026-v1" # Standardized key version for rotation control

def load_dynamic_config():
    """Loads config.json using absolute path resolution (CTO FIX)."""
    import os
    # 🚨 FIX: Path resolved relative to the file's directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, "config", "config.json")
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"FAILED TO LOAD CONFIG AT {config_path}: {e}")
        return {}

async def peca_worker():
    """
    MASTER BUILD: Consumer for raw_logs_queue (PECA Logic).
    Implements RSA-2048 digital signatures to ensure non-repudiation (PECA Section 46).
    """
    config = load_dynamic_config()
    peca_targets = config.get("compliance_targets", {}).get("peca", [4624, 4625, 4688, 4720, 4732, 4698, 1102, 4719])
    
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    redis = await Redis.from_url(settings.redis_url, decode_responses=True)

    # 🔐 Load RSA Private Key for Signing (MANDATORY for Non-Repudiation)
    try:
        with open("keys/private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        logger.info(f"Loaded RSA Private Key: {SIGNER_ID}")
    except Exception as e:
        logger.critical(f"FAILED TO LOAD SIGNING KEY: {e}. Worker non-compliant.")
        return

    # 🛠️ Scale Mandate: Group Creation
    try:
        await redis.xgroup_create(RAW_LOGS_QUEUE, PECA_GROUP, mkstream=True)
        logger.info(f"Created consumer group: {PECA_GROUP}")
    except Exception:
        pass

    logger.info("⚡ WarSOC PECA Worker: Non-Repudiable Evidence Active (Section 46)...")
    
    while True:
        try:
            # ⚡ Optimized Read Performance: Fetch forensic batch
            streams = await redis.xreadgroup(PECA_GROUP, "peca_consumer_1", {RAW_LOGS_QUEUE: ">"}, count=50, block=2000)
            
            if not streams:
                continue

            for _, messages in streams:
                forensic_batch = []
                ack_ids = []

                for message_id, payload in messages:
                    try:
                        log_data = json.loads(payload["payload"])
                        tenant_id = log_data.get("tenant_id")
                        ack_ids.append(message_id)

                        # 🔍 1. Plan Verification
                        plan = await get_tenant_plan(redis, tenant_id)
                        if plan not in ["Professional", "Enterprise"]:
                            continue

                        # 🔍 2. DYNAMIC TARGET ENFORCEMENT
                        event_id = log_data.get("event_id")
                        if event_id not in peca_targets:
                            continue

                        # 🏷️ 3. Tagging & RSA Signing
                        log_data["tags"] = "PECA_FORENSIC"
                        log_data["retention_policy"] = "365_DAYS"
                        log_data["ingested_at"] = datetime.now(timezone.utc).isoformat()
                        log_data["signer_id"] = SIGNER_ID
                        
                        payload_for_signing = json.dumps(log_data, default=str, sort_keys=True)
                        log_data["forensic_seal"] = hashlib.sha256(payload_for_signing.encode()).hexdigest()
                        
                        signature = private_key.sign(
                            payload_for_signing.encode(),
                            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                            hashes.SHA256()
                        )
                        log_data["digital_signature"] = base64.b64encode(signature).decode("utf-8")
                        
                        forensic_batch.append(log_data)
                    
                    except Exception as e:
                        logger.error(f"Error signing forensic log: {e}")

                # 📥 4. BULK VAULT PERSISTENCE
                if forensic_batch:
                    await db.peca_forensic_logs.insert_many(forensic_batch)
                    logger.info(f"[*] PECA Signed and Vaulted {len(forensic_batch)} evidence logs.")
                
                # ⚡ Batch Acknowledge
                if ack_ids:
                    async with redis.pipeline(transaction=True) as pipe:
                        for mid in ack_ids:
                            await pipe.xack(RAW_LOGS_QUEUE, PECA_GROUP, mid)
                        await pipe.execute()

        except Exception as e:
            logger.error(f"[!] PECA Pipeline crash: {str(e)}")
            await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(peca_worker())
    except KeyboardInterrupt:
        print("[*] PECA Worker shutting down gracefully.")

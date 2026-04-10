import asyncio
import json
import time
import logging
import os
import sys
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from redis import exceptions as redis_exceptions
from redis.asyncio import Redis
from app.config.config import get_settings

from app.utils.tenant_cache import get_tenant_plan

import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# 🏗️ MASTER BUILD: FBR Compliance Worker (S.R.O. 288/I/2026 Optimized)
# Strictly Decoupled, Hybrid Flush (100 logs or 3s), Redis-Cached Plan Check
# Hardened: Cryptographic Non-Repudiation (SHA-256 + RSA-2048)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [FBR] %(message)s")
logger = logging.getLogger("FBR-Worker")

settings = get_settings()
RAW_LOGS_QUEUE = "raw_logs_queue"
FBR_GROUP = "fbr_group"
FBR_CONSUMER = "fbr_consumer_1"
RECLAIM_MIN_IDLE_MS = 60000
RECLAIM_BATCH_SIZE = 50

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


def _normalize_timestamp_iso_utc(value) -> str:
    """Coerce timestamp-like values to timezone-aware UTC ISO 8601 strings."""
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()

    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()

    return datetime.now(timezone.utc).isoformat()


def _normalize_document_timestamps(document: dict):
    document["timestamp"] = _normalize_timestamp_iso_utc(document.get("timestamp"))
    if "ingested_at" in document:
        document["ingested_at"] = _normalize_timestamp_iso_utc(document.get("ingested_at"))
    return document


async def reclaim_stale_messages(redis_client: Redis):
    """Best-effort reclaim for stale pending stream entries."""
    try:
        pending_entries = await redis_client.xpending_range(
            RAW_LOGS_QUEUE,
            FBR_GROUP,
            "-",
            "+",
            RECLAIM_BATCH_SIZE,
            idle=RECLAIM_MIN_IDLE_MS,
        )
        if not pending_entries:
            return []

        stale_ids = []
        for entry in pending_entries:
            if not entry:
                continue
            if isinstance(entry, dict):
                message_id = entry.get("message_id")
            else:
                message_id = entry[0]
            if isinstance(message_id, bytes):
                message_id = message_id.decode()
            if message_id:
                stale_ids.append(message_id)

        if not stale_ids:
            return []

        reclaimed = await redis_client.xclaim(
            RAW_LOGS_QUEUE,
            FBR_GROUP,
            FBR_CONSUMER,
            RECLAIM_MIN_IDLE_MS,
            stale_ids,
        )
        if reclaimed:
            logger.info(f"[XCLAIM] Reclaimed {len(reclaimed)} stale FBR message(s).")
        return reclaimed or []

    except redis_exceptions.ResponseError as e:
        logger.warning(f"[XCLAIM] FBR reclaim skipped safely: {e}")
        return []
    except Exception as e:
        logger.error(f"[XCLAIM] FBR reclaim error (non-fatal): {e}")
        return []

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

    # 🔐 Load RSA Private Key for Signing (MANDATORY for Non-Repudiation)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    repo_root = os.path.dirname(base_dir)
    private_key_path = os.path.join(repo_root, "keys", "private_key.pem")
    
    if not os.path.exists(private_key_path):
        logger.critical(f"FBR non-compliant: signing key missing at {private_key_path}. Worker cannot start.")
        sys.exit(1)

    try:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        logger.info(f"Loaded RSA Private Key for FBR Signing")
    except Exception as e:
        logger.critical(f"FAILED TO LOAD SIGNING KEY: {e}. FBR Worker non-compliant.")
        sys.exit(1)

    # 🛠️ Scale Mandate: Group Creation (Enterprise Lazy Init)
    while True:
        try:
            await redis.xgroup_create(RAW_LOGS_QUEUE, FBR_GROUP, mkstream=True)
            logger.info(f"✅ Created consumer group: {FBR_GROUP} on {RAW_LOGS_QUEUE}")
            break
        except redis_exceptions.ResponseError as e:
            if "BUSYGROUP" in str(e):
                logger.info(f"[*] Consumer group {FBR_GROUP} already exists. Resuming...")
                break
            logger.error(f"[!] Group Creation Error: {e}. Retrying...")
            await asyncio.sleep(2)
        except redis_exceptions.ConnectionError as e:
            logger.warning(f"[!] Redis connection error during group creation: {e}. Retrying in 2s...")
            await asyncio.sleep(2)
        except Exception as e:
            logger.error(f"[!] Unexpected error during group creation: {e}. Retrying in 2s...")
            await asyncio.sleep(2)

    last_config_load = 0
    fbr_targets = set()
    buffer = []
    buffer_ack_ids = []
    last_flush_time = time.time()

    logger.info("⚡ WarSOC FBR Worker: POS Compliance Active (SRO 288/69)...")
    
    while True:
        try:
            # 🔄 HOT-RELOAD: Sync Compliance Policy every 60 seconds (BUG-24 FIX)
            if time.time() - last_config_load > 60:
                config = load_dynamic_config()
                event_map = config.get("event_id_map", {})
                
                # Derive targets STRICTLY from SSOT tags
                new_targets = set()
                for eid_str, meta in event_map.items():
                    if "fbr" in [str(t).lower() for t in meta.get("compliance_tags", [])]:
                        try:
                            new_targets.add(int(eid_str))
                        except ValueError: continue
                
                # Fallback to the dedicated list if tags are missing (Legacy Support)
                if not new_targets:
                    new_targets = set(config.get("compliance_targets", {}).get("fbr", []))
                
                fbr_targets = new_targets
                last_config_load = time.time()
                logger.info(f"[*] FBR Policy Synced: Monitoring {len(fbr_targets)} Event IDs.")

            # ⚡ Optimized Read Performance (Batch size 50)
            streams = await redis.xreadgroup(FBR_GROUP, FBR_CONSUMER, {RAW_LOGS_QUEUE: ">"}, count=50, block=2000)
            
            if not streams:
                reclaimed_messages = await reclaim_stale_messages(redis)
                if reclaimed_messages:
                    streams = [(RAW_LOGS_QUEUE, reclaimed_messages)]
                else:
                    # Flush timeout check even if no new messages
                    current_time = time.time()
                    if buffer and (current_time - last_flush_time) >= 3:
                        logger.info(f"[*] Timeout Flush: {len(buffer)} FBR logs to fbr_pos_logs...")
                        flush_batch = [_normalize_document_timestamps(item) for item in buffer]
                        try:
                            await db.fbr_pos_logs.insert_many(flush_batch)
                        except Exception as e:
                            logger.error(f"[!] FBR flush failed (timeout path): {e}")
                        else:
                            if buffer_ack_ids:
                                async with redis.pipeline(transaction=True) as pipe:
                                    for mid in buffer_ack_ids:
                                        await pipe.xack(RAW_LOGS_QUEUE, FBR_GROUP, mid)
                                    await pipe.execute()
                            buffer = []
                            buffer_ack_ids = []
                            last_flush_time = current_time
                    continue

            for _, messages in streams:
                if not messages:
                    continue

                immediate_ack_ids = []
                for message_id, payload in messages:
                    try:
                        # BUG-STABILIZE: Handle malformed JSON Poison Pills
                        raw_payload = payload.get("payload", "")
                        if not raw_payload:
                            logger.warning(f"Skipping empty FBR payload {message_id}")
                            immediate_ack_ids.append(message_id)
                            continue

                        try:
                            log_data = json.loads(raw_payload)
                        except json.JSONDecodeError:
                            # Best effort cleanup for Python-style stringified dicts
                            try:
                                sanitized = raw_payload.replace("'", '"')
                                log_data = json.loads(sanitized)
                                logger.info(f"[*] Sanitized malformed FBR JSON: {message_id}")
                            except Exception:
                                logger.error(f"[POISON PILL] Permanent JSON parse failure for FBR message {message_id}. Discarding.")
                                immediate_ack_ids.append(message_id) # Acknowledge so it's removed from Redis
                                continue
                        
                        tenant_id = log_data.get("tenant_id")

                        # 🔍 1. Plan Verification
                        plan = await get_tenant_plan(redis, tenant_id)
                        if plan not in ["Professional", "Enterprise", "FBR_PLAN", "FULL_SUITE"]:
                            immediate_ack_ids.append(message_id)
                            continue

                        # 🔍 2. DYNAMIC TARGET ENFORCEMENT
                        event_id = log_data.get("event_id")
                        if event_id not in fbr_targets:
                            immediate_ack_ids.append(message_id)
                            continue

                        # 🏷️ 4. Tagging, Hashing & RSA Signing
                        log_data["tags"] = "FBR_POS"
                        log_data["retention_policy"] = "30_DAYS"
                        log_data["ingested_at"] = datetime.now(timezone.utc).isoformat()
                        log_data["_retention_ts"] = datetime.now(timezone.utc)
                        log_data["signer_id"] = "WarSOC-FBR-v1"
                        _normalize_document_timestamps(log_data)
                        
                        # Generate Forensic Hash and Digital Signature
                        payload_for_signing = json.dumps(log_data, default=str, sort_keys=True)
                        log_data["forensic_seal"] = hashlib.sha256(payload_for_signing.encode()).hexdigest()
                        
                        signature = private_key.sign(
                            payload_for_signing.encode(),
                            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                            hashes.SHA256()
                        )
                        log_data["digital_signature"] = base64.b64encode(signature).decode("utf-8")
                        
                        buffer.append(log_data)
                        buffer_ack_ids.append(message_id)
                    
                    except Exception as e:
                        logger.error(f"Error processing FBR log: {e}")
                        # Do not ack this message on processing failure.
                        continue
                
                # Ack intentionally skipped/malformed records immediately.
                if immediate_ack_ids:
                    async with redis.pipeline(transaction=True) as pipe:
                        for mid in immediate_ack_ids:
                            await pipe.xack(RAW_LOGS_QUEUE, FBR_GROUP, mid)
                        await pipe.execute()

            # 🚀 4. HYBRID FLUSH LOGIC
            current_time = time.time()
            if len(buffer) >= 100 or (len(buffer) > 0 and (current_time - last_flush_time) >= 3):
                logger.info(f"[*] Batch Flush: {len(buffer)} FBR logs to fbr_pos_logs...")
                flush_batch = [_normalize_document_timestamps(item) for item in buffer]
                try:
                    await db.fbr_pos_logs.insert_many(flush_batch)
                except Exception as e:
                    logger.error(f"[!] FBR flush failed: {e}")
                else:
                    if buffer_ack_ids:
                        async with redis.pipeline(transaction=True) as pipe:
                            for mid in buffer_ack_ids:
                                await pipe.xack(RAW_LOGS_QUEUE, FBR_GROUP, mid)
                            await pipe.execute()
                    buffer = []
                    buffer_ack_ids = []
                    last_flush_time = current_time

        except Exception as e:
            error_msg = str(e)
            if "NOGROUP" in error_msg:
                try:
                    await redis.xgroup_create(RAW_LOGS_QUEUE, FBR_GROUP, mkstream=True)
                    logger.info("[FBR-COMPLIANCE] Auto-Healed NOGROUP missing stream.")
                except Exception:
                    pass
            else:
                logger.error(f"[FBR-COMPLIANCE] Pipeline Exception: {e}")
            await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(fbr_worker())
    except KeyboardInterrupt:
        logger.info("WarSOC FBR Worker offline.")
    except KeyboardInterrupt:
        print("[*] FBR Worker shutting down gracefully.")

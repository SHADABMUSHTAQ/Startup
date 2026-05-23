import asyncio
import json
import time
import logging
import os
import sys
import copy
import traceback
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from redis import exceptions as redis_exceptions
from redis.asyncio import Redis
from app.config.config import get_settings
from app.utils.observability import increment_redis_counter
from app.utils.crypto_executor import get_crypto_executor, shutdown_crypto_executor, _sign_canonical_bytes

from app.utils.tenant_cache import get_tenant_plan
from app.utils.rate_limiter import incr_count, set_flag, get_flag

import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
import copy
import socket
from pymongo import UpdateOne
import uuid

try:
    from canonicaljson import encode_canonical_json
    CANONICALJSON_AVAILABLE = True
except Exception:
    CANONICALJSON_AVAILABLE = False

# 🏗️ MASTER BUILD: FBR Compliance Worker (S.R.O. 288/I/2026 Optimized)
# Strictly Decoupled, Hybrid Flush (100 logs or 3s), Redis-Cached Plan Check
# Hardened: Cryptographic Non-Repudiation (SHA-256 + RSA-2048)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [FBR] %(message)s")
logger = logging.getLogger("FBR-Worker")

settings = get_settings()
RAW_LOGS_QUEUE = "raw_logs_queue"
FBR_GROUP = "fbr_group"
FBR_CONSUMER = os.environ.get("CONSUMER_NAME", f"fbr_consumer_{socket.gethostname()}")
RECLAIM_MIN_IDLE_MS = 60000
RECLAIM_BATCH_SIZE = 50
DEFAULT_TENANT_ID = os.getenv("TENANT_ID", "WARSOC_DEFAULT")
DLQ_QUEUE_PREFIX = "warsoc:dlq:"

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


def _normalize_timestamp_iso_utc(value) -> datetime:
    """Coerce timestamp-like values to timezone-aware UTC datetime objects for MongoDB BSON."""
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    return datetime.now(timezone.utc)


def _normalize_document_timestamps(document: dict):
    document["timestamp"] = _normalize_timestamp_iso_utc(document.get("timestamp"))
    if "ingested_at" in document:
        document["ingested_at"] = _normalize_timestamp_iso_utc(document.get("ingested_at"))
    # Keep _retention_ts as datetime for Mongo TTL indexes; canonicalization will convert a copy when signing.
    return document


def _to_canonical_bytes(obj) -> bytes:
    o = copy.deepcopy(obj)

    def _convert(value):
        if isinstance(value, dict):
            for k, v in list(value.items()):
                if isinstance(v, datetime):
                    value[k] = v.astimezone(timezone.utc).isoformat()
                else:
                    _convert(v)
        elif isinstance(value, list):
            for i in range(len(value)):
                v = value[i]
                if isinstance(v, datetime):
                    value[i] = v.astimezone(timezone.utc).isoformat()
                else:
                    _convert(v)

    _convert(o)

    if CANONICALJSON_AVAILABLE:
        try:
            return encode_canonical_json(o)
        except Exception as e:
            logger.error(f"FBR Canonical encoding failed: {e}")
    
    # Fallback to high-entropy deterministic JSON (Non-Compliant)
    logger.warning("FBR Worker: Using fallback deterministic JSON (Non-Compliant)")
    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


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

# NOTE: throttle/rollup logic reverted to inline handling to restore original
# pre-refactor behavior. This avoids the separate test-only helper function.

async def fbr_worker():
    """
    MASTER BUILD: Consumer for raw_logs_queue (FBR Logic).
    Implements Hybrid Flush and Redis-based plan verification for microsecond latency.
    """
    config = load_dynamic_config()
    
    # 🛡️ THE SSOT: Load monitoring targets from FBR framework in Master Config
    frameworks = config.get("compliance_frameworks", {})
    fbr_config = frameworks.get("fbr_pos", {})
    fbr_rules = fbr_config.get("rules", [])
    # Normalize target event IDs to strings to avoid integer/string mismatches
    fbr_targets = {str(rule.get("event_id")) for rule in fbr_rules if rule.get("event_id") is not None}
    
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    redis = await Redis.from_url(settings.redis_url, decode_responses=True)

    # 🔐 Load RSA Private Key for Signing (MANDATORY for Non-Repudiation)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    repo_root = os.path.dirname(base_dir)
    private_key_path = os.path.join(repo_root, "keys", "private_key.pem")
    
    # Prefer environment-provided base64 PEM for secure hosting, fallback to disk
    key_data = None
    try:
        if getattr(settings, "private_key_b64", ""):
            key_data = base64.b64decode(settings.private_key_b64)
            logger.info("Loaded RSA Private Key for FBR from PRIVATE_KEY_B64 environment variable.")
    except Exception as e:
        logger.warning(f"Failed to decode PRIVATE_KEY_B64: {e}")

    if key_data is None:
        if not os.path.exists(private_key_path):
            logger.critical(f"FBR non-compliant: signing key missing at {private_key_path}. Worker cannot start.")
            sys.exit(1)
        try:
            with open(private_key_path, "rb") as key_file:
                key_data = key_file.read()
            logger.warning("Loaded RSA Private Key from disk (keys/private_key.pem). Consider moving to a secure keystore.")
        except Exception as e:
            logger.critical(f"FAILED TO LOAD SIGNING KEY FROM FILE: {e}. FBR Worker non-compliant.")
            sys.exit(1)

    # Load key supporting optional passphrase from settings
    try:
        password = settings.private_key_password.encode() if getattr(settings, "private_key_password", None) else None
        private_key = serialization.load_pem_private_key(key_data, password=password)
        logger.info("Loaded RSA Private Key for FBR Signing")
    except Exception as e:
        logger.critical(f"FAILED TO LOAD SIGNING KEY: {e}. Worker non-compliant.")
        sys.exit(1)

    # 🚨 ROOT FIX: Dead-Letter Queue (DLQ) for Poison Pills
    def _dlq_key(tenant_id: str | None) -> str:
        return f"{DLQ_QUEUE_PREFIX}{tenant_id or DEFAULT_TENANT_ID}"

    async def _eject_to_dlq(message_id, raw_payload, reason, tenant_id=None, stack_trace=None):
        """Ejects a poison pill message to the DLQ to prevent infinite crash loops."""
        dlq_queue = _dlq_key(tenant_id)
        logger.error(f"[DLQ EJECT] Message {message_id} ejected to {dlq_queue}. Reason: {reason}")
        try:
            dlq_entry = {
                "raw_payload": str(raw_payload),
                "error_msg": reason,
                "original_id": message_id,
                "worker_id": FBR_CONSUMER,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "failure_count": "1",
            }
            if stack_trace:
                dlq_entry["stack_trace"] = stack_trace
            await redis.xadd(dlq_queue, dlq_entry, maxlen=10000)
            await increment_redis_counter(redis, "warsoc_dlq_ejections_total")
            await redis.xack(RAW_LOGS_QUEUE, FBR_GROUP, message_id)
        except Exception as dlq_err:
            logger.error(f"Critical: Failed to eject to DLQ: {dlq_err}")

    # 🔒 Load Symmetric Encryption Key for Vault
    try:
        fernet_key = settings.encryption_key.encode() if getattr(settings, "encryption_key", "") else None
        if not fernet_key:
            logger.critical("FBR non-compliant: ENCRYPTION_KEY missing in .env.")
            sys.exit(1)
        fernet = Fernet(fernet_key)
    except Exception as e:
        logger.critical(f"FAILED TO INIT FERNET: {e}. Worker non-compliant.")
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
                
                # 🚀 ROOT FIX: Derive targets directly from the Compliance Master Catalog (SSOT)
                from app.utils.compliance_catalog import COMPLIANCE_CATALOG
                # Normalize catalog targets to string form to match incoming log event_id types
                new_targets = {str(rule.get("event_id")) for rule in COMPLIANCE_CATALOG["fbr_pos"]["rules"] if rule.get("event_id") is not None}
                
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
                        flush_batch = []
                        for item in buffer:
                            item = _normalize_document_timestamps(item)
                            event_uid = item.get("event_uid") or str(uuid.uuid4())
                            item["event_uid"] = event_uid
                            flush_batch.append(UpdateOne({"event_uid": event_uid}, {"$set": item}, upsert=True))
                        try:
                            await db.fbr_pos_logs.bulk_write(flush_batch)
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
                payload_by_mid = {}
                for message_id, payload in messages:
                    try:
                        # BUG-STABILIZE: Handle malformed JSON Poison Pills
                        raw_payload = payload.get("payload", "")
                        payload_by_mid[message_id] = raw_payload
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
                                await _eject_to_dlq(
                                    message_id, 
                                    raw_payload, 
                                    "JSON_PARSE_FAILURE",
                                    tenant_id=DEFAULT_TENANT_ID,
                                    stack_trace=traceback.format_exc()
                                )
                                continue
                        
                        tenant_id = log_data.get("tenant_id")

                        # 🔍 1. Plan Verification
                        plan = await get_tenant_plan(redis, tenant_id)
                        if plan not in ["Professional", "Enterprise", "FBR_PLAN", "FULL_SUITE"]:
                            immediate_ack_ids.append(message_id)
                            continue

                        # 🔍 2. DYNAMIC TARGET ENFORCEMENT
                        # Normalize incoming event_id to string for SSOT lookup
                        raw_eid = log_data.get("event_id")
                        is_syslog = log_data.get("type") == "network_log"
                        event_id = str(raw_eid).strip() if raw_eid is not None else ""
                        if not is_syslog:
                            if not event_id or event_id not in fbr_targets:
                                immediate_ack_ids.append(message_id)
                                continue

                        # --- FBR DYNAMIC THROTTLE & ROLL-UP ---
                        # Protect against FIM storms (mass file modifications) by using
                        # a Redis sliding-window counter per tenant+source. If the
                        # threshold is exceeded, create a single summary event and
                        # skip per-event encryption to avoid CPU exhaustion.
                        src_ip = log_data.get("source_ip") or log_data.get("src_ip") or "unknown"

                        # Inline throttle/rollup (reverted refactor)
                        try:
                            throttle_key = f"warsoc:fbr:count:{tenant_id}:{src_ip}"
                            throttle_flag_key = f"warsoc:fbr:throttle:{tenant_id}:{src_ip}"
                            use_window = int(getattr(settings, "fbr_fim_window", 10))
                            try:
                                cur = await incr_count(redis, throttle_key, window_seconds=use_window)
                            except Exception:
                                cur = 0

                            if await get_flag(redis, throttle_flag_key):
                                async with redis.pipeline(transaction=True) as pipe:
                                    await pipe.xack(RAW_LOGS_QUEUE, FBR_GROUP, message_id)
                                    await pipe.execute()
                                continue

                            try:
                                if isinstance(log_data.get("fbr_threshold"), int):
                                    threshold = int(log_data.get("fbr_threshold"))
                                else:
                                    threshold = int(getattr(settings, "fbr_fim_threshold", 500))
                            except Exception:
                                threshold = 500

                            if cur and cur > threshold:
                                summary = {
                                    "tenant_id": tenant_id,
                                    "source_ip": src_ip,
                                    "window_count": cur,
                                    "threshold": threshold,
                                    "event": "MASS_FILE_MODIFICATION_DETECTED",
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "tags": "FBR_ROLLUP",
                                    "retention_policy": "30_DAYS",
                                }
                                try:
                                    await db.fbr_pos_summaries.insert_one(summary)
                                    await increment_redis_counter(redis, "warsoc_fbr_rollups_total")
                                    await set_flag(redis, throttle_flag_key, ex=60)
                                    logger.warning(f"[FBR-ROLLUP] Created rollup for {tenant_id}@{src_ip} count={cur}")
                                except Exception as e:
                                    logger.error(f"Failed to persist FBR rollup summary: {e}")

                                async with redis.pipeline(transaction=True) as pipe:
                                    await pipe.xack(RAW_LOGS_QUEUE, FBR_GROUP, message_id)
                                    await pipe.execute()
                                continue
                        except Exception as e:
                            logger.error(f"FBR throttle inline handling error: {e}")

                        # 🔒 3. ENCRYPT SENSITIVE PAYLOAD (Field-Level)
                        if "message" in log_data and log_data["message"]:
                            log_data["message"] = fernet.encrypt(str(log_data["message"]).encode()).decode()
                        if "raw_event" in log_data and log_data["raw_event"]:
                            if isinstance(log_data["raw_event"], (dict, list)):
                                log_data["raw_event"] = json.dumps(log_data["raw_event"])
                            log_data["raw_event"] = fernet.encrypt(str(log_data["raw_event"]).encode()).decode()

                        # 🏷️ 4. Tagging & Zero-Trust HMAC Sealing
                        log_data["tags"] = "FBR_POS"
                        log_data["retention_policy"] = "30_DAYS"
                        log_data["ingested_at"] = datetime.now(timezone.utc).isoformat()
                        log_data["_retention_ts"] = datetime.now(timezone.utc)
                        _normalize_document_timestamps(log_data)
                        
                        # 🚀 PHASE 4: Server-Side Cryptographic Sealing (RSA-2048/PSS-SHA256)
                        # 1. Take a snapshot of the exact data state before sealing
                        signable_data = copy.deepcopy(log_data)
                        
                        # 2. Generate strict deterministic byte-stream
                        canonical_bytes = _to_canonical_bytes(signable_data)
                        
                        # 3. Sign the bytes using FBR-compliant RSA-PSS via executor
                        loop = asyncio.get_running_loop()
                        # Allow tuning of crypto workers via settings (helps throttle CPU usage)
                        crypto_workers = int(getattr(settings, "fbr_crypto_workers", 2))
                        executor = get_crypto_executor(max_workers=crypto_workers)
                        try:
                            log_data["forensic_seal"] = await loop.run_in_executor(
                                executor,
                                _sign_canonical_bytes,
                                canonical_bytes,
                                key_data,
                                None
                            )
                            # cooperative yield to the event loop to avoid tight CPU loops
                            await asyncio.sleep(0)
                        except ValueError as sign_err:
                            logger.error(f"Executor signing failed for {message_id}: {sign_err}")
                            await _eject_to_dlq(
                                message_id,
                                payload_by_mid.get(message_id, ""),
                                f"EXECUTOR_SIGNING_FAILURE: {str(sign_err)}",
                                tenant_id=log_data.get("tenant_id", DEFAULT_TENANT_ID),
                                stack_trace=traceback.format_exc(),
                            )
                            continue
                        
                        # 4. Attach the immutable seal
                        log_data["digital_signature"] = "RSA-2048-PSS-SHA256 (WarSOC Master)"
                        
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
                flush_batch = []
                for item in buffer:
                    item = _normalize_document_timestamps(item)
                    event_uid = item.get("event_uid") or str(uuid.uuid4())
                    item["event_uid"] = event_uid
                    flush_batch.append(UpdateOne({"event_uid": event_uid}, {"$set": item}, upsert=True))
                try:
                    await db.fbr_pos_logs.bulk_write(flush_batch)
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
    finally:
        shutdown_crypto_executor()

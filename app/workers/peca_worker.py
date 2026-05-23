import asyncio
import base64
import json
import time
import hashlib
import logging
import os
import sys
import copy
import socket
import traceback
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from datetime import datetime, timezone
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from motor.motor_asyncio import AsyncIOMotorClient
from redis import exceptions as redis_exceptions
from redis.asyncio import Redis
from app.config.config import get_settings
from pymongo import UpdateOne
import uuid

try:
    from canonicaljson import encode_canonical_json
    CANONICALJSON_AVAILABLE = True
except Exception:
    encode_canonical_json = None
    CANONICALJSON_AVAILABLE = False

from app.utils.tenant_cache import get_tenant_plan
from app.utils.observability import increment_redis_counter, record_worker_heartbeat_async
from app.utils.crypto_executor import get_crypto_executor, shutdown_crypto_executor, _sign_canonical_bytes
# This worker ensures non-repudiable log integrity for court-admissible evidence.
# Strictly Decoupled, RSA-2048 Digital Signing, Senior Architect Hardened
# PHASE 1: CPU-bound cryptographic signing offloaded to ProcessPoolExecutor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ETO-FORENSIC] %(message)s")
logger = logging.getLogger("ETO-Worker")

# Module-level key storage for executor-based signing
_KEY_DATA = None

settings = get_settings()
RAW_LOGS_QUEUE = "raw_logs_queue"
PECA_GROUP = "eto_group" # 🏗️ Unified: ETO/PECA shared group
SIGNER_ID = "WarSOC-PK-2026-v1" 
PECA_CONSUMER = os.environ.get("CONSUMER_NAME", f"eto_consumer_{socket.gethostname()}")
ETO_GROUP = PECA_GROUP # Legacy alias support
ETO_CONSUMER = PECA_CONSUMER
RECLAIM_MIN_IDLE_MS = 60000
RECLAIM_BATCH_SIZE = 50
DEFAULT_TENANT_ID = os.getenv("TENANT_ID", "WARSOC_898F3395")

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
        return None


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
    # Keep _retention_ts as a datetime for Mongo TTL index; canonicalization will convert a copy when signing.
    return document


def _to_canonical_bytes(obj) -> bytes:
    """Return canonical bytes for signing. Prefer `canonicaljson` if available,
    otherwise fall back to deterministic JSON with sorted keys and compact separators.

    This will deep-copy the object and convert any datetime values to
    UTC ISO-8601 strings so canonicalization is stable.
    """
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
            logger.error(f"Canonical encoding failed: {e}")
    
    # Fallback to high-entropy deterministic JSON if package is missing (Non-Compliant)
    logger.warning("Using fallback deterministic JSON (Non-Compliant for PECA)")
    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


async def reclaim_stale_messages(redis_client: Redis):
    """Best-effort reclaim for stale pending stream entries."""
    try:
        pending_entries = await redis_client.xpending_range(
            RAW_LOGS_QUEUE,
            PECA_GROUP,
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
            ETO_GROUP,
            ETO_CONSUMER,
            RECLAIM_MIN_IDLE_MS,
            stale_ids,
        )
        if reclaimed:
            logger.info(f"[XCLAIM] Reclaimed {len(reclaimed)} stale ETO message(s).")
        return reclaimed or []

    except redis_exceptions.ResponseError as e:
        logger.warning(f"[XCLAIM] ETO reclaim skipped safely: {e}")
        return []
    except Exception as e:
        logger.error(f"[XCLAIM] ETO reclaim error (non-fatal): {e}")
        return []

async def eto_worker():
    """
    MASTER BUILD: Consumer for raw_logs_queue.
    Implements RSA-2048 digital signatures to ensure non-repudiation (ETO 2002 Sections 5 & 6).
    """
    # 🔐 Global Inits
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    redis = await Redis.from_url(settings.redis_url, decode_responses=True)

    # 🔑 Resolve Signing Keys (prefer env-provided key material)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    repo_root = os.path.dirname(base_dir)
    private_key_path = os.path.join(repo_root, "keys", "private_key.pem")

    key_data = None
    # 1) Preferred: load base64-encoded PEM from environment (secure hosting)
    try:
        if getattr(settings, "private_key_b64", ""):
            key_data = base64.b64decode(settings.private_key_b64)
            logger.info("Loaded RSA Private Key from PRIVATE_KEY_B64 environment variable.")
    except Exception as e:
        logger.warning(f"Failed to decode PRIVATE_KEY_B64: {e}")

    # 2) Fallback to file on disk
    if key_data is None:
        if not os.path.exists(private_key_path):
            logger.critical(f"PECA non-compliant: signing key missing at {private_key_path}. Worker cannot start.")
            sys.exit(1)
        try:
            with open(private_key_path, "rb") as key_file:
                key_data = key_file.read()
            logger.warning("Loaded RSA Private Key from disk (keys/private_key.pem). Consider moving to a secure keystore.")
        except Exception as e:
            logger.critical(f"FAILED TO LOAD SIGNING KEY FROM FILE: {e}. Worker non-compliant.")
            sys.exit(1)

    # 3) Load key (supports optional passphrase)
    try:
        password = settings.private_key_password.encode() if getattr(settings, "private_key_password", None) else None
        private_key = serialization.load_pem_private_key(key_data, password=password)
        logger.info("Loaded RSA Private Key for PECA Signing")
        # Store key_data at module level for ProcessPoolExecutor access
        global _KEY_DATA
        _KEY_DATA = key_data
    except Exception as e:
        logger.critical(f"FAILED TO LOAD SIGNING KEY: {e}. Worker non-compliant.")
        sys.exit(1)

    # 🚨 ROOT FIX: Dead-Letter Queue (DLQ) for Poison Pills
    DLQ_QUEUE_PREFIX = "warsoc:dlq:"

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
                "worker_id": PECA_CONSUMER,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "failure_count": "1",
            }
            trace_text = stack_trace or traceback.format_exc()
            if trace_text and not trace_text.strip().startswith("None"):
                dlq_entry["stack_trace"] = trace_text

            await redis.xadd(dlq_queue, dlq_entry, maxlen=10000)
            await increment_redis_counter(redis, "warsoc_dlq_ejections_total")
            # Acknowledge the problematic message so it does not re-deliver forever
            await redis.xack(RAW_LOGS_QUEUE, PECA_GROUP, message_id)
        except Exception as dlq_err:
            logger.error(f"Critical: Failed to eject to DLQ: {dlq_err}")

    # 🔒 Load Symmetric Encryption Key for Vault
    try:
        fernet_key = settings.encryption_key.encode() if getattr(settings, "encryption_key", "") else None
        if not fernet_key:
            logger.critical("PECA non-compliant: ENCRYPTION_KEY missing in .env.")
            sys.exit(1)
        fernet = Fernet(fernet_key)
    except Exception as e:
        logger.critical(f"FAILED TO INIT FERNET: {e}. Worker non-compliant.")
        sys.exit(1)

    # 🛡️ ETO Consumer Group (Enterprise Baseline)
    while True:
        try:
            await redis.xgroup_create(RAW_LOGS_QUEUE, PECA_GROUP, mkstream=True)
            logger.info(f"✅ Created consumer group: {PECA_GROUP} on {RAW_LOGS_QUEUE}")
            break
        except redis_exceptions.ResponseError as e:
            if "BUSYGROUP" in str(e):
                logger.info(f"[*] Consumer group {ETO_GROUP} already exists. Resuming...")
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
    WATCH_IDS = set()
    buffer = []
    buffer_ack_ids = []
    last_flush_time = time.time()
    
    logger.info("⚡ WarSOC PECA Worker: Non-Repudiable Evidence Active (ETO 2002, Sections 5 & 6)...")
    
    while True:
        try:
            await record_worker_heartbeat_async("peca_worker")
            # 🔄 HOT-RELOAD: Sync Compliance Policy every 60 seconds (BUG-24 FIX)
            if time.time() - last_config_load > 60:
                CONFIG = load_dynamic_config()

                if not CONFIG:
                    WATCH_IDS = set()
                    logger.critical("[PECA] Policy load unavailable. Processing paused to prevent forensic bypass.")
                    last_config_load = time.time()
                    await asyncio.sleep(1)
                    continue
                
                # 🛡️ THE SSOT: Load monitoring targets from ETO 2002 framework in Master Config
                frameworks = CONFIG.get("compliance_frameworks", {})
                eto_config = frameworks.get("eto_forensic", {})
                eto_rules = eto_config.get("rules", [])
                # Normalize WATCH_IDS to strings to avoid integer/string mismatches
                WATCH_IDS = set(str(rule.get("event_id")) for rule in eto_rules if rule.get("event_id") is not None)

                if not WATCH_IDS:
                    logger.critical("[PECA] No ETO watch rules loaded. Processing paused to prevent forensic bypass.")
                    last_config_load = time.time()
                    await asyncio.sleep(1)
                    continue
                
                last_config_load = time.time()
                logger.info(f"[*] ETO 2002 Policy Synced: Monitoring {len(WATCH_IDS)} Forensic Controls.")

            if not WATCH_IDS:
                await asyncio.sleep(1)
                continue

            # ⚡ Optimized Read Performance: Fetch forensic batch
            streams = await redis.xreadgroup(PECA_GROUP, PECA_CONSUMER, {RAW_LOGS_QUEUE: ">"}, count=50, block=2000)
            
            if not streams:
                reclaimed_messages = await reclaim_stale_messages(redis)
                if not reclaimed_messages:
                    continue
                streams = [(RAW_LOGS_QUEUE, reclaimed_messages)]

            for _, messages in streams:
                if not messages:
                    continue

                forensic_batch = []
                forensic_ack_ids = []
                immediate_ack_ids = []
                payload_by_mid = {}

                for message_id, payload in messages:
                    try:
                        # BUG-STABILIZE: Handle malformed JSON Poison Pills
                        raw_payload = payload.get("payload", "")
                        payload_by_mid[message_id] = raw_payload
                        if not raw_payload:
                            logger.warning(f"Skipping empty PECA payload {message_id}")
                            immediate_ack_ids.append(message_id)
                            continue

                        try:
                            log_data = json.loads(raw_payload)
                        except json.JSONDecodeError:
                            # Best effort cleanup for Python-style stringified dicts
                            try:
                                sanitized = raw_payload.replace("'", '"')
                                log_data = json.loads(sanitized)
                                logger.info(f"[*] Sanitized malformed PECA JSON: {message_id}")
                            except Exception:
                                await _eject_to_dlq(
                                    message_id,
                                    raw_payload,
                                    "JSON_PARSE_FAILURE",
                                    tenant_id=DEFAULT_TENANT_ID,
                                    stack_trace=traceback.format_exc(),
                                )
                                continue
                        
                        tenant_id = log_data.get("tenant_id")

                        # 🔍 1. Plan Verification
                        plan = await get_tenant_plan(redis, tenant_id)
                        if plan not in ["Professional", "Enterprise"]:
                            immediate_ack_ids.append(message_id)
                            continue

                        # 🔍 2. DYNAMIC TARGET ENFORCEMENT (SSOT-derived)
                        raw_event_id = log_data.get("event_id")
                        is_syslog = log_data.get("type") == "network_log"
                        try:
                            # Normalize incoming event IDs to string form for SSOT lookup
                            event_id = str(raw_event_id).strip() if raw_event_id is not None else ""
                        except Exception:
                            # Unknown or malformed event id: skip for PECA (SIEM keeps raw log)
                            if not is_syslog:
                                immediate_ack_ids.append(message_id)
                                continue
                            event_id = ""

                        if not is_syslog:
                            if not event_id or event_id not in WATCH_IDS:
                                immediate_ack_ids.append(message_id)
                                continue

                        # 🔒 3. ENCRYPT SENSITIVE PAYLOAD (Field-Level)
                        if "message" in log_data and log_data["message"]:
                            log_data["message"] = fernet.encrypt(str(log_data["message"]).encode()).decode()
                        if "raw_event" in log_data and log_data["raw_event"]:
                            if isinstance(log_data["raw_event"], (dict, list)):
                                log_data["raw_event"] = json.dumps(log_data["raw_event"])
                            log_data["raw_event"] = fernet.encrypt(str(log_data["raw_event"]).encode()).decode()

                        # 🏷️ 3. Tagging & Zero-Trust HMAC Sealing
                        log_data["tags"] = "ETO_FORENSIC"
                        log_data["retention_policy"] = "365_DAYS"
                        log_data["ingested_at"] = datetime.now(timezone.utc).isoformat()
                        log_data["_retention_ts"] = datetime.now(timezone.utc)
                        _normalize_document_timestamps(log_data)

                        # 🚀 PHASE 4: Server-Side Cryptographic Sealing (RSA-2048/PSS-SHA256)
                        # ⚡ PHASE 1 OPTIMIZATION: ProcessPoolExecutor offloads crypto from event loop
                        # 1. Take a snapshot of the exact data state before sealing
                        signable_data = copy.deepcopy(log_data)
                        
                        # 2. Generate strict deterministic byte-stream
                        canonical_bytes = _to_canonical_bytes(signable_data)
                        
                        # 3. Sign the bytes using PECA-compliant RSA-PSS (non-blocking executor)
                        loop = asyncio.get_running_loop()
                        executor = get_crypto_executor(max_workers=2)
                        try:
                            log_data["forensic_seal"] = await loop.run_in_executor(
                                executor,
                                _sign_canonical_bytes,
                                canonical_bytes,
                                _KEY_DATA,
                                None  # password, if any
                            )
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
                        log_data["signed_payload"] = base64.b64encode(canonical_bytes).decode("utf-8")
                        log_data["canonicalization_version"] = "canonicaljson-v1"
                        log_data["digital_signature"] = "RSA-2048-PSS-SHA256 (WarSOC Master)"
                        
                        buffer.append(log_data)
                        forensic_ack_ids.append(message_id)
                    
                    except Exception as e:
                        # On any per-message processing failure, eject to DLQ and ack to avoid death-loop
                        reason = f"PROCESSING_ERROR: {str(e)}"
                        logger.exception(f"Error signing forensic log for {message_id}: {e}")
                        await _eject_to_dlq(
                            message_id,
                            payload_by_mid.get(message_id, raw_payload),
                            reason,
                            tenant_id=log_data.get("tenant_id") if "log_data" in locals() and isinstance(log_data, dict) else DEFAULT_TENANT_ID,
                            stack_trace=traceback.format_exc(),
                        )
                        continue

                # 📥 4. BULK VAULT PERSISTENCE
                # Flush the in-memory `buffer` of signed logs into MongoDB.
                if buffer:
                    try:
                        forensic_batch = []
                        for item in buffer:
                            item = _normalize_document_timestamps(item)
                            event_uid = item.get("event_uid") or str(uuid.uuid4())
                            item["event_uid"] = event_uid
                            forensic_batch.append(UpdateOne({"event_uid": event_uid}, {"$set": item}, upsert=True))
                        await db.peca_forensic_logs.bulk_write(forensic_batch)
                        logger.info(f"[*] PECA Signed and Vaulted {len(forensic_batch)} evidence logs.")
                    except Exception as e:
                        logger.exception(f"[!] PECA vault flush failed: {e}")
                        # On DB persistence failure, eject each pending message to DLQ to avoid losing evidence on crash
                        for mid in forensic_ack_ids:
                            try:
                                await _eject_to_dlq(
                                    mid,
                                    payload_by_mid.get(mid, ""),
                                    f"DB_INSERT_FAILURE: {str(e)}",
                                    tenant_id=DEFAULT_TENANT_ID,
                                    stack_trace=traceback.format_exc(),
                                )
                            except Exception as ex_eject:
                                logger.error(f"Failed to eject pending message {mid} after DB failure: {ex_eject}")
                    else:
                        if forensic_ack_ids:
                            async with redis.pipeline(transaction=True) as pipe:
                                for mid in forensic_ack_ids:
                                    pipe.xack(RAW_LOGS_QUEUE, PECA_GROUP, mid)
                                await pipe.execute()
                        # Clear the buffer after successful persistence so we do not re-insert
                        buffer.clear()

                # Ack intentionally skipped/malformed records immediately.
                if immediate_ack_ids:
                    async with redis.pipeline(transaction=True) as pipe:
                        for mid in immediate_ack_ids:
                            pipe.xack(RAW_LOGS_QUEUE, PECA_GROUP, mid)
                        await pipe.execute()

            await record_worker_heartbeat_async("peca_worker")

        except Exception as e:
            error_msg = str(e)
            if "NOGROUP" in error_msg:
                try:
                    await redis.xgroup_create(RAW_LOGS_QUEUE, PECA_GROUP, mkstream=True)
                    logger.info("[ETO-FORENSIC] Auto-Healed NOGROUP missing stream.")
                except Exception:
                    pass
            else:
                logger.error(f"[!] ETO Pipeline crash: {error_msg}")
            await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(eto_worker())
    except KeyboardInterrupt:
        print("[*] ETO Worker shutting down gracefully.")
    finally:
        shutdown_crypto_executor()

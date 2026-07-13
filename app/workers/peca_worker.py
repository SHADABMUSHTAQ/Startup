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
from datetime import datetime, timezone, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from motor.motor_asyncio import AsyncIOMotorClient
from redis import exceptions as redis_exceptions
from redis.asyncio import Redis
from app.config.config import get_settings
from pymongo import UpdateOne
import uuid
from app.utils.siem_catalog import SIEM_RULES
from app.utils.compliance_catalog import COMPLIANCE_CATALOG
from app.actions.alerting import dispatch_alert_if_entitled, is_email_trigger_severity

try:
    from canonicaljson import encode_canonical_json
    CANONICALJSON_AVAILABLE = True
except Exception:
    encode_canonical_json = None
    CANONICALJSON_AVAILABLE = False

from app.utils.tenant_cache import get_tenant_features
from app.utils.observability import increment_redis_counter, record_worker_heartbeat_with_client
from app.utils.crypto_executor import get_crypto_executor, shutdown_crypto_executor, _sign_canonical_bytes
# This worker ensures non-repudiable log integrity for court-admissible evidence.
# Strictly Decoupled, RSA-2048 Digital Signing, Senior Architect Hardened
# PHASE 1: CPU-bound cryptographic signing offloaded to ProcessPoolExecutor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PECA-FORENSIC] %(message)s")
logger = logging.getLogger("PECA-Worker")

# Module-level key storage for executor-based signing
_KEY_DATA = None
_KEY_PASSWORD = None

settings = get_settings()
RAW_LOGS_QUEUE = "raw_logs_queue"
PECA_GROUP = "eto_group" # 🏗 Unified: ETO/PECA shared group
SIGNER_ID = "WarSOC-PK-2026-v1" 
PECA_CONSUMER = f"peca_{os.getenv('CONSUMER_NAME', 'worker')}_{socket.gethostname()}"
ETO_GROUP = PECA_GROUP # Legacy alias support
ETO_CONSUMER = PECA_CONSUMER
RECLAIM_MIN_IDLE_MS = 60000
RECLAIM_BATCH_SIZE = 50
DEFAULT_TENANT_ID = "UNATTRIBUTED"

def load_dynamic_config():
    """Returns SSOT catalogs (CTO FIX)."""
    config = {}
    config.update(SIEM_RULES)
    if "compliance_frameworks" not in config:
        config["compliance_frameworks"] = {}
    config["compliance_frameworks"].update(COMPLIANCE_CATALOG)
    return config


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


def _is_peca_subscribed(plan_or_packages: str | None) -> bool:
    if not plan_or_packages:
        return False
    tokens = {
        token.strip().lower()
        for token in str(plan_or_packages).replace(";", ",").replace("|", ",").split(",")
        if token.strip()
    }
    return bool(
        tokens
        & {
            "eto_forensic",
            "peca_forensic",
            "peca",
            "eto",
        }
    )


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
    
    raise RuntimeError("canonicaljson is required for PECA forensic sealing")


def _should_alert_directly(event_id: str) -> bool:
    metadata = SIEM_RULES.get("event_id_map", {}).get(str(event_id), {})
    return bool(metadata.get("alert_on_event", False))


async def reclaim_stale_messages(redis_client: Redis, db):
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
                delivery_count = entry.get("delivery_count", 1)
            else:
                message_id = entry[0]
                delivery_count = entry[3]
            if isinstance(message_id, bytes):
                message_id = message_id.decode()
            if message_id:
                if delivery_count >= 3:
                    try:
                        res = await redis_client.xrange(RAW_LOGS_QUEUE, message_id, message_id)
                        payload = res[0][1] if res else {"payload": "unknown"}
                        dlq_entry = {
                            "raw_payload": str(payload.get("payload", "")),
                            "_ejection_reason": f"Max delivery count ({delivery_count}) exceeded (DLQ)",
                            "original_id": message_id,
                            "source_worker": "peca_worker",
                            "worker_id": PECA_CONSUMER,
                            "ejected_at": datetime.now(timezone.utc).isoformat(),
                            "failure_count": str(delivery_count),
                        }
                        await db.dead_letter_logs.insert_one(dlq_entry)
                        await increment_redis_counter(redis_client, "warsoc_dlq_ejections_total")
                        await redis_client.xack(RAW_LOGS_QUEUE, PECA_GROUP, message_id)
                        logger.error(f"[DLQ] Poisoned log {message_id} quarantined successfully.")
                    except Exception as dlq_err:
                        logger.error(f"[DLQ] Failed to quarantine {message_id}: {dlq_err}")
                else:
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

async def peca_worker():
    """
    MASTER BUILD: Consumer for raw_logs_queue.
    Implements RSA-2048 digital signatures to ensure non-repudiation (ETO 2002 Sections 5 & 6).
    """
    #  Global Inits
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    redis = await Redis.from_url(settings.redis_url, decode_responses=True)
    if not CANONICALJSON_AVAILABLE:
        logger.critical("PECA non-compliant: canonicaljson is unavailable. Worker cannot start.")
        sys.exit(1)

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
        if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < 2048:
            logger.critical("PECA non-compliant: an RSA private key of at least 2048 bits is required.")
            sys.exit(1)
        logger.info("Loaded RSA Private Key for PECA Signing")
        # Store key_data at module level for ProcessPoolExecutor access
        global _KEY_DATA, _KEY_PASSWORD
        _KEY_DATA = key_data
        _KEY_PASSWORD = password
    except Exception as e:
        logger.critical(f"FAILED TO LOAD SIGNING KEY: {e}. Worker non-compliant.")
        sys.exit(1)

    #  ROOT FIX: Dead-Letter Queue (DLQ) for Poison Pills
    DLQ_QUEUE_PREFIX = "warsoc:dlq:"

    def _dlq_key(tenant_id: str | None) -> str:
        return f"{DLQ_QUEUE_PREFIX}{tenant_id or DEFAULT_TENANT_ID}"

    async def _eject_to_dlq(message_id, raw_payload, reason, tenant_id=None, stack_trace=None):
        """Ejects a poison pill message to the DLQ to prevent infinite crash loops."""
        dlq_queue = _dlq_key(tenant_id)
        logger.error(f"[DLQ EJECT] Message {message_id} ejected to {dlq_queue}. Reason: {reason}")
        severity = "medium"
        if "JSON_PARSE_FAILURE" in str(reason):
            severity = "low"
        elif "DB_INSERT_FAILURE" in str(reason) or "EXECUTOR_SIGNING_FAILURE" in str(reason):
            severity = "critical"

        try:
            dlq_entry = {
                "raw_payload": str(raw_payload),
                "_ejection_reason": reason,
                "severity": severity,
                "original_id": message_id,
                "source_worker": "peca_worker",
                "worker_id": PECA_CONSUMER,
                "ejected_at": datetime.now(timezone.utc).isoformat(),
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

    #  ETO Consumer Group (Enterprise Baseline)
    while True:
        try:
            await redis.xgroup_create(RAW_LOGS_QUEUE, PECA_GROUP, mkstream=True)
            logger.info(f" Created consumer group: {PECA_GROUP} on {RAW_LOGS_QUEUE}")
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
    last_heartbeat = 0.0
    
    logger.info("⚡ WarSOC PECA Worker: Non-Repudiable Evidence Active (ETO 2002, Sections 5 & 6)...")
    
    try:
        while True:
            try:
                if time.time() - last_heartbeat >= 15:
                    await record_worker_heartbeat_with_client(redis, "peca_worker")
                    last_heartbeat = time.time()
                #  HOT-RELOAD: Sync Compliance Policy every 60 seconds (BUG-24 FIX)
                if time.time() - last_config_load > 60:
                    config = load_dynamic_config()

                    if not config:
                        WATCH_IDS = set()
                        logger.critical("[PECA] Policy load unavailable. Processing paused to prevent forensic bypass.")
                        last_config_load = time.time()
                        await asyncio.sleep(1)
                        continue
                
                    #  THE SSOT: Load monitoring targets from PECA compliance catalog.
                    from app.utils.compliance_catalog import COMPLIANCE_CATALOG

                    frameworks = config.get("compliance_frameworks", {})
                    peca_config = frameworks.get("peca_forensic", {})
                    peca_rules = peca_config.get("rules", [])
                    WATCH_IDS = set(str(rule.get("event_id")) for rule in peca_rules if rule.get("event_id") is not None)
                
                    for rule in COMPLIANCE_CATALOG.get("peca_forensic", {}).get("rules", []):
                        event_id = rule.get("event_id")
                        if event_id is not None:
                            WATCH_IDS.add(str(event_id))

                    if not WATCH_IDS:
                        logger.critical("[PECA] No PECA watch rules loaded. Processing paused to prevent forensic bypass.")
                        last_config_load = time.time()
                        await asyncio.sleep(1)
                        continue
                
                    last_config_load = time.time()
                    logger.info(f"[*] PECA Policy Synced: Monitoring {len(WATCH_IDS)} Forensic Controls.")

                if not WATCH_IDS:
                    await asyncio.sleep(1)
                    continue

                # ⚡ Optimized Read Performance: Fetch forensic batch
                streams = await redis.xreadgroup(PECA_GROUP, PECA_CONSUMER, {RAW_LOGS_QUEUE: ">"}, count=50, block=2000)
                
                if not streams:
                    reclaimed_messages = await reclaim_stale_messages(redis, db)
                    if not reclaimed_messages:
                        continue
                    streams = [(RAW_LOGS_QUEUE, reclaimed_messages)]

                for _, messages in streams:
                    if not messages:
                        continue

                    forensic_batch = []
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
                            features = await get_tenant_features(redis, tenant_id)
                            if not _is_peca_subscribed(features):
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
                            if "raw_data" in log_data and log_data["raw_data"]:
                                if isinstance(log_data["raw_data"], (dict, list)):
                                    log_data["raw_data"] = json.dumps(log_data["raw_data"])
                                log_data["raw_data"] = fernet.encrypt(str(log_data["raw_data"]).encode()).decode()
                            if "raw_event_data" in log_data and log_data["raw_event_data"]:
                                if isinstance(log_data["raw_event_data"], (dict, list)):
                                    log_data["raw_event_data"] = json.dumps(log_data["raw_event_data"])
                                log_data["raw_event_data"] = fernet.encrypt(str(log_data["raw_event_data"]).encode()).decode()
                            if "processed_data" in log_data and log_data["processed_data"]:
                                if isinstance(log_data["processed_data"], (dict, list)):
                                    log_data["processed_data"] = json.dumps(
                                        log_data["processed_data"],
                                        sort_keys=True,
                                        separators=(",", ":"),
                                        default=str,
                                    )
                                log_data["processed_data"] = fernet.encrypt(
                                    str(log_data["processed_data"]).encode()
                                ).decode()
                            log_data["encryption_version"] = "fernet-v1"

                            # 🏷 3. Tagging & Zero-Trust HMAC Sealing
                            from app.utils.compliance_catalog import get_rule_by_event_id
                            matched_pack, matched_rule = get_rule_by_event_id(event_id)
                            
                            log_data["compliance_pack"] = matched_pack or "peca_forensic"
                            if matched_rule:
                                log_data["matched_rule_id"] = matched_rule.get("id")
                                log_data["matched_rule_name"] = matched_rule.get("name")
                                log_data["matched_rule_severity"] = matched_rule.get("severity")
                                
                            log_data["tags"] = "PECA_FORENSIC"
                            log_data["retention_policy"] = "365_DAYS"
                            log_data["ingested_at"] = datetime.now(timezone.utc).isoformat()
                            log_data["_expire_at"] = datetime.now(timezone.utc) + timedelta(days=365)
                            _normalize_document_timestamps(log_data)

                            #  PHASE 4: Server-Side Cryptographic Sealing (RSA-2048/PSS-SHA256)
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
                                    _KEY_PASSWORD,
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
                            log_data["digital_signature"] = (
                                f"RSA-{private_key.key_size}-PSS-SHA256 (WarSOC Master)"
                            )
                            
                            if message_id not in buffer_ack_ids:
                                buffer.append(log_data)
                                buffer_ack_ids.append(message_id)
                        
                        except Exception as e:
                            # Operational failures remain pending for Redis reclaim.
                            # Repeated failures are quarantined by the delivery-count
                            # DLQ path, preserving the original stream payload.
                            logger.exception(f"Error signing forensic log for {message_id}: {e}")
                            await increment_redis_counter(
                                redis,
                                "warsoc_peca_processing_retries_total",
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
                                forensic_batch.append(UpdateOne({"tenant_id": item.get("tenant_id"), "event_uid": event_uid}, {"$set": item}, upsert=True))
                            await db.peca_forensic_logs.bulk_write(forensic_batch)
                            logger.info(f"[*] PECA Signed and Vaulted {len(forensic_batch)} evidence logs.")
                            for item in buffer:
                                if (
                                    _should_alert_directly(str(item.get("event_id") or ""))
                                    and is_email_trigger_severity(item.get("matched_rule_severity"))
                                ):
                                    await dispatch_alert_if_entitled(
                                        db, redis, item.get("tenant_id"), item, "peca_forensic"
                                    )
                        except Exception as e:
                            logger.exception(f"[!] PECA vault flush failed: {e}")
                            # MongoDB outages are transient. Keep stream messages
                            # pending so XCLAIM can replay them after recovery.
                            await increment_redis_counter(
                                redis,
                                "warsoc_peca_persistence_retries_total",
                            )
                        else:
                            if buffer_ack_ids:
                                async with redis.pipeline(transaction=True) as pipe:
                                    for mid in buffer_ack_ids:
                                        pipe.xack(RAW_LOGS_QUEUE, PECA_GROUP, mid)
                                    await pipe.execute()
                            # Clear the buffer after successful persistence so we do not re-insert
                            buffer.clear()
                            buffer_ack_ids.clear()

                    # Ack intentionally skipped/malformed records immediately.
                    if immediate_ack_ids:
                        async with redis.pipeline(transaction=True) as pipe:
                            for mid in immediate_ack_ids:
                                pipe.xack(RAW_LOGS_QUEUE, PECA_GROUP, mid)
                            await pipe.execute()

                    await record_worker_heartbeat_with_client(redis, "peca_worker")

            except Exception as e:
                error_msg = str(e)
                if "NOGROUP" in error_msg:
                    try:
                        await redis.xgroup_create(RAW_LOGS_QUEUE, PECA_GROUP, mkstream=True)
                        logger.info("[PECA-FORENSIC] Auto-Healed NOGROUP missing stream.")
                    except Exception:
                        pass
                else:
                    logger.error(f"[!] PECA Pipeline crash: {error_msg}")
                await asyncio.sleep(1)
    finally:
        try:
            await redis.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass
        shutdown_crypto_executor()

if __name__ == "__main__":
    try:
        asyncio.run(peca_worker())
    except KeyboardInterrupt:
        print("[*] PECA Worker shutting down gracefully.")


eto_worker = peca_worker

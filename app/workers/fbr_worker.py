import asyncio
import json
import time
import logging
import os
import sys
import copy
import traceback
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from datetime import datetime, timezone, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from redis import exceptions as redis_exceptions
from redis.asyncio import Redis
from app.config.config import get_settings
from app.utils.observability import increment_redis_counter
from app.utils.compliance_catalog import COMPLIANCE_CATALOG, get_rule_by_event_id
from app.utils.siem_catalog import SIEM_RULES

from app.utils.tenant_cache import get_tenant_features
from app.utils.rate_limiter import incr_count, set_flag, get_flag
from app.actions.alerting import dispatch_alert_if_entitled, is_email_trigger_severity
from app.utils.agent_crypto import timestamp_age_seconds


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

# 🏗 MASTER BUILD: FBR Compliance Worker (S.R.O. 288/I/2026 Optimized)
# Strictly Decoupled, Hybrid Flush (100 logs or 3s), Redis-Cached Plan Check

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


def _get_agent_security_config(config: dict) -> dict:
    return config.get("agent_security", {}) if isinstance(config, dict) else {}

def _clock_integrity_verdict(timestamp: str, security_config: dict) -> tuple[str, int | None]:
    skew_warning_seconds = int(security_config.get("clock_skew_warning_seconds", 60))
    hard_drop_seconds = int(security_config.get("max_log_age_seconds", 300))
    if hard_drop_seconds <= skew_warning_seconds:
        hard_drop_seconds = skew_warning_seconds + 1

    age_seconds = timestamp_age_seconds(timestamp)
    if age_seconds is None:
        return "drop", None

    abs_age = abs(age_seconds)
    if abs_age >= hard_drop_seconds:
        return "drop", age_seconds
    if abs_age > skew_warning_seconds:
        return "skew", age_seconds
    return "allow", age_seconds


async def _validate_stream_signature(redis: Redis, log_data: dict, security_config: dict) -> tuple[bool, str | None]:
    # Basic non-cryptographic sanity checks: presence of identity fields and timestamp validation.
    agent_id = str(log_data.get("agent_id") or "").strip()
    tenant_id = str(log_data.get("tenant_id") or "").strip()
    event_uid = str(log_data.get("event_uid") or "").strip()
    timestamp = str(log_data.get("timestamp") or "").strip()

    if not agent_id or not tenant_id or not event_uid:
        return False, "missing identity fields"

    verdict, age_seconds = _clock_integrity_verdict(timestamp, security_config)
    if verdict == "drop":
        return False, "timestamp outside allowed drift window"

    # Non-cryptographic: no signature or HMAC handling performed here.
    return True, None


def _is_fbr_subscribed(plan_or_packages: str | None) -> bool:
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
            "fbr_pos",
            "fbr",
            "fbr_pos_shield",
            "fbr_plan",
        }
    )


def _build_watch_ids(config: dict) -> set[str]:
    watch_ids: set[str] = set()
    frameworks = config.get("compliance_frameworks", {}) if isinstance(config, dict) else {}

    for rule in frameworks.get("fbr_pos", {}).get("rules", []):
        event_id = rule.get("event_id")
        if event_id is not None:
            watch_ids.add(str(event_id))

    for rule in COMPLIANCE_CATALOG.get("fbr_pos", {}).get("rules", []):
        event_id = rule.get("event_id")
        if event_id is not None:
            watch_ids.add(str(event_id))

    # Shared control events can belong to multiple frameworks in config.json.
    for event_id, meta in (config.get("event_id_map", {}) if isinstance(config, dict) else {}).items():
        frameworks_list = meta.get("frameworks", []) if isinstance(meta, dict) else []
        if "fbr_pos" in frameworks_list:
            watch_ids.add(str(event_id))

    return watch_ids


def _apply_rule_metadata(log_data: dict, rule_pack: str | None, rule: dict | None):
    if rule_pack:
        log_data["compliance_pack"] = rule_pack
    if rule:
        log_data["matched_rule_id"] = rule.get("id")
        log_data["matched_rule_name"] = rule.get("name")
        log_data["matched_rule_severity"] = rule.get("severity")

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


def _normalize_document_timestamps(document: dict):
    document["timestamp"] = _normalize_timestamp_iso_utc(document.get("timestamp"))
    if "ingested_at" in document:
        document["ingested_at"] = _normalize_timestamp_iso_utc(document.get("ingested_at"))
    # Keep _retention_ts as datetime for Mongo TTL indexes; canonicalization will convert a copy when signing.
    return document


def _upsert_body(document: dict) -> dict:
    body = dict(document)
    body.pop("_id", None)
    return body


async def _upsert_fbr_vault_and_alerts(db, cold_docs: list[dict]) -> list[dict]:
    now = datetime.now(timezone.utc)
    cold_ops = []
    keys = []

    for item in cold_docs:
        _normalize_document_timestamps(item)
        event_uid = item.get("event_uid") or str(uuid.uuid4())
        item["event_uid"] = event_uid
        key = {"tenant_id": item.get("tenant_id"), "event_uid": event_uid}
        keys.append((item.get("tenant_id"), event_uid))
        cold_ops.append(
            UpdateOne(
                key,
                {
                    "$set": _upsert_body(item),
                    "$setOnInsert": {"created_at": now},
                },
                upsert=True,
            )
        )

    if cold_ops:
        await db.fbr_pos_logs.bulk_write(cold_ops, ordered=False)

    cold_id_by_key = {}
    unique_filters = [
        {"tenant_id": tenant_id, "event_uid": event_uid}
        for tenant_id, event_uid in sorted(set(keys))
    ]
    if unique_filters:
        cursor = db.fbr_pos_logs.find(
            {"$or": unique_filters},
            {"_id": 1, "tenant_id": 1, "event_uid": 1},
        )
        async for doc in cursor:
            cold_id_by_key[(doc.get("tenant_id"), doc.get("event_uid"))] = doc.get("_id")

    meta_ops = []
    for item in cold_docs:
        tenant_id = item.get("tenant_id")
        event_uid = item.get("event_uid")
        alert_uid = f"fbr_pos:{tenant_id}:{event_uid}"
        meta = {
            "alert_uid": alert_uid,
            "tenant_id": tenant_id,
            "timestamp": _normalize_timestamp_iso_utc(item.get("ingested_at") or item.get("timestamp") or now),
            "event_id": str(item.get("event_id") or ""),
            "severity": item.get("matched_rule_severity") or "INFO",
            "pack": "fbr_pos",
            "compliance_pack": "fbr_pos",
            "source_ip": item.get("source_ip"),
            "summary": item.get("matched_rule_name") or item.get("message") or "",
            "event_uid": event_uid,
            "cold_id": cold_id_by_key.get((tenant_id, event_uid)),
            "_retention_ts": now,
        }
        meta_ops.append(
            UpdateOne(
                {"tenant_id": tenant_id, "alert_uid": alert_uid},
                {
                    "$set": meta,
                    "$setOnInsert": {"created_at": now},
                },
                upsert=True,
            )
        )

    if meta_ops:
        await db.security_alerts.bulk_write(meta_ops, ordered=False)

    return cold_docs


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
            
        stale_ids = [msg["message_id"] for msg in pending_entries]
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
    
    #  THE SSOT: Load monitoring targets from the compliance catalog and config map
    fbr_targets = _build_watch_ids(config)
    
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    redis = await Redis.from_url(settings.redis_url, decode_responses=True)

    # Signing removed per CTO directive. Worker will not perform server-side signatures.

    #  ROOT FIX: Dead-Letter Queue (DLQ) for Poison Pills
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
                "source_worker": "fbr_worker",
                "worker_id": FBR_CONSUMER,
                "ejected_at": datetime.now(timezone.utc).isoformat(),
                "failure_count": "1",
            }
            trace_text = stack_trace or traceback.format_exc()
            if trace_text and not trace_text.strip().startswith("None"):
                dlq_entry["stack_trace"] = trace_text
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

    #  Scale Mandate: Group Creation (Enterprise Lazy Init)
    while True:
        try:
            await redis.xgroup_create(RAW_LOGS_QUEUE, FBR_GROUP, mkstream=True)
            logger.info(f" Created consumer group: {FBR_GROUP} on {RAW_LOGS_QUEUE}")
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
    # fbr_targets already loaded from config above; do NOT reset to empty set here
    buffer = []
    buffer_ack_ids = []
    buffer_payload_by_mid = {}
    last_flush_time = time.time()

    logger.info("⚡ WarSOC FBR Worker: POS Compliance Active (SRO 288/69)...")
    
    while True:
        try:
            #  HOT-RELOAD: Sync Compliance Policy every 60 seconds (BUG-24 FIX)
            if time.time() - last_config_load > 60:
                config = load_dynamic_config()
                fbr_targets = _build_watch_ids(config)
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

                        try:
                            cold_docs = await _upsert_fbr_vault_and_alerts(db, list(buffer))

                            #  Phase 3 Action Engine Hook
                            for item in cold_docs:
                                if is_email_trigger_severity(item.get("matched_rule_severity")):
                                    await dispatch_alert_if_entitled(
                                        db, redis, item.get("tenant_id"), item, "fbr_pos"
                                    )

                        except Exception as e:
                            logger.error(f"[!] FBR flush failed (timeout path): {e}")
                            for mid in buffer_ack_ids:
                                try:
                                    await _eject_to_dlq(
                                        mid,
                                        buffer_payload_by_mid.get(mid, ""),
                                        f"DB_INSERT_FAILURE: {str(e)}",
                                        tenant_id=DEFAULT_TENANT_ID,
                                        stack_trace=traceback.format_exc(),
                                    )
                                except Exception as dlq_err:
                                    logger.error(f"Failed to eject pending FBR message {mid} after timeout DB failure: {dlq_err}")
                            buffer = []
                            buffer_ack_ids = []
                            buffer_payload_by_mid = {}
                        else:
                            if buffer_ack_ids:
                                async with redis.pipeline(transaction=True) as pipe:
                                    for mid in buffer_ack_ids:
                                        pipe.xack(RAW_LOGS_QUEUE, FBR_GROUP, mid)
                                    await pipe.execute()
                            buffer = []
                            buffer_ack_ids = []
                            buffer_payload_by_mid = {}
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

                        is_valid_signature, signature_reason = await _validate_stream_signature(
                            redis,
                            log_data,
                            _get_agent_security_config(locals().get("config") or {}),
                        )
                        if not is_valid_signature:
                            print(f"DROP: Signature invalid: {signature_reason}")
                            logger.warning(
                                f"[SECURITY] Invalid agent signature detected, dropping payload: message_id={message_id} reason={signature_reason}"
                            )
                            immediate_ack_ids.append(message_id)
                            continue
                        
                        tenant_id = log_data.get("tenant_id")

                        # 1. Fetch live features
                        features = await get_tenant_features(redis, tenant_id)
                        
                        # 2. Strict Zero-Trust Filter: If no fbr_pos pack, DROP IMMEDIATELY
                        if not _is_fbr_subscribed(features):
                            print(f"DROP: Not subscribed FBR: {features}")
                            immediate_ack_ids.append(message_id)
                            continue

                        # 🔍 2. DYNAMIC TARGET ENFORCEMENT
                        # Normalize incoming event_id to string for SSOT lookup
                        raw_eid = log_data.get("event_id")
                        is_syslog = log_data.get("type") == "network_log"
                        event_id = str(raw_eid).strip() if raw_eid is not None else ""
                        matched_pack = None
                        matched_rule = None
                        if event_id:
                            rule_pack, rule = get_rule_by_event_id(event_id)
                            if rule_pack == "fbr_pos":
                                matched_pack = rule_pack
                                matched_rule = rule
                        if not is_syslog:
                            if not event_id or event_id not in fbr_targets:
                                print(f"DROP: Event ID not in fbr_targets: {event_id} {fbr_targets}")
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
                                    pipe.xack(RAW_LOGS_QUEUE, FBR_GROUP, message_id)
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
                                    "retention_policy": "6_YEARS",
                                }
                                try:
                                    await db.fbr_pos_summaries.insert_one(summary)
                                    await increment_redis_counter(redis, "warsoc_fbr_rollups_total")
                                    await set_flag(redis, throttle_flag_key, ex=60)
                                    logger.warning(f"[FBR-ROLLUP] Created rollup for {tenant_id}@{src_ip} count={cur}")
                                except Exception as e:
                                    logger.error(f"Failed to persist FBR rollup summary: {e}")

                                async with redis.pipeline(transaction=True) as pipe:
                                    pipe.xack(RAW_LOGS_QUEUE, FBR_GROUP, message_id)
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

                        # 🏷 4. Tagging & Zero-Trust HMAC Sealing
                        log_data["tags"] = "FBR_POS"
                        log_data["retention_policy"] = "6_YEARS"
                        _apply_rule_metadata(log_data, matched_pack or "fbr_pos", matched_rule)
                        log_data["ingested_at"] = datetime.now(timezone.utc).isoformat()
                        log_data["_expire_at"] = datetime.now(timezone.utc) + timedelta(days=365 * 6)
                        _normalize_document_timestamps(log_data)
                        
                        # Signing removed: append the processed log to the buffer for dual-write.
                        buffer.append(log_data)
                        buffer_ack_ids.append(message_id)
                        buffer_payload_by_mid[message_id] = raw_payload
                    
                    except Exception as e:
                        logger.error(f"Error processing FBR log: {e}")
                        await _eject_to_dlq(
                            message_id,
                            payload_by_mid.get(message_id, payload.get("payload", "")),
                            f"PROCESSING_ERROR: {str(e)}",
                            tenant_id=log_data.get("tenant_id") if "log_data" in locals() and isinstance(log_data, dict) else DEFAULT_TENANT_ID,
                            stack_trace=traceback.format_exc(),
                        )
                        continue
                
                # Ack intentionally skipped/malformed records immediately.
                if immediate_ack_ids:
                    async with redis.pipeline(transaction=True) as pipe:
                        for mid in immediate_ack_ids:
                            pipe.xack(RAW_LOGS_QUEUE, FBR_GROUP, mid)
                        await pipe.execute()

            #  4. HYBRID FLUSH LOGIC
            current_time = time.time()
            if len(buffer) >= 100 or (len(buffer) > 0 and (current_time - last_flush_time) >= 3):
                logger.info(f"[*] Batch Flush: {len(buffer)} FBR logs to fbr_pos_logs...")
                flush_batch = []
                for item in buffer:
                    item = _normalize_document_timestamps(item)
                    event_uid = item.get("event_uid") or str(uuid.uuid4())
                    item["event_uid"] = event_uid

                try:
                    cold_docs = await _upsert_fbr_vault_and_alerts(db, list(buffer))
                    for d in cold_docs:
                        _normalize_document_timestamps(d)
                        if not d.get("event_uid"):
                            d["event_uid"] = str(uuid.uuid4())

                    inserted = []
                    if False and cold_docs:
                        res = None
                        inserted = list(res.inserted_ids or [])

                    meta_docs = []
                    for idx, item in enumerate(cold_docs):
                        meta = {
                            "tenant_id": item.get("tenant_id"),
                            "timestamp": _normalize_timestamp_iso_utc(item.get("ingested_at") or item.get("timestamp") or datetime.now(timezone.utc)),
                            "event_id": str(item.get("event_id") or ""),
                            "severity": item.get("matched_rule_severity") or "INFO",
                            "pack": "fbr_pos",
                            "source_ip": item.get("source_ip"),
                            "summary": item.get("matched_rule_name") or item.get("message") or "",
                            "event_uid": item.get("event_uid"),
                            "cold_id": (inserted[idx] if idx < len(inserted) else None),
                            "_retention_ts": datetime.now(timezone.utc),
                        }
                        meta_docs.append(meta)

                    if False and meta_docs:
                        pass

                    #  Phase 3 Action Engine Hook
                    for item in cold_docs:
                        if is_email_trigger_severity(item.get("matched_rule_severity")):
                            await dispatch_alert_if_entitled(
                                db, redis, item.get("tenant_id"), item, "fbr_pos"
                            )

                except Exception as e:
                    logger.error(f"[!] FBR flush failed: {e}")
                    for mid in buffer_ack_ids:
                        try:
                            await _eject_to_dlq(
                                mid,
                                buffer_payload_by_mid.get(mid, payload_by_mid.get(mid, "")),
                                f"DB_INSERT_FAILURE: {str(e)}",
                                tenant_id=DEFAULT_TENANT_ID,
                                stack_trace=traceback.format_exc(),
                            )
                        except Exception as dlq_err:
                            logger.error(f"Failed to eject pending FBR message {mid} after DB failure: {dlq_err}")
                    buffer = []
                    buffer_ack_ids = []
                    buffer_payload_by_mid = {}
                else:
                    if buffer_ack_ids:
                        async with redis.pipeline(transaction=True) as pipe:
                            for mid in buffer_ack_ids:
                                pipe.xack(RAW_LOGS_QUEUE, FBR_GROUP, mid)
                            await pipe.execute()
                    buffer = []
                    buffer_ack_ids = []
                    buffer_payload_by_mid = {}
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
        pass

import asyncio
import hashlib
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
from app.utils.observability import increment_redis_counter, record_worker_heartbeat_with_client
from app.utils.compliance_catalog import COMPLIANCE_CATALOG, get_rule_by_event_id
from app.utils.siem_catalog import SIEM_RULES

from app.utils.tenant_cache import get_tenant_features
from app.utils.rate_limiter import incr_count, set_flag, get_flag
from app.actions.alerting import dispatch_alert_if_entitled, is_email_trigger_severity
from app.utils.agent_crypto import timestamp_age_seconds


from cryptography.fernet import Fernet
import socket
from pymongo import UpdateOne
import uuid

try:
    from canonicaljson import encode_canonical_json
    CANONICALJSON_AVAILABLE = True
except Exception:
    CANONICALJSON_AVAILABLE = False

# FBR compliance worker: POS evidence vaulting and rollup protection.
# Strictly Decoupled, Hybrid Flush (100 logs or 3s), Redis-Cached Plan Check

logging.basicConfig(level=logging.INFO, format="%(asctime)s [FBR] %(message)s")
logger = logging.getLogger("FBR-Worker")

settings = get_settings()
FBR_ROLLUP_EVENT_IDS = {"FIM-DB-MOD"}
RAW_LOGS_QUEUE = "raw_logs_queue"
FBR_GROUP = "fbr_group"
FBR_CONSUMER = os.environ.get("CONSUMER_NAME", f"fbr_consumer_{socket.gethostname()}")
RECLAIM_MIN_IDLE_MS = 60000
RECLAIM_BATCH_SIZE = 50
DEFAULT_TENANT_ID = os.getenv("TENANT_ID", "WARSOC_DEFAULT")
DLQ_QUEUE_PREFIX = "warsoc:dlq:"
FIM_CORRELATION_TTL_SECONDS = 60
FIM_CLAIM_TTL_SECONDS = 900
FIM_DATABASE_EXTENSIONS = {
    ".mdf",
    ".ndf",
    ".ldf",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".db3",
    ".bak",
}
FBR_ENCRYPTED_FIELDS = (
    "message",
    "raw_event",
    "raw_data",
    "raw_event_data",
    "processed_data",
)


class FIMCorrelationUnavailable(RuntimeError):
    """Transient Redis failure. Leave the stream event pending for reclaim."""


def _encrypt_fbr_fields(log_data: dict, fernet: Fernet) -> dict:
    for sensitive_field in FBR_ENCRYPTED_FIELDS:
        value = log_data.get(sensitive_field)
        if value in (None, "", {}, []):
            continue
        if isinstance(value, (dict, list)):
            value = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        log_data[sensitive_field] = fernet.encrypt(str(value).encode()).decode()
    log_data["encryption_version"] = "fernet-v1"
    return log_data


def _processed_event_fields(log_data: dict) -> dict:
    processed = log_data.get("processed_data")
    if isinstance(processed, dict):
        return processed
    raw_event = log_data.get("raw_event_data")
    if isinstance(raw_event, dict):
        event_fields = raw_event.get("event_data")
        if isinstance(event_fields, dict):
            return event_fields
    return {}


def _is_database_path(path_value) -> bool:
    normalized = str(path_value or "").strip().strip('"')
    if not normalized:
        return False
    return os.path.splitext(normalized.lower())[1] in FIM_DATABASE_EXTENSIONS


def _has_delete_access(processed: dict) -> bool:
    access_mask = str(processed.get("access_mask") or "").strip().lower()
    access_list = str(processed.get("access_list") or "").strip().lower()
    try:
        numeric_mask = int(access_mask, 16) if access_mask.startswith("0x") else int(access_mask or "0")
    except ValueError:
        numeric_mask = 0
    return bool(numeric_mask & 0x10000) or "%%1537" in access_list or "delete" in access_list


def _fim_correlation_key(log_data: dict, handle_id: str) -> str:
    return (
        "warsoc:fim_correlate:"
        f"{log_data.get('tenant_id')}:{log_data.get('agent_id')}:{handle_id}"
    )


async def _atomic_claim_fim(redis: Redis, correlation_key: str, claim_key: str):
    """Atomically move delete context into a retryable persistence claim."""
    script = """
    local value = redis.call('GET', KEYS[1])
    if not value then
        value = redis.call('GET', KEYS[2])
    end
    if value then
        redis.call('SETEX', KEYS[2], ARGV[1], value)
        redis.call('DEL', KEYS[1])
    end
    return value
    """
    return await redis.eval(
        script,
        2,
        correlation_key,
        claim_key,
        FIM_CLAIM_TTL_SECONDS,
    )


def _stable_fim_event_uid(log_data: dict, event_uid: str | None) -> str:
    supplied_uid = str(event_uid or log_data.get("event_uid") or "").strip()
    if supplied_uid:
        return supplied_uid
    processed = _processed_event_fields(log_data)
    identity = {
        "tenant_id": log_data.get("tenant_id"),
        "agent_id": log_data.get("agent_id"),
        "event_id": log_data.get("event_id"),
        "timestamp": log_data.get("timestamp"),
        "channel": processed.get("channel"),
        "event_record_id": processed.get("event_record_id"),
        "handle_id": processed.get("handle_id") or processed.get("HandleId"),
    }
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


async def _normalize_native_fim_event(redis: Redis, log_data: dict, event_id: str, event_uid: str = None):
    processed = _processed_event_fields(log_data)
    handle_id = str(processed.get("handle_id") or processed.get("HandleId") or "").strip()
    object_path = str(processed.get("object_name") or processed.get("ObjectName") or "").strip()

    if event_id == "4663":
        if not handle_id or not _has_delete_access(processed) or not _is_database_path(object_path):
            await increment_redis_counter(redis, "warsoc_fim_4663_writes_ignored_total")
            return "ignore", None, None
        key = _fim_correlation_key(log_data, handle_id)
        try:
            await redis.setex(key, FIM_CORRELATION_TTL_SECONDS, object_path)
            await increment_redis_counter(redis, "warsoc_fim_delete_intents_total")
        except Exception as exc:
            raise FIMCorrelationUnavailable(f"Unable to persist FIM delete intent: {exc}") from exc
        return "context", None, None

    if event_id == "4660":
        if not handle_id:
            await increment_redis_counter(redis, "warsoc_fim_correlation_misses_total")
            return "unmatched", None, None
        key = _fim_correlation_key(log_data, handle_id)

        event_uid_fallback = _stable_fim_event_uid(log_data, event_uid)
        claim_id = hashlib.sha256(event_uid_fallback.encode()).hexdigest()
        claim_key = (
            f"warsoc:fim_claim:{log_data.get('tenant_id')}:"
            f"{log_data.get('agent_id')}:{claim_id}"
        )

        try:
            object_path = await _atomic_claim_fim(redis, key, claim_key)
        except Exception as exc:
            raise FIMCorrelationUnavailable(f"Unable to consume FIM delete intent: {exc}") from exc

        if isinstance(object_path, bytes):
            object_path = object_path.decode("utf-8", errors="replace")
        if not object_path or not _is_database_path(object_path):
            await increment_redis_counter(redis, "warsoc_fim_correlation_misses_total")
            return "unmatched", None, None

        normalized = copy.deepcopy(log_data)
        normalized["source_event_id"] = "4660"
        normalized["event_id"] = "FIM-DB-MOD"
        normalized["event_type"] = "database_tampered"
        normalized["event_uid"] = f"{event_uid_fallback}:fim-delete"
        normalized["message"] = "Protected POS database file deleted"
        normalized_processed = dict(processed)
        normalized_processed["object_name"] = str(object_path)
        normalized_processed["tamper_action"] = "file_deleted"
        normalized["processed_data"] = normalized_processed
        await increment_redis_counter(redis, "warsoc_fim_correlations_total")
        return "emit", normalized, claim_key

    if event_id == "4670":
        if not _is_database_path(object_path):
            return "unmatched", None, None
        normalized = copy.deepcopy(log_data)
        normalized["source_event_id"] = "4670"
        normalized["event_id"] = "FIM-DB-MOD"
        normalized["event_type"] = "database_tampered"
        normalized["event_uid"] = f"{log_data.get('event_uid')}:fim-permissions"
        normalized["message"] = "Protected POS database permissions changed"
        normalized_processed = dict(processed)
        normalized_processed["object_name"] = object_path
        normalized_processed["tamper_action"] = "permissions_changed"
        normalized["processed_data"] = normalized_processed
        await increment_redis_counter(redis, "warsoc_fim_correlations_total")
        return "emit", normalized, None

    return "passthrough", log_data, None


def _get_agent_security_config(config: dict) -> dict:
    return config.get("agent_security", {}) if isinstance(config, dict) else {}

def _clock_integrity_verdict(timestamp: str, security_config: dict) -> tuple[str, int | None]:
    skew_warning_seconds = int(security_config.get("clock_skew_warning_seconds", 60))
    max_future_skew_seconds = int(security_config.get("max_log_age_seconds", 300))
    if max_future_skew_seconds <= skew_warning_seconds:
        max_future_skew_seconds = skew_warning_seconds + 1

    age_seconds = timestamp_age_seconds(timestamp)
    if age_seconds is None:
        return "drop", None

    # Old events can be legitimate durable-spool replays after an outage.
    # Events far in the future cannot be explained by delivery delay.
    if age_seconds <= -max_future_skew_seconds:
        return "drop", age_seconds
    if age_seconds >= max_future_skew_seconds:
        return "delayed", age_seconds
    if abs(age_seconds) > skew_warning_seconds:
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
        return False, "invalid timestamp or timestamp too far in the future"
    log_data["clock_integrity"] = {
        "verdict": verdict,
        "age_seconds": age_seconds,
    }

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


def _clean_source_ip(candidate) -> str | None:
    text = str(candidate or "").strip()
    if not text or text.lower() in {"unknown", "none", "null", "-"}:
        return None
    return text


def _extract_fbr_source_ip(log_data: dict) -> str:
    processed = log_data.get("processed_data") if isinstance(log_data.get("processed_data"), dict) else {}
    raw_data = log_data.get("raw_data") if isinstance(log_data.get("raw_data"), dict) else {}
    raw_processed = raw_data.get("processed_data") if isinstance(raw_data.get("processed_data"), dict) else {}
    raw_event = log_data.get("raw_event_data") if isinstance(log_data.get("raw_event_data"), dict) else {}

    candidates = [
        processed.get("source_network_address"),
        raw_processed.get("source_network_address"),
        raw_event.get("source_network_address"),
        processed.get("source_ip"),
        raw_processed.get("source_ip"),
        log_data.get("source_ip"),
        log_data.get("src_ip"),
    ]
    for candidate in candidates:
        cleaned = _clean_source_ip(candidate)
        if cleaned:
            return cleaned
    return "unknown"


def _resolve_fbr_fim_threshold(log_data: dict) -> int:
    try:
        if isinstance(log_data.get("fbr_threshold"), int):
            return int(log_data.get("fbr_threshold"))
        return int(getattr(settings, "fbr_fim_threshold", 50))
    except Exception:
        return 50


def _is_fbr_rollup_candidate(event_id) -> bool:
    return str(event_id or "").strip().upper() in FBR_ROLLUP_EVENT_IDS


def _canonical_rollup_bytes(summary: dict) -> bytes:
    signable = copy.deepcopy(summary)
    signable.pop("integrity_seal", None)
    signable.pop("integrity_algorithm", None)
    if CANONICALJSON_AVAILABLE:
        return encode_canonical_json(signable)
    return json.dumps(signable, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _seal_fbr_rollup_summary(summary: dict) -> dict:
    sealed = copy.deepcopy(summary)
    sealed["integrity_algorithm"] = "SHA-256-CANONICAL-JSON"
    sealed["integrity_seal"] = hashlib.sha256(_canonical_rollup_bytes(sealed)).hexdigest()
    return sealed


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


async def reclaim_stale_messages(redis_client: Redis, db):
    """Best-effort reclaim for stale pending stream entries with Dead-Letter Queue (DLQ) quarantine."""
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
                        if res:
                            payload = res[0][1]
                            dlq_doc = {
                                "failed_at": datetime.now(timezone.utc).isoformat(),
                                "error_reason": f"Max delivery count ({delivery_count}) exceeded in FBR (DLQ)",
                                "original_payload": payload,
                                "message_id": message_id,
                                "tenant_id": payload.get(b"tenant_id", b"").decode("utf-8", errors="replace") if isinstance(payload, dict) else "unknown",
                            }
                            await db.dead_letter_logs.insert_one(dlq_doc)
                            logger.error(f"[DLQ] Poisoned log {message_id} quarantined successfully in FBR.")
                            await redis_client.xack(RAW_LOGS_QUEUE, FBR_GROUP, message_id)
                        else:
                            logger.warning(f"[DLQ] Message {message_id} evicted from stream before quarantine — NOT acknowledging to preserve PEL entry.")
                    except Exception as dlq_err:
                        logger.error(f"[DLQ] Failed to quarantine {message_id} in FBR: {dlq_err}")
                else:
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

    # Load the symmetric encryption key for the evidence vault.
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
    active_claim_keys = set()
    buffer_ack_ids = []
    buffer_payload_by_mid = {}
    last_flush_time = time.time()
    last_heartbeat = 0.0

    logger.info("WarSOC FBR Worker: POS compliance active")
    
    while True:
        try:
            if time.time() - last_heartbeat >= 15:
                await record_worker_heartbeat_with_client(redis, "fbr_worker")
                last_heartbeat = time.time()

            #  HOT-RELOAD: Sync Compliance Policy every 60 seconds (BUG-24 FIX)
            if time.time() - last_config_load > 60:
                config = load_dynamic_config()
                fbr_targets = _build_watch_ids(config)
                last_config_load = time.time()
                logger.info(f"[*] FBR Policy Synced: Monitoring {len(fbr_targets)} Event IDs.")

            # Read stream entries in bounded batches.
            streams = await redis.xreadgroup(FBR_GROUP, FBR_CONSUMER, {RAW_LOGS_QUEUE: ">"}, count=50, block=2000)
            
            if not streams:
                reclaimed_messages = await reclaim_stale_messages(redis, db)
                if reclaimed_messages:
                    streams = [(RAW_LOGS_QUEUE, reclaimed_messages)]
                else:
                    # Flush timeout check even if no new messages
                    current_time = time.time()
                    if buffer and (current_time - last_flush_time) >= 3:
                        logger.info(f"[*] Timeout Flush: {len(buffer)} FBR logs to fbr_pos_logs...")
                        for item in buffer:
                            item = _normalize_document_timestamps(item)
                            event_uid = item.get("event_uid") or str(uuid.uuid4())
                            item["event_uid"] = event_uid

                        try:
                            cold_docs = await _upsert_fbr_vault_and_alerts(db, list(buffer))

                            try:
                                if active_claim_keys:
                                    await redis.delete(*active_claim_keys)
                            except Exception as cleanup_err:
                                logger.error(f"[!] FBR flush: Failed to clean up active claim keys: {cleanup_err}")
                            finally:
                                active_claim_keys = set()

                            #  Phase 3 Action Engine Hook
                            for item in cold_docs:
                                if is_email_trigger_severity(item.get("matched_rule_severity")):
                                    await dispatch_alert_if_entitled(
                                        db, redis, item.get("tenant_id"), item, "fbr_pos"
                                    )

                        except Exception as e:
                            logger.error(
                                "[!] FBR flush failed (timeout path); messages remain "
                                f"pending for reclaim: {e}"
                            )
                            await increment_redis_counter(
                                redis,
                                "warsoc_fbr_persistence_retries_total",
                            )
                            buffer = []
                            active_claim_keys = set()
                            buffer_ack_ids = []
                            buffer_payload_by_mid = {}
                        else:
                            if buffer_ack_ids:
                                async with redis.pipeline(transaction=True) as pipe:
                                    for mid in buffer_ack_ids:
                                        pipe.xack(RAW_LOGS_QUEUE, FBR_GROUP, mid)
                                    await pipe.execute()
                            buffer = []
                            active_claim_keys = set()
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
                            await _eject_to_dlq(
                                message_id,
                                raw_payload,
                                "JSON_PARSE_FAILURE",
                                tenant_id=DEFAULT_TENANT_ID,
                                stack_trace=traceback.format_exc(),
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

                        # Dynamic target enforcement.
                        # Normalize incoming event_id to string for SSOT lookup
                        raw_eid = log_data.get("event_id")
                        is_syslog = log_data.get("type") == "network_log"
                        event_id = str(raw_eid).strip() if raw_eid is not None else ""
                        native_fim_generated = False
                        message_claim_key = None

                        if event_id in {"4660", "4663", "4670"}:
                            fim_result = await _normalize_native_fim_event(
                                redis,
                                log_data,
                                event_id,
                            )
                            fim_action = fim_result[0]
                            if fim_action in {"context", "ignore", "unmatched"}:
                                immediate_ack_ids.append(message_id)
                                continue
                            if fim_action == "emit" and fim_result[1] is not None:
                                log_data = fim_result[1]
                                event_id = "FIM-DB-MOD"
                                native_fim_generated = True
                                message_claim_key = fim_result[2]

                        if event_id == "FIM-DB-MOD" and not native_fim_generated:
                            logger.warning(
                                "[SECURITY] Rejected externally supplied FIM-DB-MOD "
                                f"message_id={message_id} tenant={tenant_id}"
                            )
                            await increment_redis_counter(
                                redis,
                                "warsoc_fim_external_events_rejected_total",
                            )
                            immediate_ack_ids.append(message_id)
                            continue

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
                        # Create a summary alert during a FIM storm, but never suppress
                        # the individual encrypted compliance evidence.
                        src_ip = _extract_fbr_source_ip(log_data)
                        log_data["source_ip"] = src_ip

                        if _is_fbr_rollup_candidate(event_id):
                            # Inline throttle/rollup for true file/object/database tamper storms only.
                            try:
                                throttle_key = f"warsoc:fbr:count:{tenant_id}:{src_ip}"
                                throttle_flag_key = f"warsoc:fbr:throttle:{tenant_id}:{src_ip}"
                                use_window = int(getattr(settings, "fbr_fim_window", 10))
                                try:
                                    cur = await incr_count(redis, throttle_key, window_seconds=use_window)
                                except Exception:
                                    cur = 0

                                threshold = _resolve_fbr_fim_threshold(log_data)
                                rollup_active = await get_flag(redis, throttle_flag_key)

                                if cur and cur > threshold and not rollup_active:
                                    summary = {
                                        "tenant_id": tenant_id,
                                        "source_ip": src_ip,
                                        "window_count": cur,
                                        "threshold": threshold,
                                        "event_id": "FBR-FIM-ROLLUP",
                                        "event": "MASS_FILE_MODIFICATION_DETECTED",
                                        "severity": "Critical",
                                        "pack": "fbr_pos",
                                        "compliance_pack": "fbr_pos",
                                        "matched_rule_id": "FBR-ROLLUP-MASS-FIM",
                                        "matched_rule_name": "Mass POS File Modification Rollup",
                                        "matched_rule_severity": "Critical",
                                        "event_uid": str(uuid.uuid4()),
                                        "timestamp": datetime.now(timezone.utc).isoformat(),
                                        "tags": "FBR_ROLLUP",
                                        "retention_policy": "6_YEARS",
                                        "source_ip_confidence": "remote_or_payload_source" if src_ip != "unknown" else "unknown",
                                    }
                                    summary = _seal_fbr_rollup_summary(summary)
                                    try:
                                        await db.fbr_pos_summaries.insert_one(summary)
                                        await increment_redis_counter(redis, "warsoc_fbr_rollups_total")
                                        await set_flag(redis, throttle_flag_key, ex=60)
                                        logger.warning(f"[FBR-ROLLUP] Created rollup for {tenant_id}@{src_ip} count={cur}")
                                    except Exception as e:
                                        logger.error(f"Failed to persist FBR rollup summary: {e}")
                            except Exception as e:
                                logger.error(f"FBR throttle inline handling error: {e}")

                        # Encrypt sensitive payload fields.
                        _encrypt_fbr_fields(log_data, fernet)

                        # Apply retention and compliance metadata.
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
                        if message_claim_key:
                            active_claim_keys.add(message_claim_key)

                    except FIMCorrelationUnavailable as e:
                        logger.error(
                            f"Transient FIM correlation failure for {message_id}; "
                            f"leaving stream event pending: {e}"
                        )
                    except Exception as e:
                        logger.error(f"Error processing FBR log: {e}")
                        await _eject_to_dlq(
                            message_id,
                            buffer_payload_by_mid.get(message_id, payload.get("payload", "")),
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
                for item in buffer:
                    _normalize_document_timestamps(item)
                    if not item.get("event_uid"):
                        item["event_uid"] = str(uuid.uuid4())

                try:
                    cold_docs = await _upsert_fbr_vault_and_alerts(db, list(buffer))

                    try:
                        if active_claim_keys:
                            await redis.delete(*active_claim_keys)
                    except Exception as cleanup_err:
                        logger.error(f"[!] FBR flush: Failed to clean up active claim keys: {cleanup_err}")
                    finally:
                        active_claim_keys = set()

                    #  Phase 3 Action Engine Hook
                    for item in cold_docs:
                        if is_email_trigger_severity(item.get("matched_rule_severity")):
                            await dispatch_alert_if_entitled(
                                db, redis, item.get("tenant_id"), item, "fbr_pos"
                            )

                except Exception as e:
                    logger.error(
                        "[!] FBR flush failed; messages remain pending for reclaim: "
                        f"{e}"
                    )
                    await increment_redis_counter(
                        redis,
                        "warsoc_fbr_persistence_retries_total",
                    )
                    buffer = []
                    active_claim_keys = set()
                    buffer_ack_ids = []
                    buffer_payload_by_mid = {}
                else:
                    if buffer_ack_ids:
                        async with redis.pipeline(transaction=True) as pipe:
                            for mid in buffer_ack_ids:
                                pipe.xack(RAW_LOGS_QUEUE, FBR_GROUP, mid)
                            await pipe.execute()
                    buffer = []
                    active_claim_keys = set()
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

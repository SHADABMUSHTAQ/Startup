import asyncio
import json
import logging
import os
import re
import socket
import time
import sys
import ipaddress
import uuid
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from datetime import datetime, timezone, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from redis import exceptions as redis_exceptions
from redis.asyncio import Redis
from pymongo import UpdateOne
from app.config.config import get_settings
from app.database import ensure_threat_intel_indexes
from app.utils.siem_logic import SIEMEngine, CorrelationEngine
from app.utils.siem_catalog import SIEM_RULES
from app.utils.compliance_catalog import COMPLIANCE_CATALOG
from app.utils.observability import increment_redis_counter, record_worker_heartbeat_with_client
from app.utils.custom_json import dumps as json_dumps
from app.utils.alert_incidents import operator_message
from app.actions.alerting import dispatch_alert_if_entitled, is_email_trigger_severity

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SIEM-Worker] %(message)s")
logger = logging.getLogger("SIEM-Worker")
settings = get_settings()

# Redis stream / consumer defaults
RAW_LOGS_QUEUE = "raw_logs_queue"
SIEM_HOT_QUEUE = "siem_hot_queue"
SIEM_GROUP = "siem_group"
SIEM_HOT_GROUP = "siem_hot_group"
SIEM_CONSUMER = f"siem_{os.getenv('CONSUMER_NAME', 'worker')}_{socket.gethostname()}"
RECLAIM_MIN_IDLE_MS = 60000
RECLAIM_BATCH_SIZE = max(1, min(500, int(os.getenv("SIEM_RECLAIM_BATCH_SIZE", "250"))))
RAW_RETENTION_ANCHOR_FIELD = "_expire_at"
SIEM_READ_BATCH_SIZE = int(os.getenv("SIEM_READ_BATCH_SIZE", "500"))
SIEM_RAW_READ_BATCH_SIZE = int(os.getenv("SIEM_RAW_READ_BATCH_SIZE", "50"))
SIEM_COLD_VAULT_BATCH_SIZE = int(os.getenv("SIEM_COLD_VAULT_BATCH_SIZE", "500"))
SIEM_RECLAIM_INTERVAL_SECONDS = max(
    1,
    int(os.getenv("SIEM_RECLAIM_INTERVAL_SECONDS", "5")),
)
SIEM_THROUGHPUT_LOG_INTERVAL = int(os.getenv("SIEM_THROUGHPUT_LOG_INTERVAL", "1000"))
SIEM_HOT_RETENTION_DAYS = max(1, min(7, int(os.getenv("SIEM_HOT_RETENTION_DAYS", "7"))))


_GENERIC_HIGH_SIGNAL_KEYWORDS = {
    "../",
    "..\\",
    "<script",
    "authentication failure",
    "certutil",
    "clear-eventlog",
    "cobalt strike",
    "drop table",
    "failed password",
    "hashcat",
    "javascript:",
    "login failed",
    "meterpreter",
    "mimikatz",
    "powershell",
    "rubeus",
    "union select",
    "vssadmin",
    "wevtutil",
    "xp_cmdshell",
}

_TENANT_ID_PATTERN = re.compile(r"""["']tenant_id["']\s*:\s*["']([^"']+)["']""", re.IGNORECASE)
_BOUNCER_BYPASS_SEVERITIES = {"HIGH", "CRITICAL"}


def load_dynamic_config():
    """Returns SSOT catalogs (CTO FIX)."""
    config = {}
    config.update(SIEM_RULES)
    if "compliance_frameworks" not in config:
        config["compliance_frameworks"] = {}
    config["compliance_frameworks"].update(COMPLIANCE_CATALOG)
    return config


def _humanize_event_type(event_type: str) -> str:
    return str(event_type or "").replace("_", " ").strip().title()


def _resolve_event_id_meaning(config: dict, event_id_value) -> str | None:
    event_id = str(event_id_value or "").strip()
    if not event_id:
        return None
        
    #  SSOT PRIORITY: Search the compliance frameworks for the rule name
    frameworks = config.get("compliance_frameworks", {})
    for f_id, framework in frameworks.items():
        for rule in framework.get("rules", []):
            if str(rule.get("event_id")) == event_id:
                return rule.get("name")

    # Fallback to local config map
    event_map = config.get("event_id_map", {})
    rule = event_map.get(event_id, {})
    event_type = rule.get("event_type")
    if not event_type:
        return None

    meaning = _humanize_event_type(event_type)
    return meaning if meaning else None


def _resolve_direct_event_severity(event_rule: dict, windows_config: dict, event_id: str) -> str:
    """Resolve direct-alert severity from the event SSOT before legacy fallbacks."""
    return str(
        event_rule.get("severity")
        or windows_config.get("severity_by_event_id", {}).get(str(event_id))
        or "MEDIUM"
    ).upper()


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
    return document


async def _record_detection_latency(redis_client, event_timestamp):
    try:
        event_time = _normalize_timestamp_iso_utc(event_timestamp)
        latency = max(0.0, (datetime.now(timezone.utc) - event_time).total_seconds())
        await redis_client.set("warsoc_detection_latency_seconds", f"{latency:.6f}", ex=600)
    except Exception:
        pass


def _safe_float(val):
    try:
        return float(val) if val not in [None, ""] else None
    except (ValueError, TypeError):
        return None

def _generic_interest_keywords(config: dict) -> set[str]:
    keywords = set(_GENERIC_HIGH_SIGNAL_KEYWORDS)
    for source_cfg in (config.get("source_classification", {}) or {}).values():
        for keyword in (source_cfg.get("severity_by_keyword", {}) or {}).keys():
            text = str(keyword or "").strip().lower()
            if len(text) >= 3:
                keywords.add(text)
    return keywords


def _is_unmapped_generic_event(event_id: str, config: dict) -> bool:
    event_token = str(event_id or "").strip()
    if not event_token:
        return True
    if event_token in (config.get("event_id_map", {}) or {}):
        return False
    for source_cfg in (config.get("source_classification", {}) or {}).values():
        trigger_ids = {str(value) for value in source_cfg.get("trigger_event_ids", [])}
        if event_token in trigger_ids:
            return False
    return not event_token.isdigit()


def _has_generic_detection_signal(raw_msg: str, config: dict) -> bool:
    msg = str(raw_msg or "").lower()
    if not msg:
        return False
    return any(keyword in msg for keyword in _generic_interest_keywords(config))


def _native_windows_channel(log_data: dict) -> str:
    for field_name in ("raw_event_data", "raw_data"):
        raw_event = log_data.get(field_name)
        if not isinstance(raw_event, dict):
            continue
        system = raw_event.get("system")
        if isinstance(system, dict):
            channel = str(system.get("channel") or "").strip()
            if channel:
                return channel
    return ""


def _trusted_telemetry_family(log_data: dict, event_id: str, event_type: str) -> str:
    """Classify only from structured producer metadata, never message keywords."""
    channel = _native_windows_channel(log_data).lower()
    if channel in {"security", "system"} and str(event_id or "").isdigit():
        return "windows"

    event_type = str(event_type or "").strip().lower()
    raw_data = log_data.get("raw_data")
    has_file_origin = isinstance(raw_data, dict) and bool(raw_data.get("web_log_file"))
    if event_type in {"http_request", "http_404", "http_500"} and has_file_origin:
        return "web"
    if event_type == "firewall" and has_file_origin:
        return "network"
    return "unknown"


def _keyword_sources_for_family(family: str) -> tuple[str, ...]:
    return {
        "windows": ("Windows-Sec", "Endpoint-EDR"),
        "web": ("Web-WAF",),
        "network": ("Network-IDS",),
    }.get(family, ())


def _keyword_sources_for_event(
    family: str,
    event_id: str,
    config: dict,
) -> tuple[str, ...]:
    """Use generic keyword dictionaries only when no native event rule exists."""
    if family == "windows" and str(event_id or "") in (config.get("event_id_map", {}) or {}):
        return ()
    return _keyword_sources_for_family(family)


def _extract_tenant_id_from_raw_payload(raw_payload) -> str | None:
    match = _TENANT_ID_PATTERN.search(str(raw_payload or ""))
    if not match:
        return None
    return match.group(1).strip() or None


def _should_persist_alert_under_bouncer(suppress_bouncer: bool, severity: str) -> bool:
    if not suppress_bouncer:
        return True
    return str(severity or "").upper() in _BOUNCER_BYPASS_SEVERITIES


async def _is_whitelisted_source(redis_client, tenant_id: str, source_ip: str, user: str, siem_engine: SIEMEngine) -> bool:
    source_ip = str(source_ip or "").strip()
    user = str(user or "").strip()

    if tenant_id and source_ip and redis_client:
        try:
            if await redis_client.sismember(f"warsoc:soar_whitelist:{tenant_id}", source_ip):
                return True
        except Exception as exc:
            logger.error(f"SOAR whitelist redis check failed for tenant {tenant_id}: {exc}")

    return user in siem_engine.whitelist_users or source_ip in siem_engine.whitelist_ips

def _build_retention_anchor(value, retention_days: int) -> datetime:
    """Build a BSON Date anchor for TTL without changing public timestamp fields."""
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except Exception:
            dt = datetime.now(timezone.utc)
    else:
        dt = datetime.now(timezone.utc)
        
    return dt.astimezone(timezone.utc) + timedelta(days=retention_days)


def _upsert_body(document: dict) -> dict:
    body = dict(document)
    body.pop("_id", None)
    return body


def _alert_uid_component(value) -> str:
    text = str(value or "unknown").strip().lower()
    safe = "".join(ch if ch.isalnum() else "_" for ch in text)
    return safe[:96].strip("_") or "unknown"


def _stable_alert_uid(prefix: str, tenant_id: str, event_uid: str, alert_type) -> str:
    return f"{prefix}_{tenant_id}_{event_uid}_{_alert_uid_component(alert_type)}"


def _siem_hot_done_key(tenant_id: str, event_uid: str) -> str:
    return f"warsoc:siem_hot_done:{tenant_id}:{event_uid}"


async def _is_siem_hot_done(redis_client: Redis, tenant_id: str, event_uid: str) -> bool:
    if not tenant_id or not event_uid:
        return False
    try:
        return bool(await redis_client.exists(_siem_hot_done_key(tenant_id, event_uid)))
    except Exception:
        return False


async def _mark_siem_hot_done(redis_client: Redis, tenant_id: str, event_uid: str) -> None:
    if not tenant_id or not event_uid:
        return
    try:
        await redis_client.setex(_siem_hot_done_key(tenant_id, event_uid), 7 * 24 * 60 * 60, "1")
    except Exception as exc:
        logger.warning(f"[SIEM-HOT] Failed to set idempotency marker: {exc}")


async def _flush_siem_cold_vault(db, cold_docs: list[dict]) -> int:
    if not cold_docs:
        return 0

    now = datetime.now(timezone.utc)
    ops = []
    for item in cold_docs:
        _normalize_document_timestamps(item)
        event_uid = item.get("event_uid") or str(uuid.uuid4())
        item["event_uid"] = event_uid
        ops.append(
            UpdateOne(
                {"tenant_id": item.get("tenant_id"), "event_uid": event_uid},
                {
                    "$set": _upsert_body(item),
                    "$setOnInsert": {"created_at": now},
                },
                upsert=True,
            )
        )

    await db.siem_cold_vault.bulk_write(ops, ordered=False)
    return len(ops)


async def reclaim_stale_messages(
    redis_client: Redis,
    db,
    stream_name: str = RAW_LOGS_QUEUE,
    group_name: str = SIEM_GROUP,
    consumer_name: str = SIEM_CONSUMER,
):
    """Best-effort reclaim for stale pending stream entries with Dead-Letter Queue (DLQ) quarantine."""
    try:
        pending_entries = await redis_client.xpending_range(
            stream_name,
            group_name,
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
                #  DEAD LETTER QUEUE LOGIC (Quarantine poisoned logs)
                if delivery_count >= 3:
                    try:
                        res = await redis_client.xrange(stream_name, message_id, message_id)
                        if res:
                            payload = res[0][1]
                            dlq_doc = {
                                "failed_at": datetime.now(timezone.utc).isoformat(),
                                "error_reason": f"Max delivery count ({delivery_count}) exceeded (DLQ)",
                                "original_payload": payload,
                                "message_id": message_id
                            }
                            await db.dead_letter_logs.insert_one(dlq_doc)
                            await increment_redis_counter(redis_client, "warsoc_dlq_ejections_total")
                            logger.error(f"[DLQ] Poisoned log {message_id} quarantined successfully.")
                        
                        # Only ack after successful quarantine
                        await redis_client.xack(stream_name, group_name, message_id)
                    except Exception as dlq_err:
                        logger.error(f"[DLQ] Failed to quarantine {message_id}: {dlq_err}")
                else:
                    stale_ids.append(message_id)

        if not stale_ids:
            return []

        reclaimed = await redis_client.xclaim(
            stream_name,
            group_name,
            consumer_name,
            RECLAIM_MIN_IDLE_MS,
            stale_ids,
        )
        if reclaimed:
            logger.info(f"[XCLAIM] Reclaimed {len(reclaimed)} stale SIEM message(s).")
        return reclaimed or []

    except redis_exceptions.ResponseError as e:
        logger.warning(f"[XCLAIM] SIEM reclaim skipped safely: {e}")
        return []
    except Exception as e:
        logger.error(f"[XCLAIM] SIEM reclaim error (non-fatal): {e}")
        return []

async def siem_worker():
    """
    UNIVERSAL RULE ENGINE: Strictly enforces config.json mandates.
    """
    config = load_dynamic_config()
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    redis = await Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        await ensure_threat_intel_indexes(db)
    except Exception as exc:
        logger.warning(f"[THREAT-INTEL] Worker bootstrap failed: {exc}")

    #  ROOT FIX: Dead-Letter Queue (DLQ) for Poison Pills
    DLQ_QUEUE = "raw_logs_queue_dlq"

    async def _eject_to_dlq(
        message_id,
        raw_payload,
        reason,
        stream_name: str = RAW_LOGS_QUEUE,
        group_name: str = SIEM_GROUP,
        tenant_id: str | None = None,
    ):
        """Ejects a poison pill message to the DLQ to prevent infinite crash loops."""
        logger.error(f"[DLQ EJECT] Message {message_id} ejected to {DLQ_QUEUE}. Reason: {reason}")
        try:
            raw_text = str(raw_payload or "")
            tenant_id = tenant_id or _extract_tenant_id_from_raw_payload(raw_text)
            security_signal = _has_generic_detection_signal(raw_text, config)
            dlq_entry = {
                "payload": raw_text,
                "reason": reason,
                "original_id": message_id,
                "original_stream": stream_name,
                "security_signal": "true" if security_signal else "false",
                "ingested_at": datetime.now(timezone.utc).isoformat(),
            }
            if tenant_id:
                dlq_entry["tenant_id"] = tenant_id

            await redis.xadd(
                DLQ_QUEUE,
                dlq_entry,
                maxlen=10000,
            )
            await increment_redis_counter(redis, "warsoc_dlq_ejections_total")

            if security_signal:
                await increment_redis_counter(redis, "warsoc_dlq_security_signal_total")
                if tenant_id:
                    alert_payload = {
                        "tenant_id": tenant_id,
                        "type": "SIEM_DLQ_SECURITY_SIGNAL",
                        "severity": "HIGH",
                        "summary": "High-risk SIEM payload was quarantined in the dead-letter queue",
                        "event_id": "",
                        "event_uid": str(message_id),
                        "alert_uid": _stable_alert_uid("dlq", tenant_id, str(message_id), reason),
                        "source_ip": "unknown",
                        "message": raw_text[:500],
                        "raw_message": raw_text[:500],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "_expire_at": datetime.now(timezone.utc) + timedelta(days=7),
                    }
                    _normalize_document_timestamps(alert_payload)
                    try:
                        await db.security_alerts.update_one(
                            {"tenant_id": tenant_id, "alert_uid": alert_payload["alert_uid"]},
                            {"$set": alert_payload},
                            upsert=True,
                        )
                        await redis.publish("security_alerts", json_dumps(alert_payload))
                        if is_email_trigger_severity(alert_payload.get("severity")):
                            await dispatch_alert_if_entitled(db, redis, tenant_id, alert_payload, "SIEM")
                    except Exception as alert_err:
                        logger.error(f"[DLQ] Failed to persist security-signal alert for {message_id}: {alert_err}")

            await redis.xack(stream_name, group_name, message_id)
        except Exception as dlq_err:
            logger.error(f"Critical: Failed to eject to DLQ: {dlq_err}")

    siem_engine = SIEMEngine(config)
    siem_engine.set_redis_client(redis)
    corr_engine  = CorrelationEngine(redis, config=config)

    async def _ensure_consumer_group(stream_name: str, group_name: str):
        while True:
            try:
                await redis.xgroup_create(stream_name, group_name, id="0", mkstream=True)
                logger.info(f" Created consumer group: {group_name} on {stream_name}")
                break
            except redis_exceptions.ResponseError as e:
                if "BUSYGROUP" in str(e):
                    logger.info(f"[*] Consumer group {group_name} already exists on {stream_name}. Resuming...")
                    break
                logger.error(f"[!] Group Creation Error for {group_name}: {e}. Retrying...")
                await asyncio.sleep(2)
            except redis_exceptions.ConnectionError as e:
                logger.warning(f"[!] Redis connection error during group creation: {e}. Retrying in 2s...")
                await asyncio.sleep(2)
            except Exception as e:
                logger.error(f"[!] Unexpected error during SIEM group creation: {e}. Retrying...")
                await asyncio.sleep(2)

    await _ensure_consumer_group(RAW_LOGS_QUEUE, SIEM_GROUP)
    await _ensure_consumer_group(SIEM_HOT_QUEUE, SIEM_HOT_GROUP)

    logger.info("⚡ WarSOC SIEM: Dynamic Rule Engine Online. Awaiting logs...")

    last_config_load = time.time()
    last_reclaim_run = 0.0
    processed_since_log = 0
    last_throughput_log = time.time()
    last_heartbeat = 0.0

    try:
        while True:
            try:
            # Hot-Reload Config every 10 seconds for real-time rule tuning
                if time.time() - last_config_load > 60:
                    config = load_dynamic_config()
                    siem_engine.refresh_config(config) # Full engine re-initialization
                    corr_engine.refresh_config(config)
                    last_config_load = time.time()

                if time.time() - last_heartbeat >= 15:
                    await record_worker_heartbeat_with_client(redis, "siem_worker")
                    last_heartbeat = time.time()

                streams = []
                now_monotonic = time.time()
                hot_streams = await redis.xreadgroup(
                    SIEM_HOT_GROUP,
                    SIEM_CONSUMER,
                    {SIEM_HOT_QUEUE: ">"},
                    count=SIEM_READ_BATCH_SIZE,
                    block=50,
                )
                if hot_streams:
                    streams.extend(hot_streams)

                # Hot security events preempt raw SIEM archival work. If the hot
                # queue has traffic, process it immediately and come back for raw
                # backlog on the next loop so new alerts are not trapped behind
                # noisy compliance/archive batches.
                fresh_streams = []
                if not hot_streams:
                    fresh_streams = await redis.xreadgroup(
                        SIEM_GROUP,
                        SIEM_CONSUMER,
                        {RAW_LOGS_QUEUE: ">"},
                        count=SIEM_RAW_READ_BATCH_SIZE,
                        block=100,
                    )
                    if fresh_streams:
                        streams.extend(fresh_streams)

                # Fresh hot-lane telemetry must never wait behind old pending backlog.
                # Reclaim stale PEL messages only after checking new hot/raw traffic.
                if now_monotonic - last_reclaim_run >= SIEM_RECLAIM_INTERVAL_SECONDS:
                    if not hot_streams:
                        reclaimed_hot = await reclaim_stale_messages(
                            redis,
                            db,
                            stream_name=SIEM_HOT_QUEUE,
                            group_name=SIEM_HOT_GROUP,
                        )
                        if reclaimed_hot:
                            streams.append((SIEM_HOT_QUEUE, reclaimed_hot))
                    if not hot_streams and not fresh_streams:
                        reclaimed_raw = await reclaim_stale_messages(redis, db)
                        if reclaimed_raw:
                            streams.append((RAW_LOGS_QUEUE, reclaimed_raw))
                    last_reclaim_run = now_monotonic

                if not streams:
                    continue

                for stream_name, messages in streams:
                    if not messages:
                        continue

                    group_name = SIEM_HOT_GROUP if stream_name == SIEM_HOT_QUEUE else SIEM_GROUP
                    is_hot_stream = stream_name == SIEM_HOT_QUEUE
                    ack_ids = []
                    cold_batch = []
                    cold_ack_ids = []
                    for message_id, payload in messages:
                        try:
                            # BUG-STABILIZE: Handle malformed JSON Poison Pills
                            raw_payload = payload.get("payload", "")
                            try:
                                log_data = json.loads(raw_payload)
                            except json.JSONDecodeError:
                                await _eject_to_dlq(
                                    message_id,
                                    raw_payload,
                                    "JSON_PARSE_FAILURE",
                                    stream_name=stream_name,
                                    group_name=group_name,
                                )
                                continue

                            tenant_id = log_data.get("tenant_id")

                            # 🏷 1. Global Normalization
                            api_now = datetime.now(timezone.utc)
                            log_data["ingested_at"] = api_now.isoformat()
                            _normalize_document_timestamps(log_data)
                            event_id = str(log_data.get("event_id", ""))
                            event_id_meaning = _resolve_event_id_meaning(config, event_id)
                            reported_event_type = str(log_data.get("event_type") or "").strip()
                            event_type_slug = str(
                                config.get("event_id_map", {}).get(event_id, {}).get("event_type", "")
                                or reported_event_type
                            ).strip()
                            raw_message = str(log_data.get("message") or "").strip() or "Unknown Event"
                            raw_msg = str(raw_payload).lower()
                            log_data["raw_message"] = raw_message
                            if event_id_meaning:
                                log_data["event_id_meaning"] = event_id_meaning
                            if event_type_slug:
                                log_data["event_type"] = event_type_slug
                            telemetry_family = _trusted_telemetry_family(
                                log_data,
                                event_id,
                                event_type_slug,
                            )
                            log_data["telemetry_family"] = telemetry_family

                            event_uid = log_data.get("event_uid") or str(uuid.uuid4())
                            log_data["event_uid"] = event_uid
                            _normalize_document_timestamps(log_data)
                            log_data[RAW_RETENTION_ANCHOR_FIELD] = _build_retention_anchor(
                                log_data.get("timestamp") or log_data.get("ingested_at"),
                                SIEM_HOT_RETENTION_DAYS,
                            )

                            if is_hot_stream and await _is_siem_hot_done(redis, tenant_id, event_uid):
                                ack_ids.append(message_id)
                                continue

                            if (
                                not is_hot_stream
                                and log_data.get("siem_hot_enqueued")
                                and await _is_siem_hot_done(redis, tenant_id, event_uid)
                            ):
                                cold_batch.append(log_data)
                                cold_ack_ids.append(message_id)
                                if len(cold_batch) >= SIEM_COLD_VAULT_BATCH_SIZE:
                                    try:
                                        await _flush_siem_cold_vault(db, cold_batch)
                                        ack_ids.extend(cold_ack_ids)
                                    except Exception as e:
                                        logger.error(f"[SIEM][DB] raw hot-copy cold-vault bulk flush failed: {e}")
                                    cold_batch = []
                                    cold_ack_ids = []
                                continue

                            if (
                                _is_unmapped_generic_event(event_id, config)
                                and not _has_generic_detection_signal(raw_msg, config)
                            ):
                                cold_batch.append(log_data)
                                cold_ack_ids.append(message_id)
                                if len(cold_batch) >= SIEM_COLD_VAULT_BATCH_SIZE:
                                    try:
                                        await _flush_siem_cold_vault(db, cold_batch)
                                        ack_ids.extend(cold_ack_ids)
                                    except Exception as e:
                                        logger.error(f"[SIEM][DB] generic cold-vault bulk flush failed: {e}")
                                    cold_batch = []
                                    cold_ack_ids = []
                                continue

                            processed = log_data.get("processed_data") or {}
                            source_ip = str(processed.get("source_network_address") or log_data.get("source_ip") or "0.0.0.0").strip()
                            extracted_user = str(processed.get("user") or log_data.get("user") or "unknown").strip()
                            raw_event_data = log_data.get("raw_event_data") if isinstance(log_data.get("raw_event_data"), dict) else {}
                            raw_system = raw_event_data.get("system") if isinstance(raw_event_data.get("system"), dict) else {}
                            alert_computer = str(processed.get("computer") or raw_system.get("computer") or "").strip()
                            alert_target = str(
                                processed.get("service_name")
                                or processed.get("object_name")
                                or processed.get("task_name")
                                or processed.get("share_name")
                                or processed.get("target_server")
                                or processed.get("target_user")
                                or processed.get("member_name")
                                or processed.get("destination_address")
                                or processed.get("new_process_name")
                                or ""
                            ).strip()
                            log_data["source_ip"] = source_ip
                            log_data["user"] = extracted_user

                            is_whitelisted_source = await _is_whitelisted_source(
                                redis,
                                tenant_id,
                                source_ip,
                                extracted_user,
                                siem_engine,
                            )
                            if is_whitelisted_source:
                                # Whitelists reduce low-signal alert noise; they must not bypass
                                # threat intel, regex, or correlation engines.
                                log_data["whitelisted_source"] = True

                            # ---- BOUNCER (Alert Sieve) ----
                            # Dampens known noisy event IDs, but never bypasses the detection engines.
                            bouncer_cfg = config.get("bouncer", {})
                            bouncer_event_ids = set(str(x) for x in bouncer_cfg.get("event_ids", [8233]))
                            bouncer_threshold = int(bouncer_cfg.get("threshold", 10))
                            bouncer_window = int(bouncer_cfg.get("window_seconds", 60))
                            suppress_bouncer = False
                            try:
                                if event_id in bouncer_event_ids:
                                    bkey = f"warsoc:bouncer:{tenant_id}:{event_id}"
                                    cnt = await redis.incr(bkey)
                                    if cnt == 1:
                                        await redis.expire(bkey, bouncer_window)
                                    if cnt > bouncer_threshold:
                                        suppress_bouncer = True
                                        logger.info(f"[BOUNCER] Dampening low-severity alerts for event {event_id} tenant {tenant_id}; count={cnt}")
                            except Exception as e:
                                logger.warning(f"[BOUNCER] Redis error: {e}")

                            alert_triggered = False
                            alert_type = "GENERIC_SECURITY_EVENT"
                            severity = "INFO"

                            # 🗄 MANDATE 5: TENANT PLAN ENFORCEMENT
                            # The Basic Tier is permanently abolished. All tenants run the Advanced SIEM Engine.
                            is_basic_plan = False

                            #  MANDATE 1: THREAT INTEL ENGINE (Immediate Drop/Alert)
                            if not is_basic_plan:
                                ti_config = config.get("threat_intelligence", {})
                                if ti_config.get("enabled") and source_ip in siem_engine.blacklisted_ips:
                                    alert_triggered = True
                                    alert_type = "MALICIOUS_IP_DETECTED"
                                    severity = "CRITICAL"

                            # 🔍 MANDATE 2: DYNAMIC KEYWORD SCANNER (WAF/LINUX/EDR)
                            if not alert_triggered and not is_basic_plan:
                                source_configs = config.get("source_classification", {})
                                for source_type in _keyword_sources_for_event(
                                    telemetry_family,
                                    event_id,
                                    config,
                                ):
                                    s_config = source_configs.get(source_type, {})
                                    severity_map = s_config.get("severity_by_keyword", {})
                                    for keyword, mapped_sev in severity_map.items():
                                        if keyword.lower() in raw_msg:
                                            if source_type.upper() == "WEB-WAF":
                                                print(f"WEB-WAF KEYWORD MATCHED: '{keyword}' IN MSG: {raw_msg}", flush=True)
                                            alert_triggered = True
                                            alert_type = f"{source_type.upper()}_KEYWORD_MATCH"
                                            severity = mapped_sev
                                            break
                                    if alert_triggered:
                                        break

                            if (
                                not alert_triggered
                                and _is_unmapped_generic_event(event_id, config)
                                and not _has_generic_detection_signal(raw_msg, config)
                            ):
                                cold_batch.append(log_data)
                                cold_ack_ids.append(message_id)
                                if len(cold_batch) >= SIEM_COLD_VAULT_BATCH_SIZE:
                                    try:
                                        await _flush_siem_cold_vault(db, cold_batch)
                                        ack_ids.extend(cold_ack_ids)
                                    except Exception as e:
                                        logger.error(f"[SIEM][DB] generic cold-vault bulk flush failed: {e}")
                                    cold_batch = []
                                    cold_ack_ids = []
                                continue

                            corr_alerts_already_run = False
                            direct_event_rule_alerted = False
                            #  MANDATE 3: WINDOWS EVENT MAPPING (Stateful/Stateless)
                            win_config = config.get("source_classification", {}).get("Windows-Sec", {})
                            if not alert_triggered and not is_basic_plan and event_id in map(str, win_config.get("trigger_event_ids", [])):
                                # Check False Positive Tuning (e.g. 4624 Logon Types)
                                fp_tuning = win_config.get("false_positive_tuning", {}).get(event_id, {})
                                allowed_logon_types = fp_tuning.get("allowed_logon_types", [])

                                event_rule = config.get("event_id_map", {}).get(event_id, {})
                                trigger_event = bool(event_rule.get("alert_on_event", False))
                                if allowed_logon_types and "logon_type" in processed:
                                    if processed.get("logon_type") not in allowed_logon_types:
                                        trigger_event = False

                                if trigger_event:
                                    severity = _resolve_direct_event_severity(
                                        event_rule,
                                        win_config,
                                        event_id,
                                    )
                                    alert_triggered = True
                                    direct_event_rule_alerted = True
                                    alert_type = f"WIN_EVENT_{event_id}_DETECTED"

                                # STATEFUL: Configuration-Driven Correlation Engine
                                # SKIPPED FOR BASIC PLANS
                                if not is_basic_plan:
                                    # Resolve geo-coordinates if present for travel detection
                                    lat = processed.get("geo_lat") or log_data.get("geo_lat")
                                    lon = processed.get("geo_lon") or log_data.get("geo_lon")
                                    ts  = log_data.get("timestamp") or log_data.get("ingested_at")

                                    # MASTER CALL: Runs all 50+ rules in one pass
                                    corr_alerts = await corr_engine.run_all(
                                        tenant_id=tenant_id,
                                        source_ip=source_ip,
                                        user=extracted_user,
                                        event_id=event_id,
                                        lat=lat,
                                        lon=lon,
                                        timestamp_iso=ts,
                                        event_type=event_type_slug,
                                        log_entry=log_data,
                                    )

                                    for c_alert in corr_alerts:
                                        c_alert["tenant_id"] = tenant_id
                                        c_alert.setdefault("event_uid", log_data.get("event_uid"))
                                        c_alert.setdefault("agent_id", log_data.get("agent_id"))
                                        c_alert.setdefault("computer", alert_computer)
                                        c_alert.setdefault("target", alert_target)
                                        alert_uid = c_alert.get("alert_uid") or _stable_alert_uid(
                                            "corr",
                                            tenant_id,
                                            log_data.get("event_uid") or message_id,
                                            c_alert.get("type") or c_alert.get("summary") or event_id,
                                        )
                                        c_alert["alert_uid"] = alert_uid
                                        try:
                                            await db.security_alerts.update_one({"tenant_id": tenant_id, "alert_uid": alert_uid}, {"$set": c_alert}, upsert=True)
                                            await redis.publish("security_alerts", json_dumps(c_alert))
                                            await _record_detection_latency(redis, log_data.get("timestamp"))
                                            logger.info(f"[CORR ALERT] {c_alert['severity']}: {c_alert['summary']}")
                                            if is_email_trigger_severity(c_alert.get("severity")):
                                                await dispatch_alert_if_entitled(db, redis, tenant_id, c_alert, "SIEM")
                                        except Exception as corr_db_err:
                                            logger.error(f"[CORR][DB] Failed to persist correlation alert: {corr_db_err}")
                                            raise
                                    # Skip the unified corr block below since we already ran it here
                                    corr_alerts_already_run = True

                            # 🏷 MANDATE 4: ALERT NAMING ENFORCEMENT (Config Map)
                            title_map = config.get("alert_title_map", {})
                            fallback_event_type = config.get("event_id_map", {}).get(str(event_id), {}).get("event_type", alert_type).replace("_", " ").title()
                            display_title = title_map.get(alert_type, f"Security Event: {fallback_event_type}")

                            whitelist_suppressed = (
                                is_whitelisted_source
                                and str(severity or "").upper() not in {"HIGH", "CRITICAL"}
                            )

                            if alert_triggered and whitelist_suppressed:
                                logger.info(
                                    f"[WHITELIST] Suppressed low-severity alert {alert_type} "
                                    f"for tenant {tenant_id} source={source_ip} user={extracted_user}"
                                )
                                await increment_redis_counter(redis, "warsoc_whitelist_suppressed_alerts_total")

                            if (
                                alert_triggered
                                and not whitelist_suppressed
                                and not _should_persist_alert_under_bouncer(suppress_bouncer, severity)
                            ):
                                logger.info(
                                    f"[BOUNCER] Suppressed low-severity alert {alert_type} "
                                    f"for event {event_id} tenant {tenant_id}"
                                )
                                await increment_redis_counter(redis, "warsoc_bouncer_suppressed_alerts_total")

                            if (
                                alert_triggered
                                and not whitelist_suppressed
                                and _should_persist_alert_under_bouncer(suppress_bouncer, severity)
                            ):
                                alert_payload = {
                                    "tenant_id": tenant_id,
                                    "type": alert_type,
                                    "severity": severity,
                                    "summary": display_title,
                                    "event_id": event_id,
                                    "event_id_meaning": event_id_meaning,
                                    "event_uid": log_data.get("event_uid"),
                                    "alert_uid": f"alert_{tenant_id}_{log_data.get('event_uid', message_id)}_{alert_type}",
                                    "source_ip": source_ip,
                                    "user": extracted_user,
                                    "agent_id": log_data.get("agent_id"),
                                    "computer": alert_computer,
                                    "target": alert_target,
                                    "message": operator_message({
                                        "summary": display_title,
                                        "event_id": event_id,
                                        "event_id_meaning": event_id_meaning,
                                        "message": raw_message,
                                        "computer": alert_computer,
                                        "agent_id": log_data.get("agent_id"),
                                    }),
                                    "raw_message": raw_message,
                                    "timestamp": log_data["ingested_at"],
                                    "_expire_at": datetime.now(timezone.utc) + timedelta(days=7),
                                }
                                _normalize_document_timestamps(alert_payload)
                                # Save to security_alerts collection
                                try:
                                    await db.security_alerts.update_one({"tenant_id": tenant_id, "alert_uid": alert_payload["alert_uid"]}, {"$set": alert_payload}, upsert=True)
                                except Exception as e:
                                    logger.error(f"[SIEM][DB] alert insert failed for {message_id}: {e}")
                                    raise

                                # Publish to redis for live websocket dashboard
                                await redis.publish("security_alerts", json_dumps(alert_payload))
                                await _record_detection_latency(redis, log_data.get("timestamp"))
                                logger.info(f"[!] ALERT: {display_title} for {tenant_id}")
                                if is_email_trigger_severity(alert_payload.get("severity")):
                                    await dispatch_alert_if_entitled(db, redis, tenant_id, alert_payload, "SIEM")

                            # 🧠 ADVANCED SIEM ENGINE (Regex, Phishing, Event Map)
                            if not is_basic_plan:
                                analysis_log = dict(log_data)
                                analysis_log["_direct_event_rule_alerted"] = direct_event_rule_alerted
                                findings = await siem_engine.analyze_single_log(analysis_log)
                                for finding in findings:
                                    finding["tenant_id"] = tenant_id
                                    finding.setdefault("agent_id", log_data.get("agent_id"))
                                    finding.setdefault("computer", alert_computer)
                                    finding.setdefault("target", alert_target)
                                    finding.setdefault("user", extracted_user)
                                    if not finding.get("event_id") and event_id:
                                        finding["event_id"] = event_id
                                    if not finding.get("event_uid") and log_data.get("event_uid"):
                                        finding["event_uid"] = log_data.get("event_uid")

                                    if not finding.get("event_id_meaning"):
                                        finding_meaning = _resolve_event_id_meaning(
                                            config,
                                            finding.get("event_id") or event_id,
                                        )
                                        if finding_meaning:
                                            finding["event_id_meaning"] = finding_meaning

                                    if not finding.get("raw_message"):
                                        finding["raw_message"] = raw_message

                                    finding["message"] = operator_message({
                                        **finding,
                                        "message": finding.get("message") or raw_message,
                                        "computer": alert_computer,
                                        "agent_id": log_data.get("agent_id"),
                                    })

                                    _normalize_document_timestamps(finding)
                                    finding["_expire_at"] = datetime.now(timezone.utc) + timedelta(days=7)
                                    finding["alert_uid"] = finding.get("alert_uid") or _stable_alert_uid(
                                        "adv",
                                        tenant_id,
                                        finding.get("event_uid") or log_data.get("event_uid") or message_id,
                                        finding.get("type") or finding.get("summary") or event_id,
                                    )
                                    try:
                                        await db.security_alerts.update_one({"tenant_id": tenant_id, "alert_uid": finding["alert_uid"]}, {"$set": finding}, upsert=True)
                                        await redis.publish("security_alerts", json_dumps(finding))
                                        await _record_detection_latency(redis, log_data.get("timestamp"))
                                        logger.info(f"[!] ADVANCED ALERT: {finding['summary']} for {tenant_id}")
                                        if is_email_trigger_severity(finding.get("severity")):
                                            await dispatch_alert_if_entitled(db, redis, tenant_id, finding, "SIEM")
                                    except Exception as e:
                                        logger.error(f"[SIEM][DB] finding insert failed for {message_id}: {e}")
                                        raise

                            # ⚡ CORRELATION ENGINE (Stateful Redis-backed multi-event rules)
                            # Only run if not already run inside the Windows event block above
                            if not is_basic_plan and not corr_alerts_already_run:
                                corr_alerts = await corr_engine.run_all(
                                    tenant_id=tenant_id,
                                    source_ip=source_ip,
                                    user=extracted_user,
                                    event_id=event_id,
                                    lat=_safe_float(log_data.get("geo_lat")),
                                    lon=_safe_float(log_data.get("geo_lon")),
                                    timestamp_iso=log_data.get("ingested_at", datetime.now(timezone.utc).isoformat()),
                                    event_type=event_type_slug,
                                    log_entry=log_data,
                                )
                                for corr_alert in corr_alerts:
                                    _normalize_document_timestamps(corr_alert)
                                    if not corr_alert.get("event_uid") and log_data.get("event_uid"):
                                        corr_alert["event_uid"] = log_data.get("event_uid")
                                    corr_alert.setdefault("agent_id", log_data.get("agent_id"))
                                    corr_alert.setdefault("computer", alert_computer)
                                    corr_alert.setdefault("target", alert_target)
                                    corr_alert["alert_uid"] = corr_alert.get("alert_uid") or _stable_alert_uid(
                                        "corr_adv",
                                        tenant_id,
                                        corr_alert.get("event_uid") or log_data.get("event_uid") or message_id,
                                        corr_alert.get("type") or corr_alert.get("summary") or event_id,
                                    )
                                    try:
                                        await db.security_alerts.update_one({"tenant_id": tenant_id, "alert_uid": corr_alert["alert_uid"]}, {"$set": corr_alert}, upsert=True)
                                        await redis.publish("security_alerts", json_dumps(corr_alert))
                                        await _record_detection_latency(redis, log_data.get("timestamp"))
                                        logger.info(f"[CORR] ALERT: {corr_alert['type']} | {corr_alert['severity']} | {tenant_id}")
                                        if is_email_trigger_severity(corr_alert.get("severity")):
                                            await dispatch_alert_if_entitled(db, redis, tenant_id, corr_alert, "SIEM")
                                    except Exception as corr_err:
                                        logger.error(f"[CORR] Failed to save correlation alert: {corr_err}")
                                        raise

                            if log_data.get("siem_hot_enqueued"):
                                await _mark_siem_hot_done(redis, tenant_id, log_data.get("event_uid"))

                            # Save the raw log for historical auditing
                            _normalize_document_timestamps(log_data)
                            log_data[RAW_RETENTION_ANCHOR_FIELD] = _build_retention_anchor(
                                    log_data.get("timestamp") or log_data.get("ingested_at"),
                                    SIEM_HOT_RETENTION_DAYS
                            )
                            cold_batch.append(log_data)
                            cold_ack_ids.append(message_id)
                            if len(cold_batch) >= SIEM_COLD_VAULT_BATCH_SIZE:
                                try:
                                    await _flush_siem_cold_vault(db, cold_batch)
                                    ack_ids.extend(cold_ack_ids)
                                except Exception as e:
                                    logger.error(f"[SIEM][DB] cold-vault bulk flush failed: {e}")
                                cold_batch = []
                                cold_ack_ids = []

                        except Exception as e:
                            logger.exception(f"Processing Error for {message_id}: {e}")
                            # Do not acknowledge or immediately eject operational
                            # failures. The stream PEL retains the event for reclaim;
                            # repeated failures are quarantined by the delivery-count
                            # DLQ path with the original payload preserved.
                            await increment_redis_counter(
                                redis,
                                "warsoc_siem_processing_retries_total",
                            )

                    if cold_batch:
                        try:
                            await _flush_siem_cold_vault(db, cold_batch)
                            ack_ids.extend(cold_ack_ids)
                        except Exception as e:
                            logger.error(f"[SIEM][DB] final cold-vault bulk flush failed: {e}")

                    # Batch Acknowledge after cold-vault persistence succeeds.
                    if ack_ids:
                        async with redis.pipeline(transaction=True) as pipe:
                            for mid in ack_ids:
                                await pipe.xack(stream_name, group_name, mid)
                            await pipe.execute()
                        processed_since_log += len(ack_ids)
                        if processed_since_log >= SIEM_THROUGHPUT_LOG_INTERVAL:
                            now_log = time.time()
                            elapsed = max(now_log - last_throughput_log, 0.001)
                            logger.info(
                                "[THROUGHPUT] SIEM processed=%s rate=%.1f logs/sec",
                                processed_since_log,
                                processed_since_log / elapsed,
                            )
                            processed_since_log = 0
                            last_throughput_log = now_log

            except Exception as e:
                error_msg = str(e)
                if "NOGROUP" in error_msg:
                    # Self-Healing Pipeline: If db was flushed, automatically rebuild the stream
                    try:
                        await _ensure_consumer_group(RAW_LOGS_QUEUE, SIEM_GROUP)
                        await _ensure_consumer_group(SIEM_HOT_QUEUE, SIEM_HOT_GROUP)
                        logger.info("[SIEM-CORE] Auto-Healed missing SIEM consumer group.")
                    except Exception:
                        pass
                else:
                    logger.error(f"[SIEM-CORE] Pipeline Crash: {e}")
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

if __name__ == "__main__":
    try:
        asyncio.run(siem_worker())
    except KeyboardInterrupt:
        logger.info("WarSOC SIEM offline.")

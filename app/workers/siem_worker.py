import asyncio
import json
import logging
import os
import socket
import time
import sys
import ipaddress
import uuid
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from redis import exceptions as redis_exceptions
from redis.asyncio import Redis
from app.config.config import get_settings
from app.database import ensure_threat_intel_indexes
from app.utils.siem_logic import SIEMEngine, CorrelationEngine, ACTIVE_MALICIOUS_IPS, bootstrap_active_malicious_ips
from app.utils.tenant_cache import get_tenant_plan
from app.utils.observability import increment_redis_counter
from app.utils.custom_json import dumps as json_dumps

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SIEM-Worker] %(message)s")
logger = logging.getLogger("SIEM-Worker")
settings = get_settings()

# Redis stream / consumer defaults
RAW_LOGS_QUEUE = "raw_logs_queue"
SIEM_GROUP = "siem_group"
SIEM_CONSUMER = os.getenv("CONSUMER_NAME", f"siem_consumer_{socket.gethostname()}")
RECLAIM_MIN_IDLE_MS = 60000
RECLAIM_BATCH_SIZE = 50
RAW_RETENTION_ANCHOR_FIELD = "_retention_ts"


async def threat_intel_update_listener(redis_url: str):
    """Dedicated Pub/Sub listener for threat intel fanout updates in worker runtime."""
    logger.info("[THREAT-INTEL] Worker listener online.")
    while True:
        redis_conn = None
        pubsub = None
        try:
            redis_conn = await Redis.from_url(redis_url, decode_responses=True)
            pubsub = redis_conn.pubsub()
            await pubsub.subscribe("threat_intel_updates")

            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                try:
                    ip_candidate = str(message.get("data") or "").strip()
                    if not ip_candidate:
                        continue
                    ipaddress.ip_address(ip_candidate)
                    ACTIVE_MALICIOUS_IPS.add(ip_candidate)
                except Exception as inner_exc:
                    logger.warning(f"[THREAT-INTEL] Invalid Pub/Sub payload ignored: {inner_exc}")

        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning(f"[THREAT-INTEL] Listener error, retrying: {exc}")
            await asyncio.sleep(2)
        finally:
            try:
                if pubsub is not None:
                    await pubsub.close()
            except Exception:
                pass
            try:
                if redis_conn is not None:
                    await redis_conn.close()
            except Exception:
                pass
 
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


def _humanize_event_type(event_type: str) -> str:
    return str(event_type or "").replace("_", " ").strip().title()


def _resolve_event_id_meaning(config: dict, event_id_value) -> str | None:
    event_id = str(event_id_value or "").strip()
    if not event_id:
        return None
        
    # 🛡️ SSOT PRIORITY: Search the compliance frameworks for the rule name
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


def _safe_float(val):
    try:
        return float(val) if val not in [None, ""] else None
    except (ValueError, TypeError):
        return None

def _build_retention_anchor(value) -> datetime:
    """Build a BSON Date anchor for TTL without changing public timestamp fields."""
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


async def reclaim_stale_messages(redis_client: Redis, db):
    """Best-effort reclaim for stale pending stream entries with Dead-Letter Queue (DLQ) quarantine."""
    try:
        pending_entries = await redis_client.xpending_range(
            RAW_LOGS_QUEUE,
            SIEM_GROUP,
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
                # 🛑 DEAD LETTER QUEUE LOGIC (Quarantine poisoned logs)
                if delivery_count >= 3:
                    try:
                        res = await redis_client.xrange(RAW_LOGS_QUEUE, message_id, message_id)
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
                        await redis_client.xack(RAW_LOGS_QUEUE, SIEM_GROUP, message_id)
                    except Exception as dlq_err:
                        logger.error(f"[DLQ] Failed to quarantine {message_id}: {dlq_err}")
                else:
                    stale_ids.append(message_id)

        if not stale_ids:
            return []

        reclaimed = await redis_client.xclaim(
            RAW_LOGS_QUEUE,
            SIEM_GROUP,
            SIEM_CONSUMER,
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
    threat_listener_task = asyncio.create_task(threat_intel_update_listener(settings.redis_url))

    try:
        await bootstrap_active_malicious_ips(db)
        await ensure_threat_intel_indexes(db)
    except Exception as exc:
        logger.warning(f"[THREAT-INTEL] Worker bootstrap failed: {exc}")

    # 🚨 ROOT FIX: Dead-Letter Queue (DLQ) for Poison Pills
    DLQ_QUEUE = "raw_logs_queue_dlq"

    async def _eject_to_dlq(message_id, raw_payload, reason):
        """Ejects a poison pill message to the DLQ to prevent infinite crash loops."""
        logger.error(f"[DLQ EJECT] Message {message_id} ejected to {DLQ_QUEUE}. Reason: {reason}")
        try:
            await redis.xadd(DLQ_QUEUE, {"payload": str(raw_payload), "reason": reason, "original_id": message_id}, maxlen=10000)
            await increment_redis_counter(redis, "warsoc_dlq_ejections_total")
            await redis.xack(RAW_LOGS_QUEUE, SIEM_GROUP, message_id)
        except Exception as dlq_err:
            logger.error(f"Critical: Failed to eject to DLQ: {dlq_err}")

    siem_engine = SIEMEngine(config)
    siem_engine.set_redis_client(redis)
    corr_engine  = CorrelationEngine(redis, config=config)

    # 🛠️ Scale Mandate: Group Creation (Enterprise Lazy Init)
    while True:
        try:
            await redis.xgroup_create(RAW_LOGS_QUEUE, SIEM_GROUP, mkstream=True)
            logger.info(f"✅ Created consumer group: {SIEM_GROUP} on {RAW_LOGS_QUEUE}")
            break
        except redis_exceptions.ResponseError as e:
            if "BUSYGROUP" in str(e):
                logger.info(f"[*] Consumer group {SIEM_GROUP} already exists. Resuming...")
                break
            logger.error(f"[!] Group Creation Error: {e}. Retrying...")
            await asyncio.sleep(2)
        except redis_exceptions.ConnectionError as e:
            logger.warning(f"[!] Redis connection error during group creation: {e}. Retrying in 2s...")
            await asyncio.sleep(2)
        except Exception as e:
            logger.error(f"[!] Unexpected error during SIEM group creation: {e}. Retrying...")
            await asyncio.sleep(2)

    logger.info("⚡ WarSOC SIEM: Dynamic Rule Engine Online. Awaiting logs...")

    last_config_load = time.time()

    try:
        while True:
            try:
            # Hot-Reload Config every 10 seconds for real-time rule tuning
                if time.time() - last_config_load > 60:
                    config = load_dynamic_config()
                    siem_engine.refresh_config(config) # Full engine re-initialization
                    corr_engine.refresh_config(config)
                    last_config_load = time.time()

                streams = await redis.xreadgroup(SIEM_GROUP, SIEM_CONSUMER, {RAW_LOGS_QUEUE: ">"}, count=50, block=2000)
                if not streams:
                    reclaimed_messages = await reclaim_stale_messages(redis, db)
                    if not reclaimed_messages:
                        continue
                    streams = [(RAW_LOGS_QUEUE, reclaimed_messages)]

                for _, messages in streams:
                    if not messages:
                        continue

                    ack_ids = []
                    for message_id, payload in messages:
                        try:
                            # BUG-STABILIZE: Handle malformed JSON Poison Pills
                            raw_payload = payload.get("payload", "")
                            try:
                                log_data = json.loads(raw_payload)
                            except json.JSONDecodeError:
                                # Best effort cleanup for Python-style stringified dicts
                                try:
                                    sanitized = raw_payload.replace("'", '"')
                                    log_data = json.loads(sanitized)
                                    logger.info(f"[*] Sanitized malformed SIEM JSON: {message_id}")
                                except Exception:
                                    await _eject_to_dlq(message_id, raw_payload, "JSON_PARSE_FAILURE")
                                    continue

                            tenant_id = log_data.get("tenant_id")

                            # 🔍 0. Plan Verification
                            plan = await get_tenant_plan(redis, tenant_id)

                            # 🏷️ 1. Global Normalization
                            api_now = datetime.now(timezone.utc)
                            log_data["ingested_at"] = api_now.isoformat()
                            _normalize_document_timestamps(log_data)
                            event_id = str(log_data.get("event_id", ""))
                            logger.info(f"[*] Processing log {message_id} | tenant={tenant_id} | event={event_id}")
                            event_id_meaning = _resolve_event_id_meaning(config, event_id)
                            event_type_slug = str(
                                config.get("event_id_map", {}).get(event_id, {}).get("event_type", "")
                            ).strip()
                            raw_message = str(log_data.get("message") or "").strip() or "Unknown Event"
                            log_data["raw_message"] = raw_message
                            if event_id_meaning:
                                log_data["event_id_meaning"] = event_id_meaning
                            if event_type_slug:
                                log_data["event_type"] = event_type_slug

                            processed = log_data.get("processed_data") or {}
                            source_ip = str(processed.get("source_network_address") or log_data.get("source_ip") or "0.0.0.0").strip()
                            extracted_user = str(processed.get("user") or log_data.get("user") or "unknown").strip()
                            raw_msg = str(payload.get("payload", "")).lower()

                            # ---- BOUNCER (Alert Sieve) ----
                            # Early suppression for known noisy event IDs (e.g., 8233).
                            # Keeps raw logs but prevents alert generation when flood thresholds are exceeded.
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
                                        logger.info(f"[BOUNCER] Suppressing alerts for event {event_id} tenant {tenant_id}; count={cnt}")
                            except Exception as e:
                                logger.warning(f"[BOUNCER] Redis error: {e}")

                            if suppress_bouncer:
                                # Store raw log for audit, but do NOT create/publish alerts.
                                _normalize_document_timestamps(log_data)
                                log_data[RAW_RETENTION_ANCHOR_FIELD] = _build_retention_anchor(
                                    log_data.get("timestamp") or log_data.get("ingested_at")
                                )
                                event_uid = log_data.get("event_uid") or str(uuid.uuid4())
                                log_data["event_uid"] = event_uid
                                try:
                                    await db.logs.update_one({"event_uid": event_uid}, {"$set": log_data}, upsert=True)
                                except Exception as e:
                                    logger.error(f"[SIEM][DB] raw log insert failed for suppressed {message_id}: {e}")
                                ack_ids.append(message_id)
                                logger.info(f"[BOUNCER] Raw log stored; alert suppressed for {event_id} tenant {tenant_id}")
                                continue

                            alert_triggered = False
                            alert_type = "GENERIC_SECURITY_EVENT"
                            severity = "INFO"

                            # �️ MANDATE 5: TENANT PLAN ENFORCEMENT (Resource Isolation)
                            # Skip Threat Intel and Stateful Correlation for "basic" plans
                            is_basic_plan = (plan.lower() == "basic")

                            # 🛑 MANDATE 1: THREAT INTEL ENGINE (Immediate Drop/Alert)
                            if not is_basic_plan:
                                ti_config = config.get("threat_intelligence", {})
                                if ti_config.get("enabled") and source_ip in siem_engine.blacklisted_ips:
                                    alert_triggered = True
                                    alert_type = "MALICIOUS_IP_DETECTED"
                                    severity = "CRITICAL"

                            # 🔍 MANDATE 2: DYNAMIC KEYWORD SCANNER (WAF/LINUX/EDR)
                            if not alert_triggered and not is_basic_plan:
                                for source_type, s_config in config.get("source_classification", {}).items():
                                    severity_map = s_config.get("severity_by_keyword", {})
                                    for keyword, mapped_sev in severity_map.items():
                                        if keyword.lower() in raw_msg:
                                            alert_triggered = True
                                            alert_type = f"{source_type.upper()}_KEYWORD_MATCH"
                                            severity = mapped_sev
                                            break
                                    if alert_triggered:
                                        break

                            # 🛡️ MANDATE 3: WINDOWS EVENT MAPPING (Stateful/Stateless)
                            win_config = config.get("source_classification", {}).get("Windows-Sec", {})
                            if not alert_triggered and not is_basic_plan and event_id in map(str, win_config.get("trigger_event_ids", [])):
                                # Check False Positive Tuning (e.g. 4624 Logon Types)
                                fp_tuning = win_config.get("false_positive_tuning", {}).get(event_id, {})
                                allowed_logon_types = fp_tuning.get("allowed_logon_types", [])

                                trigger_event = True
                                if allowed_logon_types and "logon_type" in processed:
                                    if processed.get("logon_type") not in allowed_logon_types:
                                        trigger_event = False

                                if trigger_event:
                                    severity = win_config.get("severity_by_event_id", {}).get(event_id, "MEDIUM")
                                    alert_triggered = True
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
                                        alert_uid = c_alert.get("alert_uid", f"corr_{tenant_id}_{event_id}_{int(time.time()*1000)}")
                                        c_alert["alert_uid"] = alert_uid
                                        try:
                                            await db.security_alerts.update_one({"alert_uid": alert_uid}, {"$set": c_alert}, upsert=True)
                                            await redis.publish("security_alerts", json_dumps(c_alert))
                                            logger.info(f"[CORR ALERT] {c_alert['severity']}: {c_alert['summary']}")
                                        except Exception as corr_db_err:
                                            logger.error(f"[CORR][DB] Failed to persist correlation alert: {corr_db_err}")
                                    # Skip the unified corr block below since we already ran it here
                                    corr_alerts_already_run = True

                            # 🏷️ MANDATE 4: ALERT NAMING ENFORCEMENT (Config Map)
                            title_map = config.get("alert_title_map", {})
                            display_title = title_map.get(alert_type, f"Security Event: {alert_type}")

                            if alert_triggered:
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
                                    "message": raw_message,
                                    "raw_message": raw_message,
                                    "timestamp": log_data["ingested_at"],
                                    "_retention_ts": datetime.now(timezone.utc),
                                }
                                _normalize_document_timestamps(alert_payload)
                                # Save to security_alerts collection
                                try:
                                    await db.security_alerts.update_one({"alert_uid": alert_payload["alert_uid"]}, {"$set": alert_payload}, upsert=True)
                                except Exception as e:
                                    logger.error(f"[SIEM][DB] alert insert failed for {message_id}: {e}")

                                # Publish to redis for live websocket dashboard
                                await redis.publish("security_alerts", json_dumps(alert_payload))

                                logger.info(f"[!] ALERT: {display_title} for {tenant_id}")

                            # 🧠 ADVANCED SIEM ENGINE (Regex, Phishing, Event Map)
                            if not is_basic_plan and not alert_triggered:
                                findings = await siem_engine.analyze_single_log(log_data)
                                for finding in findings:
                                    finding["tenant_id"] = tenant_id
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

                                    if not finding.get("message"):
                                        finding["message"] = raw_message

                                    _normalize_document_timestamps(finding)
                                    finding["_retention_ts"] = datetime.now(timezone.utc)
                                    finding["alert_uid"] = f"adv_{tenant_id}_{finding.get('event_uid', message_id)}_{int(time.time()*1000)}"
                                    try:
                                        await db.security_alerts.update_one({"alert_uid": finding["alert_uid"]}, {"$set": finding}, upsert=True)
                                    except Exception as e:
                                        logger.error(f"[SIEM][DB] finding insert failed for {message_id}: {e}")

                                    # Publish to redis for live websocket dashboard
                                    await redis.publish("security_alerts", json_dumps(finding))

                                    logger.info(f"[!] ADVANCED ALERT: {finding['summary']} for {tenant_id}")

                            # ⚡ CORRELATION ENGINE (Stateful Redis-backed multi-event rules)
                            # Only run if not already run inside the Windows event block above
                            if not is_basic_plan and not locals().get("corr_alerts_already_run", False):
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
                                    corr_alert["alert_uid"] = corr_alert.get("alert_uid", f"corr_adv_{tenant_id}_{corr_alert.get('event_uid', message_id)}_{int(time.time()*1000)}")
                                    try:
                                        await db.security_alerts.update_one({"alert_uid": corr_alert["alert_uid"]}, {"$set": corr_alert}, upsert=True)
                                        await redis.publish("security_alerts", json_dumps(corr_alert))
                                        logger.info(f"[CORR] ALERT: {corr_alert['type']} | {corr_alert['severity']} | {tenant_id}")
                                    except Exception as corr_err:
                                        logger.error(f"[CORR] Failed to save correlation alert: {corr_err}")

                            # Save the raw log for historical auditing
                            _normalize_document_timestamps(log_data)
                            log_data[RAW_RETENTION_ANCHOR_FIELD] = _build_retention_anchor(
                                log_data.get("timestamp") or log_data.get("ingested_at")
                            )
                            event_uid = log_data.get("event_uid") or str(uuid.uuid4())
                            log_data["event_uid"] = event_uid
                            try:
                                await db.logs.update_one({"event_uid": event_uid}, {"$set": log_data}, upsert=True)
                            except Exception as e:
                                logger.error(f"[SIEM][DB] raw log insert failed for {message_id}: {e}")
                                continue

                            # Ack only after all DB writes for this message succeed.
                            ack_ids.append(message_id)

                        except Exception as e:
                            logger.error(f"Processing Error for {message_id}: {e}")
                            # Eject to DLQ instead of silently losing the message
                            try:
                                await _eject_to_dlq(message_id, payload.get("payload", ""), f"PROCESSING_EXCEPTION: {e}")
                            except Exception as dlq_err:
                                logger.error(f"[DLQ] Failed to eject {message_id}: {dlq_err}")

                    # Batch Acknowledge
                    if ack_ids:
                        async with redis.pipeline(transaction=True) as pipe:
                            for mid in ack_ids:
                                await pipe.xack(RAW_LOGS_QUEUE, SIEM_GROUP, mid)
                            await pipe.execute()

            except Exception as e:
                error_msg = str(e)
                if "NOGROUP" in error_msg:
                    # Self-Healing Pipeline: If db was flushed, automatically rebuild the stream
                    try:
                        await redis.xgroup_create(RAW_LOGS_QUEUE, SIEM_GROUP, mkstream=True)
                        logger.info("[SIEM-CORE] Auto-Healed NOGROUP missing stream.")
                    except Exception:
                        pass
                else:
                    logger.error(f"[SIEM-CORE] Pipeline Crash: {e}")
                await asyncio.sleep(1)
    finally:
        try:
            threat_listener_task.cancel()
            await asyncio.gather(threat_listener_task, return_exceptions=True)
        except Exception:
            pass
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
import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from redis import exceptions as redis_exceptions
from redis.asyncio import Redis
from app.config.config import get_settings
from app.utils.tenant_cache import get_tenant_plan
from app.utils.siem_logic import SIEMEngine

# 🏗️ MASTER BUILD: SIEM Universal Rule Engine (Dynamic Config Enforcement)
# Strictly Decoupled, Config-Driven logic (No Hardcodes)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SIEM-CORE] %(message)s")
logger = logging.getLogger("SIEM-Worker")

settings = get_settings()
RAW_LOGS_QUEUE = "raw_logs_queue"
SIEM_GROUP = "siem_group"
SIEM_CONSUMER = "siem_consumer_1"
RECLAIM_MIN_IDLE_MS = 60000
RECLAIM_BATCH_SIZE = 50
RAW_RETENTION_ANCHOR_FIELD = "_retention_ts"

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

    event_map = config.get("event_id_map", {})
    rule = event_map.get(event_id, {})
    event_type = rule.get("event_type")
    if not event_type:
        return None

    meaning = _humanize_event_type(event_type)
    return meaning if meaning else None


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


async def reclaim_stale_messages(redis_client: Redis):
    """Best-effort reclaim for stale pending stream entries."""
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
    1. Threat Intel Check (Malicious IPs)
    2. Dynamic Keyword Scanner (WAF/Linux/EDR)
    3. Windows Event Mapping (Config-Driven)
    4. Alert Title Mapping (Frontend Consistency)
    """
    config = load_dynamic_config()
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    redis = await Redis.from_url(settings.redis_url, decode_responses=True)

    siem_engine = SIEMEngine(config)
    siem_engine.set_redis_client(redis)

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
    
    while True:
        try:
            # Hot-Reload Config every 10 seconds for real-time rule tuning
            if time.time() - last_config_load > 60:
                config = load_dynamic_config()
                siem_engine.refresh_config(config) # Full engine re-initialization
                last_config_load = time.time()

            streams = await redis.xreadgroup(SIEM_GROUP, SIEM_CONSUMER, {RAW_LOGS_QUEUE: ">"}, count=50, block=2000)
            if not streams:
                reclaimed_messages = await reclaim_stale_messages(redis)
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
                                logger.error(f"[POISON PILL] Permanent JSON parse failure for SIEM message {message_id}. Discarding.")
                                ack_ids.append(message_id) # Acknowledge so it's removed from Redis
                                continue
                        
                        tenant_id = log_data.get("tenant_id")

                        # 🔍 0. Plan Verification
                        plan = await get_tenant_plan(redis, tenant_id)
                        
                        # 🏷️ 1. Global Normalization
                        api_now = datetime.now(timezone.utc)
                        log_data["ingested_at"] = api_now.isoformat()
                        _normalize_document_timestamps(log_data)
                        event_id = str(log_data.get("event_id", ""))
                        event_id_meaning = _resolve_event_id_meaning(config, event_id)
                        raw_message = str(log_data.get("message") or "").strip() or "Unknown Event"
                        log_data["raw_message"] = raw_message
                        if event_id_meaning:
                            log_data["event_id_meaning"] = event_id_meaning

                        processed = log_data.get("processed_data") or {}
                        source_ip = processed.get("source_network_address") or log_data.get("source_ip")
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
                            try:
                                await db.logs.insert_one(log_data)
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
                                if alert_triggered: break

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

                            # STATEFUL: Brute Force Correlation (Config Hardened)
                            # SKIPPED FOR BASIC PLANS
                            if event_id == "4625" and source_ip and not is_basic_plan:
                                corr_key = f"warsoc:corr:{tenant_id}:{source_ip}:4625"
                                count = await redis.incr(corr_key)
                                if count == 1: await redis.expire(corr_key, 60)
                                if count >= 5:
                                    alert_type = "High-velocity brute force attack detected"
                                    severity = "CRITICAL"
                                    alert_triggered = (count == 5) # Trigger once per threshold

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
                                "source_ip": source_ip,
                                "message": raw_message,
                                "raw_message": raw_message,
                                "timestamp": log_data["ingested_at"],
                                "_retention_ts": datetime.now(timezone.utc),
                            }
                            _normalize_document_timestamps(alert_payload)
                            # Save to security_alerts collection
                            try:
                                await db.security_alerts.insert_one(alert_payload)
                            except Exception as e:
                                logger.error(f"[SIEM][DB] alert insert failed for {message_id}: {e}")
                                raise
                            
                            # Publish to redis for live websocket dashboard
                            await redis.publish("security_alerts", json.dumps(alert_payload, default=str))
                            
                            logger.info(f"[!] ALERT: {display_title} for {tenant_id}")

                        # 🧠 ADVANCED SIEM ENGINE (Regex, Phishing, Event Map)
                        if not is_basic_plan and not alert_triggered:
                            findings = await siem_engine.analyze_single_log(log_data)
                            for finding in findings:
                                finding["tenant_id"] = tenant_id
                                if not finding.get("event_id") and event_id:
                                    finding["event_id"] = event_id

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
                                try:
                                    await db.security_alerts.insert_one(finding)
                                except Exception as e:
                                    logger.error(f"[SIEM][DB] finding insert failed for {message_id}: {e}")
                                    raise
                                
                                # Publish to redis for live websocket dashboard
                                await redis.publish("security_alerts", json.dumps(finding, default=str))
                                
                                logger.info(f"[!] ADVANCED ALERT: {finding['summary']} for {tenant_id}")

                        # Save the raw log for historical auditing
                        _normalize_document_timestamps(log_data)
                        log_data[RAW_RETENTION_ANCHOR_FIELD] = _build_retention_anchor(
                            log_data.get("timestamp") or log_data.get("ingested_at")
                        )
                        try:
                            await db.logs.insert_one(log_data)
                        except Exception as e:
                            logger.error(f"[SIEM][DB] raw log insert failed for {message_id}: {e}")
                            continue

                        # Ack only after all DB writes for this message succeed.
                        ack_ids.append(message_id)

                    except Exception as e:
                        logger.error(f"Processing Error: {e}")
                
                # Batch Acknowledge
                if ack_ids:
                    async with redis.pipeline(transaction=True) as pipe:
                        for mid in ack_ids: await pipe.xack(RAW_LOGS_QUEUE, SIEM_GROUP, mid)
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

if __name__ == "__main__":
    try:
        asyncio.run(siem_worker())
    except KeyboardInterrupt:
        logger.info("WarSOC SIEM offline.")
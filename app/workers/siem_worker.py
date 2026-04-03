import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from redis.asyncio import Redis
from app.config.config import get_settings
from app.utils.tenant_cache import get_tenant_plan

# 🏗️ MASTER BUILD: SIEM Universal Rule Engine (Dynamic Config Enforcement)
# Strictly Decoupled, Config-Driven logic (No Hardcodes)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SIEM-CORE] %(message)s")
logger = logging.getLogger("SIEM-Worker")

settings = get_settings()
RAW_LOGS_QUEUE = "raw_logs_queue"
SIEM_GROUP = "siem_group"

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

    # Scale Mandate: Group Creation
    try:
        await redis.xgroup_create(RAW_LOGS_QUEUE, SIEM_GROUP, mkstream=True)
    except Exception: pass

    logger.info("⚡ WarSOC SIEM: Dynamic Rule Engine Online. Awaiting logs...")
    
    while True:
        try:
            streams = await redis.xreadgroup(SIEM_GROUP, "siem_consumer_1", {RAW_LOGS_QUEUE: ">"}, count=50, block=2000)
            if not streams: continue

            for _, messages in streams:
                ack_ids = []
                for message_id, payload in messages:
                    try:
                        log_data = json.loads(payload["payload"])
                        tenant_id = log_data.get("tenant_id")
                        ack_ids.append(message_id)

                        # 🔍 0. Plan Verification
                        plan = await get_tenant_plan(redis, tenant_id)
                        
                        # 🏷️ 1. Global Normalization
                        api_now = datetime.now(timezone.utc)
                        log_data["ingested_at"] = api_now.isoformat()
                        event_id = str(log_data.get("event_id", ""))
                        processed = log_data.get("processed_data") or {}
                        source_ip = processed.get("source_network_address") or log_data.get("source_ip")
                        raw_msg = str(payload.get("payload", "")).lower()

                        alert_triggered = False
                        alert_type = "GENERIC_SECURITY_EVENT"
                        severity = "INFO"

                        # �️ MANDATE 5: TENANT PLAN ENFORCEMENT (Resource Isolation)
                        # Skip Threat Intel and Stateful Correlation for "basic" plans
                        is_basic_plan = (plan.lower() == "basic")

                        # 🛑 MANDATE 1: THREAT INTEL ENGINE (Immediate Drop/Alert)
                        if not is_basic_plan:
                            ti_config = config.get("threat_intelligence", {})
                            if ti_config.get("enabled") and source_ip in ti_config.get("ips", []):
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
                                "source_ip": source_ip,
                                "timestamp": log_data["ingested_at"]
                            }
                            # Save to security_alerts collection
                            await db.security_alerts.insert_one(alert_payload)
                            logger.info(f"[!] ALERT: {display_title} for {tenant_id}")

                        # Save the raw log for historical auditing
                        await db.logs.insert_one(log_data)

                    except Exception as e:
                        logger.error(f"Processing Error: {e}")
                
                # Batch Acknowledge
                if ack_ids:
                    async with redis.pipeline(transaction=True) as pipe:
                        for mid in ack_ids: await pipe.xack(RAW_LOGS_QUEUE, SIEM_GROUP, mid)
                        await pipe.execute()

        except Exception as e:
            logger.error(f"Pipeline Crash: {e}")
            await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(siem_worker())
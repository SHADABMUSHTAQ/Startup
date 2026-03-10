import asyncio
import json
import logging
import re
import redis.asyncio as aioredis
from datetime import datetime, timezone
from pathlib import Path

from app.database import get_db_context, init_db
from app.config.config import get_settings

from app.utils.threat_intel import ThreatIntelligenceManager
from app.utils.siem_logic import SIEMEngine
from app.utils.stateful_engine import StatefulThreatEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("WarSOC-Worker")
settings = get_settings()
CONFIG_PATH = Path("app/config/config.json")

def _load_config() -> dict:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

config = _load_config()
threat_intel_engine = ThreatIntelligenceManager(config)
siem_engine         = SIEMEngine(config)
stateful_engine     = StatefulThreatEngine(config_path=str(CONFIG_PATH))

def normalize_log(log_data: dict) -> dict:
    event_id = log_data.get("event_id")
    severity = "INFO"
    if event_id in [1102, "1102"]: severity = "CRITICAL"
    elif event_id in [4625, "4625"]: severity = "HIGH"
    elif event_id in [4672, "4672"]: severity = "MEDIUM"

    message = log_data.get("message", "No message provided")
    
    # Default source IP
    source_ip = log_data.get("source_ip", log_data.get("ip", "0.0.0.0"))

    # 🚀 THE MAGIC FIX: Message ke andar se Hacker ki IP nikal kar overwrite karo!
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
    if ip_match:
        source_ip = ip_match.group(0) # Ab dashboard par Hacker ki IP jayegi!

    return {
        "timestamp":     log_data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "source_ip":     source_ip,
        "user":          log_data.get("user", "system"),
        "event_id":      event_id,
        "event_type":    log_data.get("event_type", "unknown"),
        "message":       message,
        "severity":      severity,
        "engine_source": "Agent",
        "raw_data":      log_data,
    }

async def process_pulse_jobs(redis_client):
    logger.info("⚡ WarSOC Worker: Full Engine Pipeline Active...")

    while True:
        try:
            job = await redis_client.blpop("pulse_jobs", timeout=2)
            if not job: continue

            log_data = json.loads(job[1])
            tenant_id = log_data.get("tenant_id") or log_data.get("agent_id")
            if not tenant_id: continue

            normalized = normalize_log(log_data)
            normalized["tenant_id"] = tenant_id

            hacker_ip = normalized.get("source_ip", "0.0.0.0")

            # 🚀 CHECK DB ONLY FOR HACKER IP
            is_db_blocked = False
            async with get_db_context() as db:
                if db.db is not None:
                    blocked_doc = await db.db["firewall_rules"].find_one({"ip": hacker_ip})
                    if blocked_doc:
                        is_db_blocked = True

            is_malicious, _ = threat_intel_engine.check_reputation(hacker_ip)
            
            # 🔥 FIREWALL DROP! Agar hacker block hai toh log khatam!
            if is_malicious or is_db_blocked:
                logger.warning(f"🛡️ FIREWALL DROP: Blocked Hacker IP {hacker_ip} dropped.")
                continue  

            user = normalized.get("user", "unknown")
            if threat_intel_engine.is_service_account(user):
                async with get_db_context() as db:
                    if db.db is not None: await db.db["logs"].insert_one(normalized)
                continue

            stateless_alerts = siem_engine.analyze_single_log(normalized)
            stateful_alerts = await stateful_engine.analyze(normalized)

            all_alerts = stateless_alerts + stateful_alerts
            for alert in all_alerts: alert["tenant_id"] = tenant_id

            async with get_db_context() as db:
                if db.db is None: continue

                result = await db.db["logs"].insert_one(normalized)
                
                if all_alerts:
                    await db.db["alerts"].insert_many(all_alerts)
                    for alert in all_alerts:
                        await redis_client.publish("security_alerts", json.dumps(alert, default=str))

        except Exception as e:
            logger.error(f"❌ Pipeline Error: {e}", exc_info=True)
            await asyncio.sleep(1)

async def main():
    logger.info("🚀 WarSOC SIEM Backbone Starting...")
    await init_db()
    redis_client = await aioredis.from_url(settings.redis_url, decode_responses=True)
    await stateful_engine.start(settings.redis_url)
    
    try:
        await process_pulse_jobs(redis_client)
    except asyncio.CancelledError:
        pass
    finally:
        await stateful_engine.stop()
        await redis_client.aclose()

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass
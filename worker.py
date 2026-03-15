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
_LOCAL_IPS = {"127.0.0.1", "0.0.0.0", "::1", "localhost"}
_IP_IN_TEXT_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

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

def extract_source_ip_from_message(message: str):
    """Best-effort extraction of remote IPv4 from raw log text."""
    if not message:
        return None
    for ip in _IP_IN_TEXT_PATTERN.findall(message):
        if ip not in _LOCAL_IPS:
            return ip
    return None

def normalize_log(log_data: dict) -> dict:
    event_id = log_data.get("event_id")
    message = log_data.get("message", "No message provided")
    # Use agent-reported source IP, don't overwrite from message body
    source_ip = log_data.get("source_ip", log_data.get("ip", "0.0.0.0"))
    if str(source_ip).lower() in _LOCAL_IPS:
        extracted_ip = extract_source_ip_from_message(message)
        if extracted_ip:
            source_ip = extracted_ip

    # Load event_id to event_type and severity mapping strictly from config.json
    event_id_map = config.get("event_id_map", {})
    eid = str(event_id) if event_id else ""
    event_type = log_data.get("event_type", "unknown")
    severity = "INFO"
    if event_type == "unknown" and eid in event_id_map:
        event_type = event_id_map[eid]["event_type"]
        severity = event_id_map[eid]["severity"]
    else:
        msg_lower = message.lower()
        if event_type == "unknown":
            if any(k in msg_lower for k in ["get /", "post /", "put /", "delete /", "http/"]):
                event_type = "http_request"
            elif "404" in msg_lower:
                event_type = "http_404"
            elif "500" in msg_lower:
                event_type = "http_500"

    return {
        "timestamp":     log_data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "source_ip":     source_ip,
        "user":          log_data.get("user", "system"),
        "event_id":      event_id,
        "event_type":    event_type,
        "message":       message,
        "severity":      severity,
        "engine_source": "Agent",
        "raw_data":      log_data,
    }

async def process_pulse_jobs(redis_client):
    logger.info("⚡ WarSOC Worker: Full Engine Pipeline Active...")

    while True:
        try:
            job = await redis_client.blpop("pulse_jobs", timeout=1)
            if not job: continue

            log_data = json.loads(job[1])
            tenant_id = log_data.get("tenant_id") or log_data.get("agent_id")
            if not tenant_id: continue

            normalized = normalize_log(log_data)
            normalized["tenant_id"] = tenant_id

            hacker_ip = normalized.get("source_ip", "0.0.0.0")

            # 🚀 CHECK DB ONLY FOR HACKER IP (tenant-isolated)
            is_db_blocked = False
            async with get_db_context() as db:
                if db.db is not None:
                    blocked_doc = await db.db["firewall_rules"].find_one({"ip": hacker_ip, "tenant_id": tenant_id})
                    if blocked_doc:
                        is_db_blocked = True

            is_malicious, _ = threat_intel_engine.check_reputation(hacker_ip)
            
            # Log and alert on malicious IPs instead of silently dropping
            if is_malicious or is_db_blocked:
                logger.warning(f"🛡️ THREAT DETECTED: Malicious IP {hacker_ip}")
                normalized["severity"] = "CRITICAL"
                normalized["source"] = "agent"
                threat_alert = {
                    "id": __import__('uuid').uuid4().hex[:12],
                    "type": "THREAT_INTEL_BLOCKED",
                    "severity": "CRITICAL",
                    "summary": f"Blocked malicious IP: {hacker_ip}",
                    "ip": hacker_ip,
                    "user": normalized.get("user", "unknown"),
                    "mitre": "T1071",
                    "timestamp": normalized.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "engine_source": "ThreatIntel",
                    "tenant_id": tenant_id,
                }
                async with get_db_context() as db:
                    if db.db is not None:
                        await db.db["logs"].insert_one(normalized)
                        await db.db["security_alerts"].insert_one(threat_alert)
                        await redis_client.publish("security_alerts", json.dumps(threat_alert, default=str))
                continue

            user = normalized.get("user", "unknown")
            if threat_intel_engine.is_service_account(user):
                async with get_db_context() as db:
                    normalized["source"] = "agent"
                    if db.db is not None: await db.db["logs"].insert_one(normalized)
                continue

            stateless_alerts = siem_engine.analyze_single_log(normalized)
            stateful_alerts = await stateful_engine.analyze(normalized)

            all_alerts = stateless_alerts + stateful_alerts
            for alert in all_alerts: alert["tenant_id"] = tenant_id

            async with get_db_context() as db:
                if db.db is None: continue

                normalized["source"] = "agent"
                result = await db.db["logs"].insert_one(normalized)
                
                if all_alerts:
                    await db.db["security_alerts"].insert_many(all_alerts)
                    for alert in all_alerts:
                        await redis_client.publish("security_alerts", json.dumps(alert, default=str))
                    logger.info(f"🔥 [{tenant_id}] {len(all_alerts)} alert(s): {[a['type'] for a in all_alerts]}")
                else:
                    logger.info(f"📋 [{tenant_id}] Log processed (no alerts): {normalized.get('event_type', 'unknown')}")

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
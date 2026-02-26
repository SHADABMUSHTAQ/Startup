import os
import sys
import json
import asyncio
from datetime import datetime, timezone
import redis.asyncio as aioredis

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database import get_db_context, init_db
from app.config.config import get_settings, load_config
from app.utils.siem_logic import SIEMEngine
from app.utils.stateful_engine import StatefulThreatEngine

# 🔐 ENV COMPLIANCE: Loading settings from your .env via the config helper
settings = get_settings()
config_data = load_config()

stateless_engine = SIEMEngine(config_data)
stateful_engine = StatefulThreatEngine("app/config/config.json")

def normalize_log(raw_job: dict) -> dict:
    original_msg = str(raw_job.get("raw_message", raw_job.get("message", "")))
    src_ip = raw_job.get("source_ip", raw_job.get("ip_address", raw_job.get("hostname", "0.0.0.0")))
    event_id = raw_job.get("event_id")

    return {
        "timestamp": raw_job.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "source_ip": src_ip,
        "user": raw_job.get("user", "unknown"),
        "event_id": event_id,
        "message": original_msg,
        "raw_data": raw_job 
    }

async def process_pulse_jobs(r):
    print("⚡ WarSOC Worker: Atomic Pipeline Active...")
    while True:
        try:
            job = await r.blpop("pulse_jobs", timeout=1)
            if not job: continue

            log_data = json.loads(job[1])
            
            # 🔐 ENV COMPLIANCE: Extracting identity keys dynamically
            tenant_id = log_data.get("tenant_id") or log_data.get("agent_id")
            
            if not tenant_id:
                print(f"⚠️ Dropped log: Missing identity keys")
                continue

            normalized = normalize_log(log_data)
            normalized["tenant_id"] = tenant_id 
            
            # 2. Compliance: Permanent Raw Storage
            async with get_db_context() as db:
                if db.db is not None:
                    try:
                        # 🚨 SURGICAL FIX: Points to 'logs' collection as per your screenshot
                        result = await db.db["logs"].insert_one(normalized)
                        if "_id" in normalized: del normalized["_id"]
                    except Exception as db_err:
                        print(f"[❌] MongoDB Insert Failed: {db_err}")
                else:
                    # 🔐 ENV COMPLIANCE: Referencing DB name from settings
                    print(f"[❌] CRITICAL: Connection to {settings.db_name} failed!")

            # 3. Security Analysis
            stateless_alerts = stateless_engine.analyze_single_log(normalized)
            stateful_alerts = await stateful_engine.analyze(normalized)

            for alert in (stateless_alerts + stateful_alerts):
                title = alert.get("summary", alert.get("title", "Threat Detected"))
                ip = alert.get("source_ip", alert.get("ip", "0.0.0.0"))
                
                safe_title = title.replace(" ", "_").lower()
                dedup_key = f"alert_lock:{tenant_id}:{safe_title}:{ip}" 
                
                is_unique = await r.set(dedup_key, "active", ex=60, nx=True)
                if not is_unique: continue 

                alert_payload = {
                    "tenant_id": tenant_id, 
                    "severity": alert.get("severity", "MEDIUM"),
                    "title": title,
                    "source_ip": ip,
                    "mitre": alert.get("mitre", "T1000"),
                    "engine_source": alert.get("engine_source", "Stateless"),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                async with get_db_context() as db:
                    if db.db is not None:
                        # 🚨 SURGICAL FIX: Points to 'security_alerts' collection
                        await db.db["security_alerts"].insert_one(alert_payload)
                        if "_id" in alert_payload: del alert_payload["_id"]

                await r.publish("security_alerts", json.dumps(alert_payload))

        except Exception as e:
            print(f"❌ Pipeline Error: {e}")
            await asyncio.sleep(1)

async def main():
    await init_db()
    try: 
        # 🔐 ENV COMPLIANCE: Using Redis URL from settings
        await stateful_engine.start(settings.redis_url)
    except Exception as e: 
        print(f"⚠️ Stateful Engine degraded: {e}")
        
    # 🔐 ENV COMPLIANCE: Using Redis URL from settings
    r = await aioredis.from_url(settings.redis_url, decode_responses=True)
    try: 
        await process_pulse_jobs(r)
    except KeyboardInterrupt: 
        print("\n🛑 Shutting down WarSOC Workers...")
    finally: 
        await r.close()

if __name__ == "__main__":
    asyncio.run(main())
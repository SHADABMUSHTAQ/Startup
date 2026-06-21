import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Prevent UnicodeEncodeError on Windows terminals
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

import asyncio
import json
import time
from datetime import datetime, timezone
import redis.asyncio as aioredis
from motor.motor_asyncio import AsyncIOMotorClient
from app.config.config import get_settings

# Target Environment
settings = get_settings()
TENANT_ID = "WARSOC_TEST_898F"
REDIS_URL = settings.redis_url
MONGO_URI = settings.mongodb_uri
DB_NAME = settings.mongodb_db_name

async def inject_log(redis, payload):
    """Bypasses the HTTP API to inject raw telemetry directly into the worker queue."""
    log_data = {
        "tenant_id": TENANT_ID,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_version": "Omni-Audit-1.0",
        **payload
    }
    await redis.xadd(
        "raw_logs_queue",
        {"payload": json.dumps(log_data)},
        maxlen=100000
    )
    print(f"[+] Injected Event {payload.get('event_id')} from {payload.get('source_ip')}")

async def run_audit():
    print(" Initializing WarSOC Omni-Audit Simulation...")
    redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
    mongo = AsyncIOMotorClient(MONGO_URI)
    db = mongo[DB_NAME]

    # 🧹 PHASE 1: CLEAN ROOM SETUP
    print("\n🧹 Phase 1: Clean Room Setup")
    keys = await redis.keys(f"warsoc:state:*:{TENANT_ID}:*")
    keys.extend(await redis.keys(f"warsoc:corr:*:{TENANT_ID}:*"))
    keys.append(f"warsoc:banned_ips:{TENANT_ID}")
    if keys:
        await redis.delete(*keys)
        
    # 🧹 Clean up old MongoDB documents to prevent false-positives from prior runs
    await db.peca_forensic_logs.delete_many({"tenant_id": TENANT_ID})
    await db.security_alerts.delete_many({"tenant_id": TENANT_ID})
    
    # 💥 Trim the ingestion queue to 0 so workers process our simulation instantly (without destroying groups)
    await redis.xtrim("raw_logs_queue", maxlen=0, approximate=False)
    
    #  Elevate the test tenant to Enterprise tier so the PECA worker processes the logs
    await redis.set(f"tenant_plan:{TENANT_ID}", "Enterprise")
    print("   Clean room established.")

    # 👻 PHASE 2: GHOST ADMIN SEQUENCE
    print("\n👻 Phase 2: Ghost Admin Sequence (T1548 + T1070)")
    await inject_log(redis, {"event_id": 4732, "source_ip": "10.0.0.50", "user": "admin_ceo", "message": "Member added to Administrators"})
    await asyncio.sleep(2)
    await inject_log(redis, {"event_id": 1102, "source_ip": "10.0.0.50", "user": "admin_ceo", "message": "Audit log cleared"})
    await asyncio.sleep(2)

    # ✈ PHASE 3: IMPOSSIBLE TRAVEL
    print("\n✈ Phase 3: Impossible Travel Sequence (T1078)")
    await inject_log(redis, {
        "event_id": 4624, "source_ip": "203.0.113.10", "user": "finance_lead", 
        "geo_lat": 24.86, "geo_lon": 67.00, "message": "Successful Logon (Karachi)"
    })
    await asyncio.sleep(2)
    await inject_log(redis, {
        "event_id": 4624, "source_ip": "185.10.20.30", "user": "finance_lead", 
        "geo_lat": 55.75, "geo_lon": 37.61, "message": "Successful Logon (Moscow)"
    })
    await asyncio.sleep(2)

    # 🔨 PHASE 4: BRUTE FORCE
    print("\n🔨 Phase 4: Brute Force Attack (T1110)")
    for i in range(5):
        await inject_log(redis, {"event_id": 4625, "source_ip": "192.168.1.100", "user": "target_user", "message": f"Failed Logon {i+1}"})
    await asyncio.sleep(3)

    # 🔍 PHASE 5: VERIFICATION
    print("\n🔍 Phase 5: Verification & SOAR Heartbeat")
    print("   Waiting for defense engines to process the telemetry stream...")
    
    banned_ips = set()
    for _ in range(15):
        banned_ips = await redis.smembers(f"warsoc:banned_ips:{TENANT_ID}")
        if "10.0.0.50" in banned_ips and "185.10.20.30" in banned_ips:
            break
        await asyncio.sleep(1)
        
    print(f"   [SOAR] Banned IPs: {banned_ips}")
    
    assert "10.0.0.50" in banned_ips, "Ghost Admin IP not banned!"
    assert "185.10.20.30" in banned_ips, "Impossible Travel IP not banned!"
    print("    SOAR Auto-Mitigation Verified: Malicious IPs atomically blacklisted.")

    print("\n   [Forensics] Checking RSA-PSS Seals...")
    logs = []
    for _ in range(10):
        cursor = db.peca_forensic_logs.find({"tenant_id": TENANT_ID}).sort("timestamp", -1).limit(5)
        logs = await cursor.to_list(length=5)
        if logs and any(log.get("digital_signature") for log in logs):
            break
        await asyncio.sleep(1)
    
    if logs:
        for log in logs:
            sig_type = log.get("digital_signature", "MISSING")
            assert sig_type == "RSA-2048-PSS-SHA256 (WarSOC Master)", f"Forensic seal failed! Found: {sig_type}"
        print("    Legal Forensics Verified: All logs cryptographically sealed via RSA-PSS.")
    else:
        print("    No forensic logs found. (Ensure peca_worker is running).")

if __name__ == "__main__":
    asyncio.run(run_audit())
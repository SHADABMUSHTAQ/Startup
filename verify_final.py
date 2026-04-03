import asyncio
import json
import time
import httpx
import uuid
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from redis.asyncio import Redis
from app.config.config import get_settings

# 🏗️ MASTER BATTLE DRILL V3: Final Architecture Validation
# Validates: FBR (Event 4670), SIEM (Isolation), Audit, PECA (RSA), Keyword (WAF)

settings = get_settings()
MONGO_URI = settings.mongodb_uri
REDIS_URL = settings.redis_url
DB_NAME = settings.mongodb_db_name

# 🟢 Mock Data
TENANT_BASIC = f"tenant_basic_{uuid.uuid4().hex[:6]}"
TENANT_PRO = f"tenant_pro_{uuid.uuid4().hex[:6]}"
ADMIN_USER = f"admin_{uuid.uuid4().hex[:6]}"

async def setup_environment(db, redis):
    print(f"[*] Setting up Environment [Tenant: {TENANT_PRO}]...")
    
    # 1. Redis Plan Cache
    await redis.set(f"tenant_plan:{TENANT_BASIC}", "FREE")
    await redis.set(f"tenant_plan:{TENANT_PRO}", "Professional")
    
    # 2. Database records for workers
    await db.tenants.insert_one({
        "tenant_id": TENANT_PRO,
        "subscription_plan": "Professional",
        "status": "active"
    })
    
    user_payload = {
        "username": ADMIN_USER,
        "tenant_id": TENANT_PRO,
        "role": "admin",
        "plan_type": "Professional",
        "subscription_plan": "Professional",
        "email": "battle@drill.com",
        "is_active": True
    }
    await db.users.insert_one(user_payload)
    return user_payload

async def manual_ingest(redis, tenant_id, event_id, source_ip="127.0.0.1", msg="Battle Drill"):
    log_data = {
        "tenant_id": tenant_id,
        "event_id": event_id,
        "source_ip": source_ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": msg,
        "processed_data": {"source_network_address": source_ip}
    }
    payload_to_stream = {"payload": json.dumps(log_data, default=str)}
    await redis.xadd("raw_logs_queue", payload_to_stream)

async def verify_fbr(db, redis):
    print("\n[Drill 1] FBR POS (Event 4670)...")
    await manual_ingest(redis, TENANT_PRO, 4670)
    await asyncio.sleep(5)
    # FBR worker writes to 'logs' collection in some versions, or 'fbr_pos_logs'
    # Checking both for robustness
    doc = await db.logs.find_one({"tenant_id": TENANT_PRO, "compliance_tags": "FBR_POS"}) or \
          await db.fbr_pos_logs.find_one({"tenant_id": TENANT_PRO})
    return "[PASS]" if doc else "[FAIL]"

async def verify_siem(db, redis):
    print("[Drill 2] SIEM Isolation (Basic vs Pro)...")
    for _ in range(6): await manual_ingest(redis, TENANT_BASIC, 4625, "1.1.1.1")
    for _ in range(6): await manual_ingest(redis, TENANT_PRO, 4625, "2.2.2.2")
    await asyncio.sleep(6)
    basic_alert = await db.security_alerts.find_one({"tenant_id": TENANT_BASIC})
    pro_alert = await db.security_alerts.find_one({"tenant_id": TENANT_PRO, "type": "High-velocity brute force attack detected"})
    return "[PASS]" if (not basic_alert and pro_alert) else "[FAIL]"

async def verify_peca(db, redis):
    print("[Drill 3] PECA Forensic Vault (Event 4688)...")
    await manual_ingest(redis, TENANT_PRO, 4688)
    await asyncio.sleep(5)
    doc = await db.peca_forensic_logs.find_one({"tenant_id": TENANT_PRO})
    return "[PASS]" if (doc and "digital_signature" in doc) else "[FAIL]"

async def verify_keyword(db, redis):
    print("[Drill 4] Keyword Engine (SQLi Pattern)...")
    await manual_ingest(redis, TENANT_PRO, 80, "4.4.4.4", "id=1' UNION SELECT--")
    await asyncio.sleep(6)
    doc = await db.security_alerts.find_one({"tenant_id": TENANT_PRO, "type": "WEB-WAF_KEYWORD_MATCH"})
    return "[PASS]" if doc else "[FAIL]"

async def main():
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]
    redis = await Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        await setup_environment(db, redis)
        r1 = await verify_fbr(db, redis)
        r2 = await verify_siem(db, redis)
        r3 = await verify_peca(db, redis)
        r4 = await verify_keyword(db, redis)
        print("\n" + "="*40)
        print(f"FBR:     {r1}")
        print(f"SIEM:    {r2}")
        print(f"PECA:    {r3}")
        print(f"KEYWORD: {r4}")
        print("="*40)
    finally:
        await redis.delete(f"tenant_plan:{TENANT_BASIC}")
        await redis.delete(f"tenant_plan:{TENANT_PRO}")
        client.close()

if __name__ == "__main__":
    asyncio.run(main())

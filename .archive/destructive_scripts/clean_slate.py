import asyncio
import os
import redis.asyncio as aioredis
from motor.motor_asyncio import AsyncIOMotorClient

# ─── WarSOC Live Integration Clean Slate (Phase 1) ───

REDIS_URL = os.environ.get("REDIS_URL", "redis://:W4rS0c_R3d1s_S3cur3_2026!@127.0.0.1:6379")
MONGO_URI = os.environ.get("MONGODB_URI", "mongodb://warsoc_admin:W4rS0c_M0ng0_S3cur3_2026!@127.0.0.1:27017/WarSOC_DB?authSource=admin")
DB_NAME = os.environ.get("MONGODB_DB_NAME", "WarSOC_DB")

async def run_clean_slate():
    print("\n" + "="*50)
    print("🧹 WARSOC PHASE 1: THE CLEAN SLATE")
    print("="*50)
    
    # 1. Flush Redis
    try:
        r = await aioredis.from_url(REDIS_URL, decode_responses=True)
        await r.flushall()
        print("✅ Redis FLUSHALL Complete. Zero Pending Streams.")
    except Exception as e:
        print(f"❌ Redis Flush Failed: {e}")

    # 2. Wipe MongoDB Forensic Vaults
    try:
        client = AsyncIOMotorClient(MONGO_URI)
        db = client[DB_NAME]
        
        await db.logs.delete_many({})
        await db.fbr_pos_logs.delete_many({})
        await db.peca_forensic_logs.delete_many({})
        print("✅ MongoDB Vaults Zeroed (SIEM, FBR, PECA).")
    except Exception as e:
        print(f"❌ MongoDB Wipe Failed: {e}")
        
    # 3. Critical Pre-Flight: Re-seed the Test Tenant
    try:
        await r.set("tenant_plan:WARSOC_TEST", "Enterprise")
        print("✅ Valid Tenant Re-Seeded in Redis Cache (WARSOC_TEST -> Enterprise).")
    except Exception as e:
        print(f"❌ Tenant Seeding Failed: {e}")

    print("\n🚀 Clean Slate Ready. Proceed to Phase 2: The 4-Vector Attack.")

if __name__ == "__main__":
    asyncio.run(run_clean_slate())

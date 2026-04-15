"""
WarSOC Fast Diagnostic - Run this IMMEDIATELY to find the mismatch.
Usage: python scripts/fast_diag.py
"""
import asyncio
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from motor.motor_asyncio import AsyncIOMotorClient
from app.config.config import get_settings
import redis.asyncio as aioredis

async def diagnose():
    settings = get_settings()
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    redis = await aioredis.from_url(settings.redis_url, decode_responses=True)

    print("\n" + "="*60)
    print("  WarSOC FAST DIAGNOSTIC")
    print("="*60)

    # 1. What tenant IDs exist in the users table?
    print("\n[1] USER ACCOUNTS IN DATABASE:")
    async for user in db.users.find({}, {"username":1, "tenant_id":1, "plan_type":1}):
        print(f"    👤 username='{user.get('username')}' → tenant_id='{user.get('tenant_id')}' plan='{user.get('plan_type')}'")

    # 2. What tenant IDs exist in the logs collection?
    print("\n[2] TENANT IDs FOUND IN LOGS COLLECTION:")
    pipeline = [{"$group": {"_id": "$tenant_id", "count": {"$sum": 1}}}]
    async for doc in db.logs.aggregate(pipeline):
        print(f"    📦 tenant_id='{doc['_id']}' → {doc['count']} logs")
    
    count = await db.logs.count_documents({})
    if count == 0:
        print("    ❌ logs collection is EMPTY — SIEM worker not writing to DB!")

    # 3. Redis stream status
    print("\n[3] REDIS STREAM STATUS:")
    try:
        info = await redis.xinfo_stream("raw_logs_queue")
        length = info.get("length", 0)
        print(f"    📮 raw_logs_queue has {length} pending messages")
        if length > 0:
            print(f"    ⚠️  Logs are STUCK IN REDIS — SIEM worker is not consuming them!")
    except Exception as e:
        print(f"    ❌ Stream check failed: {e}")

    # 4. Check Redis consumer groups
    print("\n[4] REDIS CONSUMER GROUPS:")
    try:
        groups = await redis.xinfo_groups("raw_logs_queue")
        for g in groups:
            print(f"    🔗 group='{g.get('name')}' pending={g.get('pending')} lag={g.get('lag', 'N/A')}")
    except Exception as e:
        print(f"    ❌ Group check failed: {e}")

    # 5. Show last 3 logs in db
    print("\n[5] LAST 3 LOGS IN DATABASE:")
    last = await db.logs.find({}).sort("_id", -1).limit(3).to_list(length=3)
    if last:
        for l in last:
            print(f"    🗒️  event_id={l.get('event_id')} tenant='{l.get('tenant_id')}' ts={l.get('timestamp', '')[:19]}")
    else:
        print("    ❌ NO LOGS IN DATABASE AT ALL")

    print("\n" + "="*60)
    print("  COPY THIS OUTPUT AND SHARE IT")
    print("="*60 + "\n")

if __name__ == "__main__":
    asyncio.run(diagnose())

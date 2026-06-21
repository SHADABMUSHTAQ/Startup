import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from redis.asyncio import Redis
from app.config.config import get_settings

async def force_migration():
    """
    WarSOC Global Migration: Standardizing Compliance Logic.
    1. Renames 'fbr_pos_shield' to 'fbr_pos'.
    2. Popluates compliance_packs based on plan_type for all users.
    3. Synchronizes Redis Tenant Cache.
    """
    settings = get_settings()
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    redis = await Redis.from_url(settings.redis_url, decode_responses=True)

    print("[*] Starting Global Compliance Migration...")

    # 1. Update Users Collection
    cursor = db.users.find({})
    async for user in cursor:
        plan = user.get("plan_type", "Free")
        username = user.get("username")
        tenant_id = user.get("tenant_id")
        
        # Determine correct packs
        correct_packs = []
        if plan == "Professional":
            correct_packs = ["peca_forensic"]
        elif plan == "Enterprise":
            correct_packs = ["peca_forensic", "fbr_pos"]
        
        # Atomic Update
        await db.users.update_one(
            {"username": username},
            {"$set": {"compliance_packs": correct_packs}}
        )
        
        # 2. Sync Redis Cache
        if tenant_id:
            await redis.set(f"tenant_plan:{tenant_id}", plan)
        
        print(f"[+] Migrated User: {username} | Plan: {plan} | Packs: {correct_packs}")

    # 3. Update Tenants Collection
    await db.tenants.update_many(
        {"plan": {"$in": ["Professional", "Enterprise"]}},
        {"$set": {"status": "active"}}
    )

    print(" Global Migration Complete. WarSOC Identity State is now Synchronized.")

if __name__ == "__main__":
    asyncio.run(force_migration())

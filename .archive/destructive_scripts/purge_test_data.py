import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient

# 🧹 WarSOC Production Purge: Final Sanitization
# Goal: Remove all non-admin and non-enterprise users created during testing/audit phase.

MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://warsoc_admin:W4rS0c_M0ng0_S3cur3_2026!@127.0.0.1:27017/WarSOC_DB?authSource=admin")
DB_NAME = os.environ.get("MONGODB_DB_NAME", "WarSOC_DB")

# Users we MUST keep
KEEP_LIST = ["warsoc_admin", "hamza"] 

async def purge_ghost_accounts():
    print(f"\n🗑️ Starting WarSOC Production Purge (DB: {DB_NAME})")
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]
    
    # 1. Purge Ghost Users
    print("[*] Filtering Users collection...")
    users_coll = db["users"]
    
    # Identify users to delete (those not in keep list and not specifically 'Professional' or 'Enterprise' if we want to be safe)
    # But usually, test users have names like 'testuser_', 'u_', 'pop', etc.
    # We will delete users where username matches a 'test' pattern or is not in our known list.
    
    deleted_count = 0
    async for user in users_coll.find({"username": {"$nin": KEEP_LIST}}):
        username = user.get("username", "Unknown")
        # Selective purge: only delete if it looks like a generated test user or is part of the 'Free' plan debris
        if "test" in username.lower() or "u_" in username or user.get("plan") == "Free" or username in ["pop", "lop", "popla1", "Debug User"]:
            print(f" [DELETE] Ghost User: {username} (Plan: {user.get('plan')})")
            await users_coll.delete_one({"_id": user["_id"]})
            deleted_count += 1
            
    print(f"\n✅ Sanitization Complete: {deleted_count} ghost accounts purged.")
    print("[!] MANDATORY: Please run 'python scripts/final_cleanup.py' next to remove file debris.")

if __name__ == "__main__":
    asyncio.run(purge_ghost_accounts())

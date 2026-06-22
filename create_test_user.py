import asyncio
from app.database import get_db, db_manager
from app.routes.auth import get_password_hash
from datetime import datetime, timezone

async def main():
    email = "testuser@warsoc.local"
    password = "TestPassword123!"
    tenant_id = "WARSOC_TEST_2"

    await db_manager.connect()
    db = db_manager.db
    
    # Ensure tenant exists with a Free plan
    await db["tenants"].update_one(
        {"tenant_id": tenant_id},
        {"$set": {"plan": "Free", "retention_days": 90, "compliance_packs": []}},
        upsert=True
    )
    
    user = {
        "username": email.split("@")[0],
        "email": email,
        "full_name": "Testing User",
        "hashed_password": get_password_hash(password),
        "tenant_id": tenant_id,
        "plan_type": "Free",
        "role": "admin",
        "compliance_packs": [],
        "has_active_plan": True,
        "created_at": datetime.now(timezone.utc)
    }
    
    await db["users"].delete_one({"email": email})
    await db["users"].insert_one(user)
    print(f"Created test account: {email} / {password}")
    
    await db_manager.close()

if __name__ == "__main__":
    asyncio.run(main())

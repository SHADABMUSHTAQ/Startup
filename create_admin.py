import asyncio
from app.database import get_db, db_manager
from app.routes.auth import get_password_hash
from datetime import datetime, timezone

async def main():
    await db_manager.connect()
    db = db_manager.db
    
    tenant_id = "WARSOC_TEST_1"
    admin_email = "admin@warsoc.local"
    
    # ensure tenant exists
    await db["tenants"].update_one(
        {"tenant_id": tenant_id},
        {"$set": {"plan": "Customized", "retention_days": 365, "compliance_packs": ["fbr_pos", "peca_forensic"]}},
        upsert=True
    )
    
    # ensure user exists
    user = {
        "username": admin_email.split("@")[0],
        "email": admin_email,
        "full_name": "Test Admin",
        "hashed_password": get_password_hash("Password123!"),
        "tenant_id": tenant_id,
        "plan_type": "Customized",
        "role": "admin",
        "compliance_packs": ["fbr_pos", "peca_forensic"],
        "has_active_plan": True,
        "created_at": datetime.now(timezone.utc)
    }
    
    await db["users"].delete_one({"email": admin_email})
    await db["users"].insert_one(user)
    print(f"Created admin account: {admin_email} / Password123!")
    

    await db_manager.close()

if __name__ == "__main__":
    asyncio.run(main())

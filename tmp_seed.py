import pymongo
import sys

def seed():
    try:
        # Match current .env settings
        uri = "mongodb://warsoc_admin:W4rS0c_M0ng0_S3cur3_2026!@localhost:27017"
        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
        db = client["WarSOC_DB"]
        
        # Test connection
        client.admin.command('ping')
        print("✅ MongoDB connection successful.")
        
        tenant_id = "WARSOC_898F3395"
        
        # Seed User
        db.users.update_one(
            {"tenant_id": tenant_id},
            {"$set": {
                "username": "warsoc_admin",
                "tenant_id": tenant_id,
                "plan_type": "Enterprise",
                "has_active_plan": True,
                "role": "admin"
            }},
            upsert=True
        )
        print(f"✅ User seeded for {tenant_id}")
        
        # Seed Tenant
        db.tenants.update_one(
            {"tenant_id": tenant_id},
            {"$set": {
                "plan": "Enterprise",
                "status": "active"
            }},
            upsert=True
        )
        print(f"✅ Tenant seeded for {tenant_id}")
        
    except Exception as e:
        print(f"❌ Error during seeding: {e}")
        sys.exit(1)

if __name__ == "__main__":
    seed()

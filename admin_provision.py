import argparse
import asyncio
import uuid
import secrets
from passlib.context import CryptContext
from motor.motor_asyncio import AsyncIOMotorClient
import redis.asyncio as redis
from dotenv import load_dotenv
import os

load_dotenv()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

async def provision_tenant(email, tenant_name, password, agent_limit, packs):
    # Connect to MongoDB
    mongo_uri = os.getenv("MONGODB_URI")
    db_name = os.getenv("MONGODB_DB_NAME", "warsoc_db")
    client = AsyncIOMotorClient(mongo_uri)
    db = client[db_name]

    # Connect to Redis
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    redis_client = redis.from_url(redis_url)

    hashed_password = get_password_hash(password)
    packs_set = set(packs)
    packs_set.add("SIEM")
    features = sorted(packs_set)

    # Check for existing tenant by email
    existing_user = await db.users.find_one({"email": email})
    
    if existing_user:
        print(f"[*] Tenant with email {email} already exists. Updating their limits and packs...")
        tenant_id = existing_user["tenant_id"]
        activation_code = existing_user.get("activation_code", secrets.token_hex(16))
        
        await db.users.update_one(
            {"email": email},
            {"$set": {
                "compliance_packs": packs,
                "agent_limit": agent_limit,
                "max_agents": agent_limit,
                "hashed_password": hashed_password
            }}
        )
        await db.tenants.update_one(
            {"tenant_id": tenant_id},
            {"$set": {
                "compliance_packs": packs,
                "agent_limit": agent_limit,
                "max_agents": agent_limit,
                "features": features
            }}
        )
    else:
        tenant_id = str(uuid.uuid4())
        activation_code = secrets.token_hex(16)
        
        # 1. Create User
        user_doc = {
            "email": email,
            "username": tenant_name,
            "hashed_password": hashed_password,
            "tenant_id": tenant_id,
            "activation_code": activation_code,
            "role": "admin",
            "plan_type": "Enterprise",
            "has_active_plan": True,
            "compliance_packs": packs,
            "agent_limit": agent_limit,
            "max_agents": agent_limit,
            "active_agents": 0
        }
        await db.users.insert_one(user_doc)
        
        # 2. Create Tenant record
        tenant_doc = {
            "tenant_id": tenant_id,
            "name": tenant_name,
            "plan": "Enterprise",
            "compliance_packs": packs,
            "agent_limit": agent_limit,
            "max_agents": agent_limit,
            "features": features,
            "retention_days": 30
        }
        await db.tenants.insert_one(tenant_doc)

    # 3. Push to Redis immediately
    feature_string = ",".join(sorted(packs_set))
    
    await redis_client.set(f"tenant_features:{tenant_id}", feature_string)
    await redis_client.set(f"tenant_plan:{tenant_id}", "Enterprise")
    await redis_client.set(f"tenant_agent_limit:{tenant_id}", str(agent_limit))
    await redis_client.set(f"tenant_retention:{tenant_id}", "30")

    print("\n" + "="*50)
    print(" TENANT SUCCESSFULLY PROVISIONED ")
    print("="*50)
    print(f"Tenant Name:       {tenant_name}")
    print(f"Email:             {email}")
    print(f"Password:          {password}")
    print(f"Tenant ID:         {tenant_id}")
    print(f"Activation Code:   {activation_code}")
    print(f"Agent Limit:       {agent_limit}")
    print(f"Packs:             {packs}")
    print("="*50)
    print("Send the Email, Password, Tenant ID, and Activation Code to the client.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WarSOC Admin Tenant Provisioning Tool")
    parser.add_argument("--tenant", required=True, help="Tenant/Company Name")
    parser.add_argument("--quota", type=int, default=10, help="Max Agent Quota")
    parser.add_argument("--packs", default="siem", help="Comma-separated packs (e.g. siem,fbr_pos,peca_forensic)")
    parser.add_argument("--email", required=False, help="Client Admin Email")
    parser.add_argument("--password", required=False, help="Initial Password")

    args = parser.parse_args()
    pack_list = [p.strip() for p in args.packs.split(",")]
    
    email = args.email or f"admin@{args.tenant.lower().replace('_', '')}.local"
    password = args.password or secrets.token_urlsafe(12)

    asyncio.run(provision_tenant(email, args.tenant, password, args.quota, pack_list))

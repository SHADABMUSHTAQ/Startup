import os
import sys

# Force local host mapping for testing outside docker
os.environ["MONGODB_URI"] = "mongodb://warsoc_admin:W4rS0c_M0ng0_S3cur3_2026!@localhost:27017"
os.environ["REDIS_URL"] = "redis://:W4rS0c_R3d1s_S3cur3_2026!@localhost:6379"

import asyncio
import json
import logging
import subprocess
import time
import redis.asyncio as aioredis
from motor.motor_asyncio import AsyncIOMotorClient

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from app.config.config import get_settings

settings = get_settings()
# Ensure settings also reflect the local host mapping
settings.mongodb_uri = os.environ["MONGODB_URI"]
settings.redis_url = os.environ["REDIS_URL"]

async def setup_test_data():
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client["WarSOC_DB"]
    tenants_col = db["tenants"]
    logs_col = db["logs"]
    
    # 1. Seed Tenants
    await tenants_col.delete_many({"tenant_id": {"$in": ["tenant_fbr_123", "tenant_peca_456"]}})
    await tenants_col.insert_many([
        {"tenant_id": "tenant_fbr_123", "subscription_plan": "FBR_PLAN"},
        {"tenant_id": "tenant_peca_456", "subscription_plan": "PECA_PLAN"}
    ])
    
    # Clear previously matching logs to avoid confusion
    await logs_col.delete_many({"tenant_id": {"$in": ["tenant_fbr_123", "tenant_peca_456"]}})

    # 2. Inject Mock Payloads
    redis_client = await aioredis.from_url(settings.redis_url, decode_responses=True)
    
    # Delete the stream to start fresh
    await redis_client.delete("raw_logs_queue")
    
    fbr_payload = {
        "tenant_id": "tenant_fbr_123",
        "event_id": "4670",
        "message": r"Permissions changed on C:\Program Files\FBR_POS\config.ini"
    }
    peca_payload = {
        "tenant_id": "tenant_peca_456",
        "event_id": "4624",
        "message": "Administrator logged in interactively."
    }
    noise_payload = {
        "tenant_id": "tenant_peca_456",
        "event_id": "5156",
        "message": "Routine network noise."
    }
    
    await redis_client.xadd("raw_logs_queue", {"payload": json.dumps(fbr_payload)})
    await redis_client.xadd("raw_logs_queue", {"payload": json.dumps(peca_payload)})
    await redis_client.xadd("raw_logs_queue", {"payload": json.dumps(noise_payload)})
    
    await redis_client.aclose()

async def verify_results():
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client["WarSOC_DB"]
    logs_col = db["logs"]
    
    docs = await logs_col.find({"tenant_id": {"$in": ["tenant_fbr_123", "tenant_peca_456"]}}).to_list(length=100)
    print("\n--- MONGODB OUTPUT ---")
    for doc in docs:
        doc["_id"] = str(doc["_id"])
        print(json.dumps(doc, indent=2, default=str))
    print("--- END OUTPUT ---\n")

def run_test():
    print("Seeding test data into DB and Redis...")
    asyncio.run(setup_test_data())
    
    print("Starting workers...")
    fbr_proc = subprocess.Popen([sys.executable, "workers/fbr_worker.py"])
    peca_proc = subprocess.Popen([sys.executable, "workers/peca_worker.py"])
    
    # Wait for workers to process and FBR to reach its batch timeout (2 seconds)
    time.sleep(4)
    
    print("Terminating workers...")
    fbr_proc.terminate()
    peca_proc.terminate()
    
    fbr_proc.wait()
    peca_proc.wait()
    
    print("Fetching results...")
    asyncio.run(verify_results())

if __name__ == "__main__":
    run_test()

import asyncio
import json
import uuid
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from redis.asyncio import Redis
from app.config.config import get_settings

async def prime():
    settings = get_settings()
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]
    redis = await Redis.from_url(settings.redis_url)

    # 1. Get latest tenant
    tenant = await db.tenants.find_one(sort=[("_id", -1)])
    if not tenant:
        print("No tenant found to prime.")
        return
    
    tenant_id = tenant["tenant_id"]
    print(f"Priming for Tenant: {tenant_id}")

    # 2. Mock Compliance Logs (PECA & FBR Standards)
    events = [
        # PECA 2016 (Forensic Trail)
        {"event_id": 4624, "message": "An account was successfully logged on.", "severity": "informational", "pack": "peca_forensic"},
        {"event_id": 1102, "message": "The audit log was cleared.", "severity": "critical", "pack": "peca_forensic"},
        # FBR SRO 288 (POS Compliance)
        {"event_id": 4663, "message": "File System Modification (POS Invoice Path).", "severity": "alert", "pack": "fbr_pos"},
        {"event_id": 4670, "name": "Permissions Changed (Retail Database)", "severity": "high", "pack": "fbr_pos"}
    ]

    for event in events:
        payload = {
            "tenant_id": tenant_id,
            "event_id": event["event_id"],
            "source": "Security",
            "source_ip": "192.168.1.105", 
            "computer": "WORKSTATION-01",
            "message": event.get("message", event.get("name")),
            "severity": event["severity"],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        await redis.xadd("raw_logs_queue", {"payload": json.dumps(payload)})
        print(f"Injected Event {event['event_id']}")

    print("✅ Compliance Dashboard Primed. Workers should process these in 2 seconds.")

if __name__ == "__main__":
    asyncio.run(prime())

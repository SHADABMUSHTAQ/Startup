import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from app.config.config import get_settings

async def check_log_age():
    settings = get_settings()
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]

    collections = ["logs", "peca_forensic_logs", "fbr_pos_logs", "security_alerts"]
    
    for coll_name in collections:
        print(f"--- {coll_name.upper()} ---")
        count = await db[coll_name].count_documents({})
        if count == 0:
            print("No logs found.")
            continue
            
        oldest = await db[coll_name].find_one(sort=[("timestamp", 1)])
        newest = await db[coll_name].find_one(sort=[("timestamp", -1)])
        
        print(f"Count: {count}")
        print(f"Oldest: {oldest.get('timestamp')}")
        print(f"Newest: {newest.get('timestamp')}")
        print()

    client.close()

if __name__ == "__main__":
    asyncio.run(check_log_age())

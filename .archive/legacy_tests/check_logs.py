import asyncio
from app.config.config import get_settings
from motor.motor_asyncio import AsyncIOMotorClient

async def check():
    settings = get_settings()
    db = AsyncIOMotorClient(settings.mongodb_uri)[settings.mongodb_db_name]
    fbr = await db.fbr_pos_logs.count_documents({})
    peca = await db.peca_forensic_logs.count_documents({})
    print("\n========================")
    print(f"FBR Logs Captured:  {fbr}")
    print(f"PECA Logs Secured:  {peca}")
    print("========================\n")

if __name__ == "__main__":
    asyncio.run(check())

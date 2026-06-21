import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
import asyncio
import pymongo
from motor.motor_asyncio import AsyncIOMotorClient
from app.config.config import get_settings

async def setup_indexes():
    settings = get_settings()
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db_name]

    print(" Building Enterprise MongoDB Indexes...")

    # 1. CORE DASHBOARD PAGINATION (The "Speed" Indexes)
    # Used by /logs and /alerts endpoints. 
    # Sorts the index exactly how the API queries it to completely eliminate in-memory sorting.
    collections_to_index = ["logs", "security_alerts", "peca_forensic_logs", "fbr_pos_logs", "csv_uploads"]
    for coll in collections_to_index:
        await db[coll].create_index(
            [("tenant_id", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)],
            background=True
        )
        print(f"    Created compound pagination index on: {coll}")

    # 2. ALERT FILTERING
    # Used when an analyst filters the Alerts Dashboard by severity or workflow status
    await db.security_alerts.create_index(
        [("tenant_id", pymongo.ASCENDING), ("status", pymongo.ASCENDING), ("severity", pymongo.ASCENDING)],
        background=True
    )
    print("    Created alert filtering index on: security_alerts")

    # 3. CSV FORENSIC UPLOADS
    # Used by upload.py to fetch the 5,000 findings belonging to a specific uploaded file
    await db.csv_uploads.create_index(
        [("tenant_id", pymongo.ASCENDING), ("analysis_tag", pymongo.ASCENDING)],
        background=True
    )
    print("    Created batch analysis index on: csv_uploads")

    # 4. EDGE DEVICE & SOAR MITIGATION
    try:
        await db.agents.create_index("agent_id", unique=True, background=True)
        await db.firewall_rules.create_index(
            [("tenant_id", pymongo.ASCENDING), ("ip", pymongo.ASCENDING)],
            name="idx_firewall_rules_tenant_id_1_ip_1",
            background=True
        )
        print("    Created SOAR mitigation & edge identity indexes")
    except pymongo.errors.OperationFailure as e:
        if e.code == 85:
            print("    SOAR mitigation & edge identity indexes already exist (skipping).")
        else:
            raise e

    print("\n🏁 All B2B Enterprise Indexes Built Successfully!")
    client.close()

if __name__ == "__main__":
    asyncio.run(setup_indexes())
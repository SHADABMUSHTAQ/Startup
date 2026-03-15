import pymongo

# Use Docker Compose network host and credentials from .env
MONGO_URI = "mongodb://warsoc_admin:W4rS0c_M0ng0_S3cur3_2026!@localhost:27017"
DB_NAME = "WarSOC_DB"

client = pymongo.MongoClient(MONGO_URI)
db = client[DB_NAME]
agents = db["agents"]

agent_doc = {
    "agent_id": "WARSOC_98F626B8",
    "agent_secret": "warsoc_enterprise_agent_key_2026",
    "tenant_id": "WARSOC_98F626B8",
    "approved": True
}

agents.update_one({"agent_id": agent_doc["agent_id"]}, {"$set": agent_doc}, upsert=True)
print("Agent registered/updated successfully.")

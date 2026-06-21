from motor.motor_asyncio import AsyncIOMotorClient
from app.config.config import get_settings
from bson import ObjectId
import logging
from contextlib import asynccontextmanager

# Logger Setup
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self):
        self.client = None
        self.db = None

    async def connect(self):
        """Initializes the connection to MongoDB."""
        settings = get_settings()
        
        #  DB Name dynamically pulled from settings (CTO FIX)
        db_name = settings.mongodb_db_name  
        
        try:
            self.client = AsyncIOMotorClient(settings.mongodb_uri)
            self.db = self.client[db_name]
            
            # Ping verify
            await self.client.admin.command('ping')
            print(f" MongoDB Connected: {db_name}")
            
        except Exception as e:
            print(f" MongoDB Connection Failed: {e}")
            raise e

    async def close(self):
        """Closes the connection."""
        if self.client:
            self.client.close()
            print(" MongoDB Connection Closed")

    #  MAGIC METHOD 
    # Handles dynamic calls like 'db.users'
    def __getattr__(self, name):
        if self.db is not None:
            return getattr(self.db, name)
        raise AttributeError(f"'DatabaseManager' not connected. Cannot access '{name}'")

    # ==========================================
    #  HELPER METHODS
    # ==========================================
    
    async def insert_analysis_result(self, data: dict) -> str:
        """Saves a new log analysis job."""
        if self.db is None: await self.connect()
        result = await self.db.analysis_results.insert_one(data)
        return str(result.inserted_id)

    async def get_analysis_result(self, analysis_id: str, tenant_id: str):
        """Fetches a report by ID with tenant isolation."""
        if self.db is None: await self.connect()
        if not ObjectId.is_valid(analysis_id):
            return None
        return await self.db.analysis_results.find_one({"_id": ObjectId(analysis_id), "tenant_id": tenant_id})
    
    #  PIPE 1: Strictly for Manual File Uploads
    async def get_all_analyses(self, tenant_id: str):
        """Fetches manual uploads with tenant isolation."""
        if self.db is None: await self.connect()
        if not tenant_id:
            raise ValueError("tenant_id is required for get_all_analyses.")
        
        cursor = self.db.analysis_results.find({"tenant_id": tenant_id}).sort("uploaded_at", -1)
        results = await cursor.to_list(length=100)
        
        clean_results = []
        for res in results:
            res["_id"] = str(res["_id"])
            res["analysisId"] = str(res["_id"]) 
            clean_results.append(res)
            
        return clean_results

    #  PIPE 2: Strictly for Live Windows Agent
    async def get_all_logs(self, tenant_id: str):
        """Fetches live agent streaming data from the logs collection.
        Tenant isolation enforcement: `tenant_id` is required.
        """
        if self.db is None: await self.connect()
        if not tenant_id:
            raise ValueError("tenant_id is required for get_all_logs to enforce tenant isolation.")
        
        cursor = self.db.logs.find({"tenant_id": tenant_id}).sort("timestamp", -1)
        results = await cursor.to_list(length=100)
        
        clean_results = []
        for res in results:
            res["_id"] = str(res["_id"])
            clean_results.append(res)
            
        return clean_results

    async def update_analysis_result(self, analysis_id: str, update_data: dict):
        """Updates a report (Used by Worker)."""
        if self.db is None: await self.connect()
        if not ObjectId.is_valid(analysis_id):
            return
        await self.db.analysis_results.update_one(
            {"_id": ObjectId(analysis_id)},
            {"$set": update_data}
        )

# --- GLOBAL INSTANCE ---
db_manager = DatabaseManager()

# --- DEPENDENCY FOR ROUTES ---
async def get_db():
    if db_manager.db is None:
        # Fallback ONLY if lifespan somehow failed, but we raise an error instead of thrashing
        raise Exception("Database not initialized. Check lifespan startup.")
    return db_manager.db

# --- CONTEXT MANAGER FOR WORKER ---
@asynccontextmanager
async def get_db_context():
    if db_manager.db is None:
        await db_manager.connect()
    try:
        yield db_manager
    finally:
        # Motor manages connection pooling. Do NOT close the client here —
        # repeatedly opening/closing the client from a worker will thrash connections.
        # Keep the client open for the process lifetime and rely on `init_db()` at startup.
        pass

# --- INITIALIZATION ---
async def init_db():
    await db_manager.connect()
    # Ensure tenant isolation indexes exist for performance and safety
    if db_manager.db is not None:
        indexes = [
            ("logs", [("tenant_id", 1), ("timestamp", -1)]),
            ("security_alerts", [("tenant_id", 1), ("timestamp", -1)]),
            ("peca_forensic_logs", [("tenant_id", 1), ("timestamp", -1)]),
            ("fbr_pos_logs", [("tenant_id", 1), ("timestamp", -1)]),
            ("csv_uploads", [("tenant_id", 1), ("timestamp", -1)]),
            ("logs", "tenant_id"),
            ("security_alerts", "tenant_id"),
            ("analysis_results", "tenant_id"),
            ("firewall_rules", [("tenant_id", 1), ("ip", 1)]),
            ("users", "tenant_id")
        ]
        for coll, idx in indexes:
            try:
                # Use a specific name to avoid collision with default generated names
                idx_str = str(idx).replace(' ', '').replace('[', '').replace(']', '').replace('(', '').replace(')', '').replace(',', '_').replace("'", '')
                index_name = f"idx_{coll}_{idx_str}"
                try:
                    await db_manager.db[coll].create_index(idx, name=index_name)
                except Exception as e:
                    # Handle IndexOptionsConflict (existing same-key index with different name/options)
                    is_conflict = getattr(e, 'code', None) == 85 or 'IndexOptionsConflict' in str(e)
                    if is_conflict:
                        # Normalize expected key pattern
                        if isinstance(idx, str):
                            expected_key = [(idx, 1)]
                        else:
                            expected_key = list(idx)

                        idxs = await db_manager.db[coll].index_information()
                        dropped = False
                        for name, info in idxs.items():
                            if info.get('key') == expected_key:
                                await db_manager.db[coll].drop_index(name)
                                print(f"    - Dropped conflicting index {coll}.{name}")
                                await db_manager.db[coll].create_index(idx, name=index_name)
                                print(f"    - Recreated compound index {index_name}")
                                dropped = True
                                break
                        if not dropped:
                            print(f" Index conflict for {coll}/{idx} but no matching key found: {e}")
                    else:
                        print(f" Index setup for {coll}/{idx} failed: {e}")
            except Exception as e:
                print(f" Index setup for {coll}/{idx} (skipped or already exists): {e}")

        # Team management requires multiple users per tenant; remove any legacy unique tenant index or conflicting name.
        try:
            users_indexes = await db_manager.db["users"].index_information()
            for idx_name, idx_def in users_indexes.items():
                if idx_name == "_id_":
                    continue
                if idx_def.get("key") != [("tenant_id", 1)]:
                    continue
                if idx_def.get("unique") or idx_name != "idx_users_tenant_id_1":
                    await db_manager.db["users"].drop_index(idx_name)
                    print(f"    - Dropped legacy or conflicting users.{idx_name} index")
                    # Don't break here, we want to drop all such indices
            await db_manager.db["users"].create_index([("tenant_id", 1)], name="idx_users_tenant_id_1", unique=False)
        except Exception as e:
            print(f" users.tenant_id index normalization failed: {e}")

        await ensure_threat_intel_indexes(db_manager.db)
        await ensure_used_provisioning_token_indexes(db_manager.db)
        
        # Ensure TTL index for forensic retention
        try:
            async def _ensure_ttl(coll_name: str, retention_seconds: int, field_name: str = "_retention_ts"):
                coll = db_manager.db.get_collection(coll_name)
                idxs = await coll.index_information()
                
                # Check for existing TTL indexes and drop conflicting ones
                for name, info in idxs.items():
                    if info.get("key") == [(field_name, 1)]:
                        existing_ttl = info.get("expireAfterSeconds")
                        if existing_ttl != retention_seconds:
                            await coll.drop_index(name)
                            await coll.create_index([(field_name, 1)], expireAfterSeconds=retention_seconds, name=f"idx_{coll_name}_{field_name}")
                            print(f"    - Recreated TTL index on {coll_name} expireAfterSeconds={retention_seconds}")
                        else:
                            print(f"    - TTL index {name} present with {existing_ttl}s on {coll_name}")
                        break
                else:
                    await coll.create_index([(field_name, 1)], expireAfterSeconds=retention_seconds, name=f"idx_{coll_name}_{field_name}")
                    print(f"    - Created TTL index on {coll_name} expireAfterSeconds={retention_seconds}")

            # 7 days
            await _ensure_ttl("security_alerts", 604800)
            
            # 1 year (Mandated by PECA)
            await _ensure_ttl("peca_forensic_logs", 31536000)
            
            # 6 years (mandated for FBR compliance)
            await _ensure_ttl("fbr_pos_logs", 189216000)
            
            # Hot Logs (7 days)
            await _ensure_ttl("logs", 604800)
        except Exception as e:
            print(f" TTL index setup failed: {e}")

        print(" MongoDB Indexes Ensured")


async def _dedupe_field_before_unique(collection, collection_name: str, field_name: str):
    seen = set()
    duplicates = []
    cursor = collection.find({field_name: {"$exists": True}}, {field_name: 1}).sort([("timestamp", -1), ("_id", -1)])
    async for document in cursor:
        value = str(document.get(field_name) or "").strip()
        if not value:
            continue
        if value in seen:
            duplicates.append(document["_id"])
        else:
            seen.add(value)

    if duplicates:
        await collection.delete_many({"_id": {"$in": duplicates}})
        print(f"    - Removed {len(duplicates)} duplicate {collection_name}.{field_name} document(s)")


async def ensure_threat_intel_indexes(db):
    collection = db.get_collection("threat_intel_learned_ips")
    indexes = await collection.index_information()
    expected_key = [("ip", 1)]

    for idx_name, idx_def in indexes.items():
        if idx_name == "_id_":
            continue
        if idx_def.get("key") != expected_key:
            continue
        if idx_def.get("unique"):
            return
        await collection.drop_index(idx_name)
        logger.warning(f"Dropped non-unique threat intel index {idx_name} before enforcing uniqueness")
        break

    await _dedupe_field_before_unique(collection, "threat_intel_learned_ips", "ip")
    await collection.create_index([("ip", 1)], name="ip_1", unique=True)
    logger.info("Threat intel learned IP uniqueness enforced")


async def ensure_used_provisioning_token_indexes(db):
    collection = db.get_collection("used_provisioning_tokens")
    indexes = await collection.index_information()
    expected_key = [("jti", 1)]

    for idx_name, idx_def in indexes.items():
        if idx_name == "_id_":
            continue
        if idx_def.get("key") != expected_key:
            continue
        if idx_def.get("unique"):
            return
        await collection.drop_index(idx_name)
        logger.warning(f"Dropped non-unique provisioning token index {idx_name} before enforcing uniqueness")
        break

    await _dedupe_field_before_unique(collection, "used_provisioning_tokens", "jti")
    await collection.create_index([("jti", 1)], name="jti_1", unique=True)
    logger.info("Used provisioning token uniqueness enforced")
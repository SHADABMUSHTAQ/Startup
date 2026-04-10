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
        
        # ✅ DB Name dynamically pulled from settings (CTO FIX)
        db_name = settings.mongodb_db_name  
        
        try:
            self.client = AsyncIOMotorClient(settings.mongodb_uri)
            self.db = self.client[db_name]
            
            # Ping verify
            await self.client.admin.command('ping')
            print(f"✅ MongoDB Connected: {db_name}")
            
        except Exception as e:
            print(f"❌ MongoDB Connection Failed: {e}")
            raise e

    async def close(self):
        """Closes the connection."""
        if self.client:
            self.client.close()
            print("🔌 MongoDB Connection Closed")

    # 🔥🔥 MAGIC METHOD 🔥🔥
    # Handles dynamic calls like 'db.users'
    def __getattr__(self, name):
        if self.db is not None:
            return getattr(self.db, name)
        raise AttributeError(f"'DatabaseManager' not connected. Cannot access '{name}'")

    # ==========================================
    # 🛡️ HELPER METHODS
    # ==========================================
    
    async def insert_analysis_result(self, data: dict) -> str:
        """Saves a new log analysis job."""
        if self.db is None: await self.connect()
        result = await self.db.analysis_results.insert_one(data)
        return str(result.inserted_id)

    async def get_analysis_result(self, analysis_id: str):
        """Fetches a report by ID."""
        if self.db is None: await self.connect()
        if not ObjectId.is_valid(analysis_id):
            return None
        return await self.db.analysis_results.find_one({"_id": ObjectId(analysis_id)})
    
    # ✅ PIPE 1: Strictly for Manual File Uploads
    async def get_all_analyses(self):
        """Fetches manual uploads from the analysis_results collection."""
        if self.db is None: await self.connect()
        
        cursor = self.db.analysis_results.find().sort("uploaded_at", -1)
        results = await cursor.to_list(length=100)
        
        clean_results = []
        for res in results:
            res["_id"] = str(res["_id"])
            res["analysisId"] = str(res["_id"]) 
            clean_results.append(res)
            
        return clean_results

    # ✅ PIPE 2: Strictly for Live Windows Agent
    async def get_all_logs(self):
        """Fetches live agent streaming data from the logs collection."""
        if self.db is None: await self.connect()
        
        cursor = self.db.logs.find().sort("timestamp", -1)
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
                            print(f"⚠️ Index conflict for {coll}/{idx} but no matching key found: {e}")
                    else:
                        print(f"⚠️ Index setup for {coll}/{idx} failed: {e}")
            except Exception as e:
                print(f"⚠️ Index setup for {coll}/{idx} (skipped or already exists): {e}")
        print("✅ MongoDB Indexes Ensured")
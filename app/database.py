from motor.motor_asyncio import AsyncIOMotorClient
from app.config.config import get_settings
from bson import ObjectId
import logging

# Logger Setup
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self):
        self.client = None
        self.db = None

    async def connect(self):
        """Initializes the connection to MongoDB."""
        settings = get_settings()
        
        # ✅ DB Name fixed as per your setup
        db_name = "WarSOC_DB"  
        
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
    # Ye method 'db.users' jaisi calls ko handle karta hai
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
    
    # ✅ NEW: Ye function Dashboard Sidebar ke liye list layega
    async def get_all_analyses(self):
        """Fetches all uploaded files sorted by newest first."""
        if self.db is None: await self.connect()
        
        # Sort by 'uploaded_at' descending (-1) taake nayi file sabse upar aaye
        cursor = self.db.analysis_results.find().sort("uploaded_at", -1)
        results = await cursor.to_list(length=100)
        
        # Frontend ke liye ID convert karna zaroori hai
        clean_results = []
        for res in results:
            res["_id"] = str(res["_id"])
            res["analysisId"] = str(res["_id"]) 
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
        await db_manager.connect()
    return db_manager

# --- CONTEXT MANAGER FOR WORKER ---
from contextlib import asynccontextmanager

@asynccontextmanager
async def get_db_context():
    if db_manager.db is None:
        await db_manager.connect()
    try:
        yield db_manager
    finally:
        pass 

# --- INITIALIZATION ---
async def init_db():
    await db_manager.connect()
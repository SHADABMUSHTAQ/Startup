import asyncio
import json
import jwt
from contextlib import asynccontextmanager
import redis.asyncio as aioredis
from app.routes.auth import get_current_user
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.routes import data

# ==========================================
# 1. ENTERPRISE IMPORTS
# ==========================================
from app.database import init_db, get_db
from app.config.config import get_settings
from app.routes import auth, ingest_pulse, threat_intel, upload
from app.api.ws_manager import manager 

settings = get_settings()

# ==========================================
# 2. REDIS-TO-WEBSOCKET BRIDGE (TENANT AWARE)
# ==========================================
async def redis_to_websocket_listener():
    """Enterprise-grade self-healing listener for Redis alerts."""
    print("📡 Redis-to-WebSocket Listener Active & Waiting...")
    while True:
        try:
            r = await aioredis.from_url(settings.redis_url, decode_responses=True)
            pubsub = r.pubsub()
            await pubsub.subscribe("security_alerts")
            
            async for message in pubsub.listen():
                if message["type"] == "message":
                    alert_data = json.loads(message["data"])
                    
                    # 🚨 CTO FIX: Extract tenant_id and route to the correct private room
                    tenant_id = alert_data.get("tenant_id")
                    if tenant_id:
                        await manager.broadcast_to_tenant(tenant_id, alert_data)
                        print(f"🚀 BROADCASTED to [{tenant_id}]: {alert_data.get('title')}")
        except Exception as e:
            print(f"⚠️ Redis Connection lost. Retrying... ({e})")
            await asyncio.sleep(2)
        finally:
            try: await r.close()
            except: pass

# ==========================================
# 3. FASTAPI LIFESPAN
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Booting WarSOC Backend...")
    await init_db()
    # Initialize global Redis connection pool
    app.state.redis = await aioredis.from_url(settings.redis_url, decode_responses=True)
    listener_task = asyncio.create_task(redis_to_websocket_listener())
    yield
    print("🛑 Shutting down WarSOC Backend...")
    listener_task.cancel()
    # Close global Redis connection pool
    try:
        await app.state.redis.close()
    except Exception:
        pass

# ==========================================
# 4. APP INITIALIZATION
# ==========================================
app = FastAPI(
    title="WarSOC SIEM API", 
    version="3.0-Enterprise",
    lifespan=lifespan
)

# ==========================================
# 4.1 RATE LIMITING
# ==========================================
limiter = Limiter(key_func=get_remote_address, storage_uri=settings.redis_url)
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Too many requests. Please try again later."})

# Parse allowed origins from settings (comma-separated string)
_allowed_origins = [o.strip() for o in settings.allowed_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# 5. UNIFIED ROUTERS
# ==========================================
app.include_router(threat_intel.router, prefix="/api/v1", tags=["Security Ops"])
app.include_router(ingest_pulse.router, prefix="/api/v1/ingest", tags=["Ingestion"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(upload.router, prefix="/api/v1/upload", tags=["Upload"])

# Legacy support
app.include_router(threat_intel.router, prefix="/firewall", tags=["Legacy Mitigation"])
app.include_router(upload.router, prefix="/upload", tags=["Legacy Upload"])
app.include_router(auth.router, prefix="/auth", tags=["Legacy Auth"])
app.include_router(data.router, prefix="/api/v1/data", tags=["Data Engine"])

# ==========================================
# 5.5 DASHBOARD ROUTES (🔥 THE FIX FOR THE BLANK TABLE)
# ==========================================
@app.get("/api/v1/logs", tags=["Dashboard"])
async def fetch_live_logs(db = Depends(get_db), current_user = Depends(get_current_user)):
    """The Secure Bridge: Only fetches logs belonging to the logged-in user's Tenant ID"""
    try:
        # 🚨 DEFENSIVE FIX: Safely extract Tenant ID whether it's a dict or a Database Model
        if isinstance(current_user, dict):
            secure_tenant_id = current_user.get("tenant_id")
        else:
            secure_tenant_id = getattr(current_user, "tenant_id", None)
            
        print(f"🔍 [DASHBOARD TRACER] React is requesting logs for Tenant ID: '{secure_tenant_id}'")
        
        # 🚨 Fetching exactly from the collection the worker wrote to
        # Exclude CSV-uploaded logs so the live dashboard only shows agent/real-time data
        log_query = {"tenant_id": secure_tenant_id, "source": {"$ne": "csv_upload"}}
        fresh_start_at = current_user.get("agent_issued_at") if isinstance(current_user, dict) else getattr(current_user, "agent_issued_at", None)
        if fresh_start_at:
            log_query["timestamp"] = {"$gte": fresh_start_at}

        cursor = db.db["logs"].find(log_query).sort("timestamp", -1).limit(100)
        
        data = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"]) # Convert MongoDB ID to string for React
            data.append(doc)
            
        print(f"✅ [DASHBOARD TRACER] Sending {len(data)} logs to the React Screen.")
        return {"status": "success", "data": data}
        
    except Exception as e:
        print(f"❌ [DASHBOARD ERROR]: {e}")
        return {"status": "error", "message": str(e)}
# ==========================================
# 6. WEBSOCKET ENDPOINT (BULLETPROOF AUTH)
# ==========================================
@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    # 🚨 CTO FIX: Safely extract token directly from the connection URL
    token = websocket.query_params.get("token")
    
    if not token:
        print("❌ WebSocket Rejected: No token provided in URL.")
        return # Drop unauthenticated connection cleanly
        
    try:
        # 🚨 CTO FIX: Cryptographically verify the token
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        tenant_id = payload.get("tenant_id")
        
        if not tenant_id:
            print("❌ WebSocket Rejected: Token lacks tenant_id.")
            return
            
        # Handshake successful, pass to the private Tenant Room
        await manager.connect(websocket, tenant_id)
        try:
            while True:
                await websocket.receive_text() # Keep connection alive
        except WebSocketDisconnect:
            manager.disconnect(websocket, tenant_id)
            
    except jwt.ExpiredSignatureError:
        print("❌ WebSocket Rejected: Token has expired.")
        return
    except jwt.InvalidTokenError:
        print("❌ WebSocket Rejected: Invalid token signature.")
        return
    except Exception as e:
        print(f"❌ WebSocket System Error: {str(e)}")
        return
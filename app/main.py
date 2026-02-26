import asyncio
import json
import jwt
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
import redis.asyncio as aioredis

# ==========================================
# 1. ENTERPRISE IMPORTS
# ==========================================
from app.database import init_db
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
    listener_task = asyncio.create_task(redis_to_websocket_listener())
    yield 
    print("🛑 Shutting down WarSOC Backend...")
    listener_task.cancel()

# ==========================================
# 4. APP INITIALIZATION
# ==========================================
app = FastAPI(
    title="WarSOC SIEM API", 
    version="3.0-Enterprise",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
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
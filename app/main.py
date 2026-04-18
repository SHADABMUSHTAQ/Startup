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
from app.database import init_db, get_db, db_manager
from app.config.config import get_settings
from app.routes import auth, ingest_pulse, threat_intel, upload, compliance, logs, ingestion, alerts
from app.routes import metrics
from app.db.init_db import init_compliance_db
from app.api.ws_manager import manager 

settings = get_settings()

# ==========================================
# 2. REDIS-TO-WEBSOCKET BRIDGE (TENANT AWARE)
# ==========================================
async def redis_to_websocket_listener(app: FastAPI):
    """Enterprise-grade self-healing listener for Redis alerts using the app global pool."""
    print("📡 Redis-to-WebSocket Listener Active & Waiting...")
    while True:
        r = None
        try:
            r = getattr(app.state, "redis", None)
            if r is None:
                # fallback to temporary connection if global pool isn't attached yet
                r = await aioredis.from_url(settings.redis_url, decode_responses=True)

            pubsub = r.pubsub()
            await pubsub.subscribe("security_alerts")

            async for message in pubsub.listen():
                if message["type"] == "message":
                    alert_data = json.loads(message["data"])
                    tenant_id = alert_data.get("tenant_id")
                    if tenant_id:
                        await manager.broadcast_to_tenant(tenant_id, alert_data)
                        print(f"🚀 BROADCASTED to [{tenant_id}]: {alert_data.get('summary', alert_data.get('type', 'alert'))}")
        except Exception as e:
            print(f"⚠️ Redis Connection lost. Retrying... ({e})")
            await asyncio.sleep(2)
        finally:
            # only close temporary connections
            try:
                if r is not None and getattr(app.state, "redis", None) is not r:
                    await r.close()
            except Exception:
                pass

from app.utils.tenant_cache import sync_tenant_cache

# ==========================================
# 3. FASTAPI LIFESPAN
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize global Redis connection pool with startup retries
    max_retries = 5
    backoff = 1
    redis_pool = None
    for attempt in range(1, max_retries + 1):
        try:
            redis_pool = await aioredis.from_url(settings.redis_url, decode_responses=True)
            await redis_pool.ping()
            print("✅ Redis pool connected and ready.")
            break
        except Exception as e:
            print(f"⚠️ Redis connection attempt {attempt} failed: {e}")
            if redis_pool is not None:
                try: await redis_pool.close()
                except Exception: pass
            if attempt < max_retries:
                await asyncio.sleep(backoff)
                backoff *= 2
            else:
                print("❌ Could not establish Redis connection after retries; starting in degraded mode.")

    # attach global pool (may be None if degraded)
    app.state.redis = redis_pool

    # Start a background health monitor to keep `app.state.redis` connected when possible.
    async def redis_health_monitor():
        backoff = 1
        while True:
            try:
                r = getattr(app.state, "redis", None)
                if r is None:
                    try:
                        pool = await aioredis.from_url(settings.redis_url, decode_responses=True)
                        await pool.ping()
                        app.state.redis = pool
                        print("🔁 Redis health monitor: connected.")
                        backoff = 1
                    except Exception as e:
                        print(f"🔁 Redis health monitor: connect failed: {e}")
                        await asyncio.sleep(backoff)
                        backoff = min(backoff * 2, 30)
                else:
                    try:
                        await r.ping()
                    except Exception as e:
                        print(f"🔁 Redis health monitor: ping failed: {e}")
                        try:
                            await r.close()
                        except Exception:
                            pass
                        app.state.redis = None
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"🔁 Redis health monitor unexpected error: {e}")
            await asyncio.sleep(5)

    monitor_task = asyncio.create_task(redis_health_monitor())

    # 1. MONGODB INITIALIZATION (WITH RETRIES)
    max_db_retries = 10
    db_backoff = 2
    db_connected = False
    
    for attempt in range(1, max_db_retries + 1):
        try:
            print(f"🔄 MongoDB connection attempt {attempt}/{max_db_retries}...")
            await init_db()
            if db_manager.db is not None:
                await init_compliance_db(db_manager.db)
                db_connected = True
                print("✅ MongoDB & Compliance Schema initialized successfully.")
                break
        except Exception as e:
            print(f"⚠️ MongoDB attempt {attempt} failed: {e}")
            if attempt < max_db_retries:
                await asyncio.sleep(db_backoff)
                # Cap the backoff at 10 seconds to avoid excessive wait
                db_backoff = min(db_backoff * 1.5, 10)
            else:
                print("❌ FATAL: Could not establish MongoDB connection after retries.")
                # Don't raise if MongoDB fails, just run degraded
                break
    
    # 💳 SYNC TENANT CACHE (Enterprise SRO 288 Optimization)
    if db_manager.db is not None and app.state.redis is not None:
        try:
            await sync_tenant_cache(db_manager.db, app.state.redis)
        except Exception as e:
            print(f"⚠️ Tenant cache sync failed: {e}")

    listener_task = asyncio.create_task(redis_to_websocket_listener(app))
    yield
    print("🛑 Shutting down WarSOC Backend...")
    # Cancel background tasks and close Redis gracefully
    try:
        monitor_task.cancel()
    except Exception:
        pass
    try:
        listener_task.cancel()
    except Exception:
        pass
    # Close global Redis connection pool
    try:
        if getattr(app.state, "redis", None) is not None:
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
# 4.1 RATE LIMITING (BULK PROTECTED)
# ==========================================
from app.utils.limiter import limiter
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
app.include_router(compliance.router, prefix="/api/v1/compliance", tags=["Compliance"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alert Management"])
app.include_router(logs.router, prefix="/api/v1/logs", tags=["Dashboard Logs"])
app.include_router(metrics.router, prefix="", tags=["Metrics"])

# 🚨 CTO FIX: Remove ingestion.router to prevent prefix collision with ingest_pulse.router
# app.include_router(ingestion.router, prefix="/api/v1/ingest", tags=["Compliance Ingestion"])

# Legacy support
app.include_router(threat_intel.router, prefix="/firewall", tags=["Legacy Mitigation"])
app.include_router(upload.router, prefix="/upload", tags=["Legacy Upload"])
app.include_router(auth.router, prefix="/auth", tags=["Legacy Auth"])
app.include_router(data.router, prefix="/api/v1/data", tags=["Data Engine"])

# ==========================================
# 5.5 DASHBOARD ROUTES (Moved to app/routes/logs.py)
# ==========================================
# ==========================================
# 6. WEBSOCKET ENDPOINT (BULLETPROOF AUTH)
# ==========================================
@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    # 🚨 CTO FIX: Safely extract token directly from the connection URL
    token = websocket.query_params.get("token")
    
    if not token:
        print("❌ WebSocket Rejected: No token provided in URL.")
        await websocket.close(code=4001, reason="No token provided")
        return
        
    try:
        # 🚨 CTO FIX: Cryptographically verify the token
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        tenant_id = payload.get("tenant_id")
        jti = payload.get("jti")
        
        if not tenant_id:
            print("❌ WebSocket Rejected: Token lacks tenant_id.")
            await websocket.close(code=4001, reason="Missing tenant_id")
            return

        # 🚨 FIX BUG-13: Check if token is blacklisted in Redis
        if jti:
            redis_client = getattr(websocket.app.state, "redis", None)
            if redis_client:
                is_blacklisted = await redis_client.exists(f"warsoc:blacklist:{jti}")
                if is_blacklisted:
                    print(f"❌ WebSocket Rejected: Token {jti} is blacklisted.")
                    await websocket.close(code=4001, reason="Token revoked")
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
        await websocket.close(code=4001, reason="Token expired")
        return
    except jwt.InvalidTokenError:
        print("❌ WebSocket Rejected: Invalid token signature.")
        await websocket.close(code=4001, reason="Invalid token")
        return
    except Exception as e:
        print(f"❌ WebSocket System Error: {str(e)}")
        return
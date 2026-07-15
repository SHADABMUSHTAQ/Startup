import asyncio
import json
import jwt
import uuid
import ipaddress
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
import redis.asyncio as aioredis
from app.routes.auth import get_current_user
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, Depends, Request, status, WebSocketException, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.routes import data
import psutil
from starlette.middleware.base import BaseHTTPMiddleware

# ==========================================
# 1. ENTERPRISE IMPORTS
# ==========================================
from app.database import init_db, get_db, db_manager
from app.config.config import get_settings
from app.routes import auth, ingest_pulse, threat_intel, upload, compliance, logs, alerts, admin, account, sales, export, pos
from app.routes import metrics
from app.db.init_db import init_compliance_db
from app.api.ws_manager import manager 
from app.utils.rbac import RoleChecker
from app.utils.redis_client import create_redis_client

settings = get_settings()
logger = logging.getLogger(__name__)
WS_TICKET_PREFIX = "warsoc:ws_ticket:"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_BOOT_LOCK_KEY = "warsoc:startup:schema_lock"
SCHEMA_BOOT_READY_KEY = "warsoc:startup:schema_ready"


def _parse_allowed_origins() -> list[str]:
    # Strip whitespace and trailing slashes to ensure strict CORS matching
    origins = [origin.strip().rstrip("/") for origin in settings.allowed_origins.split(",") if origin.strip()]
    
    # Fallback to standard React/Vite development ports if env var is missing
    if not origins:
        origins = ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"]

    if settings.environment.lower() == "production":
        unsafe_origins = {"*", "http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"}
        if any(origin in unsafe_origins for origin in origins):
            raise RuntimeError(
                "ALLOWED_ORIGINS must be set to the real frontend domain in production; localhost and wildcard origins are not allowed"
            )

    return origins


class MemoryLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, threshold: float = 0.85):
        super().__init__(app)
        self.threshold = threshold
        self.cache_seconds = float(os.getenv("MEMORY_CHECK_CACHE_SECONDS", "1.0"))
        self._last_check_at = 0.0
        self._last_memory_percent = 0.0

    async def dispatch(self, request: Request, call_next):
        try:
            now = time.monotonic()
            if now - self._last_check_at >= self.cache_seconds:
                self._last_memory_percent = psutil.virtual_memory().percent / 100.0
                self._last_check_at = now
            memory_percent = self._last_memory_percent
        except Exception:
            return JSONResponse(status_code=503, content={"detail": "Service unavailable: memory pressure check failed"})

        if memory_percent >= self.threshold:
            return JSONResponse(status_code=503, content={"detail": "Service unavailable: memory pressure too high"})

        return await call_next(request)


# ==========================================
# 2. REDIS-TO-WEBSOCKET BRIDGE (TENANT AWARE)
# ==========================================
async def redis_to_websocket_listener(app: FastAPI):
    """Enterprise-grade self-healing listener for Redis alerts using the app global pool."""
    print("📡 Redis-to-WebSocket Listener Active & Waiting...")
    while True:
        r = None
        pubsub = None
        try:
            r = getattr(app.state, "redis", None)
            if r is None:
                # fallback to temporary connection if global pool isn't attached yet
                r = await aioredis.from_url(
                    settings.redis_url,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    health_check_interval=30,
                )

            pubsub = r.pubsub()
            await pubsub.subscribe("security_alerts")

            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if not message:
                    await asyncio.sleep(0.1)
                    continue
                if message["type"] == "message":
                    alert_data = json.loads(message["data"])
                    tenant_id = alert_data.get("tenant_id")
                    if tenant_id:
                        await manager.broadcast_to_tenant(tenant_id, alert_data)
                        print(f" BROADCASTED to [{tenant_id}]: {alert_data.get('summary', alert_data.get('type', 'alert'))}")
        except Exception as e:
            print(f" Redis Connection lost. Retrying... ({e})")
            await asyncio.sleep(2)
        finally:
            try:
                if pubsub is not None:
                    await pubsub.close()
            except Exception:
                pass
            # only close temporary connections
            try:
                if r is not None and getattr(app.state, "redis", None) is not r:
                    await r.close()
            except Exception:
                pass


async def bootstrap_threat_intel_to_redis(db, redis_client) -> int:
    """Hydrate the Redis threat intel cache from MongoDB with a 30-day TTL."""
    if not redis_client:
        return 0
    try:
        cursor = db["threat_intel_learned_ips"].find({}, {"_id": 0, "ip": 1})
        count = 0
        # 30 days = 2592000 seconds
        ttl = 2592000
        
        # Use pipeline for efficiency
        pipe = redis_client.pipeline()
        async for document in cursor:
            ip = str(document.get("ip") or "").strip()
            if ip:
                pipe.setex(f"threat_intel:ip:{ip}", ttl, "true")
                count += 1
                if count % 1000 == 0:
                    await pipe.execute()
                    pipe = redis_client.pipeline()
        
        # Execute remaining
        if count % 1000 != 0:
            await pipe.execute()
            
        print(f" Bootstrapped {count} malicious IPs to Redis with 30-day TTL.")
        return count
    except Exception as exc:
        print(f" Threat Intel bootstrap to Redis failed: {exc}")
        return 0

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
            redis_pool = create_redis_client(settings.redis_url)
            await redis_pool.ping()
            print("OK: Redis pool connected and ready.")
            break
        except Exception as e:
            print(f"WARN: Redis connection attempt {attempt} failed: {e}")
            if redis_pool is not None:
                try: await redis_pool.close()
                except Exception: pass
            if attempt < max_retries:
                await asyncio.sleep(backoff)
                backoff *= 2
            else:
                print(" Could not establish Redis connection after retries; starting in degraded mode.")

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
                        pool = create_redis_client(settings.redis_url)
                        await pool.ping()
                        app.state.redis = pool
                        print(" Redis health monitor: connected.")
                        backoff = 1
                    except Exception as e:
                        print(f" Redis health monitor: connect failed: {e}")
                        await asyncio.sleep(backoff)
                        backoff = min(backoff * 2, 30)
                else:
                    try:
                        await r.ping()
                    except Exception as e:
                        print(f" Redis health monitor: ping failed: {e}")
                        try:
                            await r.close()
                        except Exception:
                            pass
                        app.state.redis = None
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f" Redis health monitor unexpected error: {e}")
            await asyncio.sleep(5)

    monitor_task = asyncio.create_task(redis_health_monitor())

    async def _connect_mongo_with_retries(run_schema: bool):
        max_db_retries = 10
        db_backoff = 2

        for attempt in range(1, max_db_retries + 1):
            try:
                print(f" MongoDB connection attempt {attempt}/{max_db_retries}...")
                if run_schema:
                    await init_db()
                    if db_manager.db is not None:
                        await init_compliance_db(db_manager.db)
                        print(" MongoDB & Compliance Schema initialized successfully.")
                        return True
                else:
                    await db_manager.connect()
                    print(" MongoDB connected without schema migration.")
                    return True
            except Exception as e:
                print(f" MongoDB attempt {attempt} failed: {e}")
                if attempt < max_db_retries:
                    await asyncio.sleep(db_backoff)
                    db_backoff = min(db_backoff * 1.5, 10)
                else:
                    print("FATAL: Could not establish MongoDB connection after retries.")
                    return False

        return False

    async def _run_schema_boot_once():
        redis_client = getattr(app.state, "redis", None)
        if redis_client is None:
            return await _connect_mongo_with_retries(run_schema=True)

        lock_token = str(uuid.uuid4())
        owns_lock = False
        try:
            owns_lock = bool(
                await redis_client.set(
                    SCHEMA_BOOT_LOCK_KEY,
                    lock_token,
                    nx=True,
                    ex=180,
                )
            )

            if owns_lock:
                await redis_client.delete(SCHEMA_BOOT_READY_KEY)
                ok = await _connect_mongo_with_retries(run_schema=True)
                if ok:
                    await redis_client.setex(SCHEMA_BOOT_READY_KEY, 3600, "1")
                return ok

            # Another API worker is doing schema/index work. Wait so this
            # worker does not serve requests while indexes are being dropped.
            for _ in range(60):
                if await redis_client.exists(SCHEMA_BOOT_READY_KEY):
                    return await _connect_mongo_with_retries(run_schema=False)
                if not await redis_client.exists(SCHEMA_BOOT_LOCK_KEY):
                    break
                await asyncio.sleep(2)

            print(" Schema boot lock wait expired; connecting without schema migration.")
            return await _connect_mongo_with_retries(run_schema=False)
        finally:
            if owns_lock:
                try:
                    if await redis_client.get(SCHEMA_BOOT_LOCK_KEY) == lock_token:
                        await redis_client.delete(SCHEMA_BOOT_LOCK_KEY)
                except Exception as e:
                    print(f" Schema boot lock cleanup failed: {e}")

    schema_boot_timeout = int(os.getenv("SCHEMA_BOOT_TIMEOUT_SECONDS", "45"))
    try:
        await asyncio.wait_for(_run_schema_boot_once(), timeout=schema_boot_timeout)
    except asyncio.TimeoutError:
        print(f" Schema boot timed out after {schema_boot_timeout}s; connecting without schema migration.")
        await _connect_mongo_with_retries(run_schema=False)
    
    startup_cache_timeout = int(os.getenv("STARTUP_CACHE_TIMEOUT_SECONDS", "5"))

    #  SYNC TENANT CACHE (Enterprise plan and entitlement optimization)
    if db_manager.db is not None and app.state.redis is not None:
        try:
            await asyncio.wait_for(
                sync_tenant_cache(db_manager.db, app.state.redis),
                timeout=startup_cache_timeout,
            )
        except asyncio.TimeoutError:
            print(f" Tenant cache sync timed out after {startup_cache_timeout}s; continuing startup.")
        except Exception as e:
            print(f" Tenant cache sync failed: {e}")

    if db_manager.db is not None and app.state.redis is not None:
        try:
            await asyncio.wait_for(
                bootstrap_threat_intel_to_redis(db_manager.db, app.state.redis),
                timeout=startup_cache_timeout,
            )
        except asyncio.TimeoutError:
            print(f" Threat intel bootstrap timed out after {startup_cache_timeout}s; continuing startup.")
        except Exception as e:
            print(f" Threat intel bootstrap failed: {e}")

    listener_task = asyncio.create_task(redis_to_websocket_listener(app))
    yield
    print(" Shutting down WarSOC Backend...")
    # Cancel background tasks and close Redis gracefully
    try:
        monitor_task.cancel()
    except Exception:
        pass
    try:
        listener_task.cancel()
    except Exception:
        pass
    await asyncio.gather(monitor_task, listener_task, return_exceptions=True)
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
# 4.1 RATE LIMITING & PROXY SECURITY
# ==========================================
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware


def _parse_trusted_proxy_hosts(raw_hosts: str) -> list[str]:
    hosts = [host.strip() for host in raw_hosts.split(",") if host.strip()]
    return hosts or ["127.0.0.1", "::1"]


trusted_proxy_hosts = _parse_trusted_proxy_hosts(
    os.getenv("TRUSTED_PROXY_HOSTS", "127.0.0.1,::1,localhost")
)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=trusted_proxy_hosts)
# Relax memory pressure blocking in non-production environments to allow local E2E testing.
if settings.environment.lower() == "production":
    # Enforce strict memory limits in production only
    app.add_middleware(MemoryLimitMiddleware, threshold=0.85)
else:
    # Skip memory blocking locally to allow integration and pressure testing
    print("[WARN] MemoryLimitMiddleware disabled in non-production environment for local testing.")
    # Force a no-op dispatch to ensure no memory check runs in any local/test context
    async def _noop_dispatch(self, request: Request, call_next):
        return await call_next(request)

    MemoryLimitMiddleware.dispatch = _noop_dispatch

from app.utils.limiter import limiter
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Too many requests. Please try again later."})




# Parse allowed origins from settings (comma-separated string)
_allowed_origins = _parse_allowed_origins()

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(
        "Request validation failed: method=%s path=%s errors=%s",
        request.method,
        request.url.path,
        exc.errors(),
    )
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )

@app.middleware("http")
async def memory_debug_middleware(request: Request, call_next):
    if logger.isEnabledFor(logging.DEBUG):
        now = time.monotonic()
        last_check = getattr(app.state, "_memory_debug_last_check", 0.0)
        if now - last_check >= 5.0:
            try:
                app.state._memory_debug_percent = psutil.virtual_memory().percent
            except Exception:
                app.state._memory_debug_percent = None
            app.state._memory_debug_last_check = now
        logger.debug(
            "[Memory Debug] env=%s mem_percent=%s",
            settings.environment,
            getattr(app.state, "_memory_debug_percent", None),
        )
    return await call_next(request)

# ==========================================
# 5. UNIFIED ROUTERS
# ==========================================
app.include_router(threat_intel.router, prefix="/api/v1", tags=["Security Ops"])
app.include_router(ingest_pulse.router, prefix="/api/v1/ingest", tags=["Ingestion"])
from app.routes import agent_orchestration
app.include_router(agent_orchestration.router, prefix="/api/v1/agent", tags=["Agent Orchestration"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(account.router, prefix="/api/v1/auth", tags=["Auth Security"])
app.include_router(pos.router, prefix="/api/v1/fbr/pos", tags=["FBR POS"])
app.include_router(upload.router, prefix="/api/v1/upload", tags=["Upload"])
app.include_router(compliance.router, prefix="/api/v1/compliance", tags=["Compliance"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alert Management"])
app.include_router(logs.router, prefix="/api/v1/logs", tags=["Dashboard Logs"])

app.include_router(admin.router, prefix="/api/v1/admin", tags=["Admin Control Plane"])
app.include_router(sales.router, prefix="/api/v1/sales", tags=["Sales"])
app.include_router(export.router, prefix="/api/v1/export", tags=["Export"])
app.include_router(metrics.router, prefix="", tags=["Metrics"])


#  CTO FIX: Remove ingestion.router to prevent prefix collision with ingest_pulse.router
# app.include_router(ingestion.router, prefix="/api/v1/ingest", tags=["Compliance Ingestion"])

# Legacy support
if settings.enable_legacy_routes:
    app.include_router(threat_intel.router, prefix="/firewall", tags=["Legacy Mitigation"])
    app.include_router(upload.router, prefix="/upload", tags=["Legacy Upload"])
    app.include_router(auth.router, prefix="/auth", tags=["Legacy Auth"])
app.include_router(data.router, prefix="/api/v1/data", tags=["Data Engine"])


@app.get("/health", tags=["System Health"])
async def health_check(request: Request):
    dependencies = {"mongodb": "unavailable", "redis": "unavailable"}

    try:
        if db_manager.db is not None:
            await db_manager.db.command("ping")
            dependencies["mongodb"] = "healthy"
    except Exception:
        logger.exception("MongoDB readiness check failed")

    try:
        redis_client = getattr(request.app.state, "redis", None)
        if redis_client is not None and await redis_client.ping():
            dependencies["redis"] = "healthy"
    except Exception:
        logger.exception("Redis readiness check failed")

    if any(value != "healthy" for value in dependencies.values()):
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "dependencies": dependencies},
        )
    return {"status": "healthy", "dependencies": dependencies}


@app.post("/api/v1/ws/ticket")
async def create_ws_ticket(
    request: Request,
    current_user: dict = Depends(get_current_user),
    _: str = Depends(RoleChecker(["admin", "manager", "analyst"])),
):
    redis_client = getattr(request.app.state, "redis", None)
    if not redis_client:
        raise HTTPException(status_code=503, detail="WebSocket ticket service unavailable")

    jti = current_user.get("current_jti")
    tenant_id = current_user.get("tenant_id")
    if not jti or not tenant_id:
        raise HTTPException(status_code=401, detail="Invalid session for WebSocket ticket issuance")

    ticket = str(uuid.uuid4())
    ticket_payload = json.dumps({"jti": jti, "tenant_id": tenant_id})
    await redis_client.setex(f"{WS_TICKET_PREFIX}{ticket}", 30, ticket_payload)

    return {"ticket": ticket, "expires_in_seconds": 30}

# ==========================================
# 5.5 DASHBOARD ROUTES (Moved to app/routes/logs.py)
# ==========================================
# ==========================================
# 6. WEBSOCKET ENDPOINT (BULLETPROOF AUTH)
# ==========================================
@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    #  CTO FIX: Require a short-lived single-use WebSocket ticket
    ticket = websocket.query_params.get("ticket")

    if not ticket:
        print(" WebSocket Rejected: No ticket provided in URL.")
        await websocket.close(code=4001, reason="No ticket provided")
        return

    try:
        redis_client = getattr(websocket.app.state, "redis", None)
        if not redis_client:
            print(" WebSocket Rejected: Redis unavailable for ticket validation.")
            await websocket.close(code=4001, reason="Ticket validation unavailable")
            return

        ticket_key = f"{WS_TICKET_PREFIX}{ticket}"
        raw_ticket_payload = await redis_client.execute_command("GETDEL", ticket_key)
        if not raw_ticket_payload:
            print(" WebSocket Rejected: Ticket missing, expired, or already used.")
            await websocket.close(code=4001, reason="Invalid or expired ticket")
            return

        try:
            ticket_payload = json.loads(raw_ticket_payload)
        except Exception:
            print(" WebSocket Rejected: Ticket payload invalid.")
            await websocket.close(code=4001, reason="Invalid ticket payload")
            return

        tenant_id = ticket_payload.get("tenant_id")
        jti = ticket_payload.get("jti")
        if not tenant_id or not jti:
            print(" WebSocket Rejected: Ticket missing tenant or session binding.")
            await websocket.close(code=4001, reason="Invalid ticket binding")
            return

        is_blacklisted = await redis_client.exists(f"warsoc:blacklist:{jti}")
        if is_blacklisted:
            print(f" WebSocket Rejected: Ticket-bound token {jti} is blacklisted.")
            await websocket.close(code=4001, reason="Token revoked")
            return

        # Handshake successful, pass to the private Tenant Room
        await manager.connect(websocket, tenant_id)

        # Concurrent background check loop to enforce blacklist eviction within 60s
        async def blacklist_watcher():
            try:
                while True:
                    await asyncio.sleep(60)
                    is_blacklisted = await redis_client.exists(f"warsoc:blacklist:{jti}")
                    if is_blacklisted:
                        print(f" WebSocket Eviction: Token {jti} has been blacklisted. Closing socket.")
                        try:
                            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Token revoked")
                        except Exception:
                            pass
                        break
            except asyncio.CancelledError:
                pass
            except Exception as e:
                print(f" Error in WebSocket blacklist watcher: {e}")

        watcher_task = asyncio.create_task(blacklist_watcher())

        try:
            while True:
                try:
                    await asyncio.wait_for(websocket.receive_text(), timeout=60)
                except asyncio.TimeoutError:
                    if await redis_client.exists(f"warsoc:blacklist:{jti}"):
                        print(f" WebSocket Closed: Token {jti} revoked during idle timeout.")
                        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Token revoked")
                        break
                    continue
        except WebSocketDisconnect:
            pass
        finally:
            watcher_task.cancel()
            manager.disconnect(websocket, tenant_id)

    except WebSocketException:
        # Let FastAPI/Starlette handle WebSocketException so the proper close code is sent
        raise
    except Exception as e:
        print(f" WebSocket System Error: {str(e)}")
        return

# WarSOC Backend — Comprehensive Implementation Plan

## Summary

This plan maps every finding from the end-to-end codebase audit to concrete code changes, organized by priority. Each section specifies the exact file, line range, current code pattern, and the required fix with rationale.

---

## P0 — Critical Fixes (Data Loss / Crashes / Security Bypass)

### P0-1: `detection_worker.py` — Ack Only on Success

**File:** `app/workers/detection_worker.py` ~L523  
**Problem:** Redis stream `XACK` fires regardless of processing outcome; failed events are permanently lost.  
**Fix:** Move `XACK` inside the success branch; on failure, leave the message in the stream for redelivery (or push to a dead-letter stream).

```python
# BEFORE (broken)
try:
    await process_event(event)
except Exception as e:
    logger.error(f"Detection processing failed: {e}")
    # BUG: XACK still fires below
await redis.xack(stream, group, msg_id)

# AFTER (fixed)
try:
    await process_event(event)
    await redis.xack(stream, group, msg_id)
except Exception as e:
    logger.error(f"Detection processing failed: {e}; message stays in stream for redelivery")
    # Do NOT ack — message remains pending for XREADGROUP
```

---

### P0-2: `fbr_worker.py` — Clear Buffer Only After Confirmed Write

**File:** `app/workers/fbr_worker.py`  
**Problem:** Processing buffer cleared before MongoDB write confirmation; evidence lost on write failure.  
**Fix:** Move buffer clear to after the confirmed write succeeds; add dead-letter queue (DLQ) on failure.

```python
# BEFORE (broken)
buffer.clear()
try:
    await db.fbr_events.insert_many(processed_docs)
except Exception:
    # Buffer already cleared — evidence gone
    logger.error("FBR write failed")

# AFTER (fixed)
try:
    result = await db.fbr_events.insert_many(processed_docs)
    if result.acknowledged:
        buffer.clear()
    else:
        raise RuntimeError("FBR write not acknowledged")
except Exception as e:
    logger.error(f"FBR write failed, buffering for retry: {e}")
    # Buffer preserved — retry on next cycle
    await _push_to_dlq("fbr_dlq", processed_docs, redis)
```

---

### P0-3: `peca_worker.py` — Remove `sys.exit(1)`

**File:** `app/workers/peca_worker.py`  
**Problem:** `sys.exit(1)` kills the entire process (all 6 workers in unified mode).  
**Fix:** Replace with `raise`; `safe_worker_runner` in `unified_worker.py` already catches exceptions and restarts.

```python
# BEFORE (broken)
if not db:
    logger.critical("MongoDB connection lost")
    sys.exit(1)

# AFTER (fixed)
if not db:
    raise RuntimeError("PECA worker: MongoDB connection lost — safe_worker_runner will restart")
```

---

### P0-4: `siem_worker.py` — Catch Per-Event Exceptions in Batch

**File:** `app/workers/siem_worker.py` ~L924  
**Problem:** Exception on one event raises out of the entire batch loop; remaining events dropped.  
**Fix:** Wrap per-event processing in try/except inside the batch loop.

```python
# BEFORE (broken)
for event in batch:
    enriched = await enrich_event(event)  # raises → drops remaining batch
    await db.security_alerts.insert_one(enriched)

# AFTER (fixed)
for event in batch:
    try:
        enriched = await enrich_event(event)
        await db.security_alerts.insert_one(enriched)
    except Exception as e:
        logger.error(f"Failed to process event {event.get('event_id')}: {e}")
        # Log and continue; remaining batch events are processed
```

---

### P0-5: `syslog_receiver.py` L88 — Add `tenant_id` to TCP Handler

**File:** `app/syslog_receiver.py` L67-88  
**Problem:** UDP handler (L56-58) attaches `tenant_id`; TCP handler (L88) only sends `{"payload": payload}` — tenant isolation bypass.  
**Fix:** Mirror the UDP tenant-lookup logic into the TCP handler.

```python
# AFTER (fixed TCP handler)
async def handle_tcp_client(reader, writer, redis):
    addr = writer.get_extra_info('peername')
    src_ip = addr[0] if addr else 'unknown'
    # ... existing connection limit check ...

    try:
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not line:
                break
            payload = line.decode(errors='ignore').strip()

            # Tenant isolation — mirror UDP handler logic
            tenant_id = ip_tenant_cache.get(src_ip)
            if not tenant_id and mongo_db is not None:
                agent = await mongo_db['agents'].find_one({"last_ip": src_ip})
                if agent:
                    tenant_id = agent.get("tenant_id")
                    ip_tenant_cache[src_ip] = tenant_id
                else:
                    tenant_id = "WARSOC_NETWORK"

            queue_name = getattr(settings, 'raw_logs_queue', 'raw_logs_queue')
            await redis.xadd(queue_name, {
                "payload": payload,
                "tenant_id": tenant_id or "WARSOC_NETWORK"
            })
    except asyncio.TimeoutError:
        logger.warning(f"TCP connection from {src_ip} timed out.")
    # ... rest of finally block unchanged ...
```

---

### P0-6: `warsoc_omni_audit.py` — Move Out of `app/utils/`

**File:** `app/utils/warsoc_omni_audit.py` L62  
**Problem:** `xtrim("raw_logs_queue", maxlen=0)` destroys all tenants' ingestion queues; script lives in importable `app/utils/`.  
**Fix:**
1. Move file from `app/utils/warsoc_omni_audit.py` → `scripts/warsoc_omni_audit.py`
2. Remove `xtrim` to maxlen=0 or scope it to test tenant only
3. Add confirmation prompt and `--force` flag

---

### P0-7: `test_combined_final_acceptance.py` L65 — Scope `delete_many`

**File:** `tests/test_combined_final_acceptance.py` L65  
**Problem:** `delete_many({})` with empty filter deletes across ALL tenants.  
**Fix:** Add tenant_id filter; also rename file to avoid pytest auto-collection.

```python
# BEFORE
await db["detection_engine_agent_bindings"].delete_many({})

# AFTER
await db["detection_engine_agent_bindings"].delete_many({"tenant_id": tenant_id})
```

---

## P1 — Performance Optimizations (Highest ROI)

### P1-1: `rbac.py` — Cache Role in Redis (40-60% MongoDB Load Reduction)

**File:** `app/utils/rbac.py` L38-40  
**Current:** `db["users"].find_one({"username": username, "tenant_id": tenant_id})` on every authenticated request.  
**Fix:** Cache `(username, tenant_id) → role` in Redis with 60s TTL.

```python
# AFTER (rbac.py with Redis cache)
import json
from app.utils.redis_client import get_redis

class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = [str(role).strip().lower() for role in allowed_roles]

    async def __call__(self, request: Request, token: str = Depends(oauth2_scheme), db = Depends(get_db)):
        try:
            token = token or request.cookies.get("warsoc_token")
            if not token:
                raise HTTPException(status_code=401, detail="Could not validate credentials for RBAC")

            payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
            username = payload.get("sub")
            tenant_id = payload.get("tenant_id")
            token_type = payload.get("type")
            if token_type != "user" or not username or not tenant_id:
                raise HTTPException(status_code=401, detail="Could not validate credentials for RBAC")

            # Redis cache check (60s TTL)
            cache_key = f"rbac:{tenant_id}:{username}"
            redis = await get_redis()
            cached_role = await redis.get(cache_key)

            if cached_role:
                user_role = cached_role
            else:
                user = await db["users"].find_one(
                    {"username": username, "tenant_id": tenant_id},
                    {"role": 1}
                )
                if not user:
                    raise HTTPException(status_code=401, detail="User not found")
                user_role = str(user.get("role") or "").strip().lower()
                await redis.set(cache_key, user_role, ex=60)

            if user_role not in self.allowed_roles:
                raise HTTPException(status_code=403,
                    detail=f"Restricted to: {', '.join(self.allowed_roles)}. Your role: {user_role}")
            return user_role
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Could not validate credentials for RBAC")
```

**Cache invalidation:** In `app/routes/admin.py` and `app/routes/auth.py`, on any role change:
```python
await redis.delete(f"rbac:{tenant_id}:{username}")
```

---

### P1-2: `key_lifecycle.py` — Cache Fernet Ciphers

**File:** `app/utils/key_lifecycle.py` L57-82  
**Current:** `Fernet()` constructed and JSON parsed on every call.  
**Fix:** Cache active key and historical keyring at module level.

```python
# AFTER (add caching to key_lifecycle.py)
from functools import lru_cache

_ACTIVE_KEY_CACHE: SourceEnvelopeKey | None = None
_HISTORICAL_KEYRING_CACHE: dict[str, SourceEnvelopeKey] | None = None

def active_source_envelope_key() -> SourceEnvelopeKey:
    global _ACTIVE_KEY_CACHE
    if _ACTIVE_KEY_CACHE is not None:
        return _ACTIVE_KEY_CACHE
    settings = get_settings()
    key_material = settings.source_envelope_encryption_key or settings.encryption_key
    _ACTIVE_KEY_CACHE = SourceEnvelopeKey(
        key_id=settings.source_envelope_key_id,
        version=settings.source_envelope_key_version,
        cipher=_cipher(key_material, key_id=settings.source_envelope_key_id),
    )
    return _ACTIVE_KEY_CACHE

def source_envelope_decryption_key(key_id, key_version=None) -> SourceEnvelopeKey:
    global _HISTORICAL_KEYRING_CACHE
    settings = get_settings()
    active = active_source_envelope_key()
    if _HISTORICAL_KEYRING_CACHE is None:
        _HISTORICAL_KEYRING_CACHE = _historical_keyring(settings)
    resolved = active if not key_id or key_id == active.key_id else _HISTORICAL_KEYRING_CACHE.get(key_id)
    # ... rest unchanged ...
```

---

### P1-3: Consolidate `_PACK_ALIASES` to Single Source

**File:** `app/utils/tenant_cache.py` L10-18  
**Current:** Duplicated in 6+ files (`auth.py`, `compliance.py`, `logs.py`, `network_relay.py`, `agent_orchestration.py`).  
**Fix:** Import from `tenant_cache.py` everywhere.

```python
# In each consuming file, replace local copy with:
from app.utils.tenant_cache import _PACK_ALIASES, normalize_pack_id

# Remove all local _PACK_ALIASES dict definitions from:
# - app/routes/auth.py L126-138
# - app/routes/compliance.py L604-644
# - app/routes/logs.py L172-186
# - app/routes/network_relay.py
# - app/routes/agent_orchestration.py L39
```

---

### P1-4: Batch `count_documents` with `$facet` Aggregation

**File:** `app/routes/incidents.py` L148-161 (5 sequential calls)  
**Current:** 5 separate `count_documents()` calls for critical/high/medium/low/total.  
**Fix:** Single aggregation pipeline with `$facet`.

```python
# AFTER (single aggregation for all counts)
pipeline = [
    {"$match": {"tenant_id": tenant_id}},
    {"$facet": {
        "critical": [{"$match": {"severity": "critical"}}, {"$count": "count"}],
        "high":     [{"$match": {"severity": "high"}},     {"$count": "count"}],
        "medium":   [{"$match": {"severity": "medium"}},   {"$count": "count"}],
        "low":      [{"$match": {"severity": "low"}},      {"$count": "count"}],
        "total":    [{"$count": "count"}],
    }}
]
result = await db.security_incidents.aggregate(pipeline).to_list(1)
counts = result[0] if result else {}
```

**Apply same pattern to:** `network_relay.py` L557-558, `alerts.py` L165, `agent_orchestration.py` L260-267.

---

### P1-5: Add `.limit()` + Pagination to Unbounded Queries

**Files and fixes:**

```python
# threat_intel.py L65-68 — Add limit
cursor = db.threat_intel_feeds.find({"tenant_id": tenant_id}).limit(1000)

# evidence_cases.py L324-329 — Already has skip/limit but 5K/10K caps are too high
# Lower to reasonable page size and require explicit pagination
cursor = db.evidence_cases.find(query).skip(skip).limit(min(limit, 100))

# admin.py L244 — Add limit
tenants = await db.tenants.find({}).limit(100).to_list(100)

# data.py L208 — Already has limit(1000); add explicit pagination parameter
```

---

### P1-6: Add gzip Compression to Nginx

**Files:** `nginx/nginx.conf`, `nginx/nginx.prod.conf`  
**Fix:** Add gzip block in both files inside the `http {}` block.

```nginx
# Add after `sendfile on;` in both nginx.conf and nginx.prod.conf:
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_min_length 1024;
gzip_types
    application/json
    application/javascript
    text/css
    text/plain
    text/xml
    application/xml;
```

---

### P1-7: Skip Backfills on Repeat Startup

**File:** `app/db/init_db.py` L47-81, L253-268, L505-548, L906-914  
**Current:** Three `update_many` backfills + incident backfill run unconditionally.  
**Fix:** Track completion in `system_migrations` collection.

```python
# Add at the top of init_db.py
MIGRATION_COLLECTION = "system_migrations"

async def _migration_done(db, migration_id: str) -> bool:
    doc = await db[MIGRATION_COLLECTION].find_one({"_id": migration_id})
    return doc is not None

async def _mark_migration_done(db, migration_id: str):
    await db[MIGRATION_COLLECTION].update_one(
        {"_id": migration_id},
        {"$set": {"completed_at": datetime.now(timezone.utc)}},
        upsert=True,
    )

# Wrap each backfill:
async def _backfill_expire_at_if_needed(db, collection, retention_days, migration_id):
    if await _migration_done(db, migration_id):
        logger.info(f"Skipping backfill {migration_id} (already completed)")
        return
    await _backfill_expire_at(collection, retention_days)
    await _mark_migration_done(db, migration_id)
```

---

### P1-8: Parallelize Index Creation

**File:** `app/db/init_db.py` L158-920  
**Current:** ~90 indexes created sequentially with individual `await` calls.  
**Fix:** Group independent collection indexes into `asyncio.gather` batches.

```python
# AFTER (batch by collection group)
import asyncio

async def _create_indexes_batch(tasks: list):
    """Run index creations concurrently, log individual failures."""
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Index creation task {i} failed: {result}")

# Group: users collection indexes
await _create_indexes_batch([
    _aggressive_create_index(db.users, [("email", 1)], ...),
    _aggressive_create_index(db.users, [("username", 1)], ...),
    _aggressive_create_index(db.users, [("tenant_id", 1), ("status", 1)], ...),
])

# Group: evidence collections (independent)
await _create_indexes_batch([
    _aggressive_create_index(db.peca_evidence, ...),
    _aggressive_create_index(db.fbr_evidence, ...),
    _aggressive_create_index(db.siem_alerts, ...),
])
# ... continue for remaining groups ...
```

---

### P1-9: `_vt_cache` — Add Size Limit + TTL

**File:** `app/utils/threat_intel.py` L16, L138-143  
**Current:** `self._vt_cache = {}` — unbounded dict, no eviction.  
**Fix:** Use `OrderedDict` with maxsize + per-entry TTL.

```python
from collections import OrderedDict

MAX_VT_CACHE_SIZE = 10000
VT_CACHE_TTL_SECONDS = 86400  # 24 hours

class ThreatIntelligenceManager:
    def __init__(self, config):
        # ...
        self._vt_cache: OrderedDict[str, tuple] = OrderedDict()
        self._vt_cache_ts: dict[str, float] = {}

    async def check_reputation(self, ip, db=None, redis_client=None):
        # ...
        # TTL-aware cache lookup
        if ip in self._vt_cache:
            age = time.time() - self._vt_cache_ts.get(ip, 0)
            if age < VT_CACHE_TTL_SECONDS:
                return self._vt_cache[ip]
            else:
                del self._vt_cache[ip]
                del self._vt_cache_ts[ip]

        # On cache insert, evict oldest if full
        if len(self._vt_cache) >= MAX_VT_CACHE_SIZE:
            self._vt_cache.popitem(last=False)

        # ... on cache store:
        self._vt_cache[ip] = (is_malicious, msg)
        self._vt_cache_ts[ip] = time.time()
```

---

### P1-10: `upload.py` — Use Global Rate Limiter

**File:** `app/routes/upload.py` L25  
**Current:** Creates its own `Limiter` instance with separate Redis keyspace.  
**Fix:** Import and use the global limiter.

```python
# BEFORE
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

# AFTER
from app.utils.limiter import limiter
```

---

## P2 — Code Quality & Maintainability

### P2-1: Move Sync I/O to `asyncio.to_thread()`

**File:** `app/routes/upload.py` L225-266  
**Fix:**
```python
# BEFORE (blocking event loop)
with open(file_path, "wb") as f:
    f.write(content)

# AFTER (non-blocking)
await asyncio.to_thread(_write_file, file_path, content)

def _write_file(path: str, content: bytes):
    with open(path, "wb") as f:
        f.write(content)
```

**File:** `app/routes/export.py` L408-528  
**Fix:** Same pattern — wrap PDF generation in `asyncio.to_thread()`.

---

### P2-2: Replace `print()` with `logging` in `main.py`

**File:** `app/main.py`  
**Current:** ~20 `print()` calls alongside an already-defined `logger`.  
**Fix:** Global replace `print(` → `logger.info(` with appropriate level.

```python
# BEFORE
print(f"✓ MongoDB connected")
print(f"⚠ Redis unavailable: {e}")

# AFTER
logger.info("MongoDB connected")
logger.warning(f"Redis unavailable: {e}")
```

**Scope:** Same replacement needed across all route/worker files that use `print()`.

---

### P2-3: Share MotorClient Across Unified Workers

**File:** `app/workers/unified_worker.py`  
**Current:** Each worker creates its own `AsyncIOMotorClient` = 6 connection pools.  
**Fix:** Create one shared client, pass as parameter.

```python
# AFTER (unified_worker.py)
async def unified_worker_main():
    # Single shared MongoDB client for all workers
    mongo_client = AsyncIOMotorClient(settings.mongodb_uri, maxPoolSize=50)
    db = mongo_client[settings.mongodb_db_name]

    results = await asyncio.gather(
        safe_worker_runner(siem_worker, "SIEM Engine", db=db),
        safe_worker_runner(fbr_worker, "FBR Archiver", db=db),
        safe_worker_runner(peca_worker, "PECA Forensic", db=db),
        safe_worker_runner(run_email_daemon, "Email Daemon", db=db),
        safe_worker_runner(stream_retention_worker, "Stream Retention"),
        safe_worker_runner(source_outbox_worker, "Source Evidence Outbox", db=db),
        return_exceptions=True
    )

    mongo_client.close()
```

Each worker signature changes from `async def siem_worker():` to `async def siem_worker(db=None):`, using the shared `db` if provided.

---

### P2-4: Fix `siem_privacy.py` Fail-Open Decryption

**File:** `app/utils/siem_privacy.py` L88-98  
**Current:** Decryption failure silently returns ciphertext.  
**Fix:** Log the failure and mark the document.

```python
# AFTER (L95-98)
def decrypt_siem_value(value, fernet):
    # ... prefix handling unchanged ...
    try:
        plaintext = fernet.decrypt(token.encode("ascii")).decode("utf-8")
    except Exception as exc:
        logger.warning(f"SIEM decryption failed for field (version={SIEM_ENCRYPTION_VERSION}): {exc}")
        return f"[DECRYPTION_FAILED:{SIEM_ENCRYPTION_VERSION}]"
    # ... json.loads unchanged ...
```

---

### P2-5: Fix `source_provenance.py` Classification Order

**File:** `app/utils/source_provenance.py` L34-37  
**Current:** `event_type == "network_log"` short-circuits before relay attestation check.  
**Fix:** Check relay attestation FIRST.

```python
# BEFORE (L34-37)
if event_type == "network_log":
    return LEGACY_SYSLOG, NETWORK_TELEMETRY_PROFILE
if assurance == "relay_attested" and signature_verified:
    return RELAY_ATTESTED_NETWORK, NETWORK_TELEMETRY_PROFILE

# AFTER (swap order)
if assurance == "relay_attested" and signature_verified:
    return RELAY_ATTESTED_NETWORK, NETWORK_TELEMETRY_PROFILE
if event_type == "network_log":
    return LEGACY_SYSLOG, NETWORK_TELEMETRY_PROFILE
```

---

### P2-6: Fix `agent_lifecycle.py` Fail-Open Default

**File:** `app/utils/agent_lifecycle.py` L8-10  
**Current:** `None` and empty string normalize to `"active"`.  
**Fix:** Use permit-list instead of deny-list.

```python
# BEFORE
def normalize_agent_lifecycle_status(value: object) -> str:
    status = str(value or "active").strip().lower()
    return status or "active"

# AFTER
KNOWN_ACTIVE_STATES = frozenset({"active", "enrolled", "pending_enrollment"})

def normalize_agent_lifecycle_status(value: object) -> str:
    status = str(value or "").strip().lower()
    if not status:
        return "unknown"
    return status

def agent_lifecycle_is_active(value: object) -> bool:
    return normalize_agent_lifecycle_status(value) in KNOWN_ACTIVE_STATES
```

---

### P2-7: Replace `deepcopy` in `telemetry_groups.py`

**File:** `app/utils/telemetry_groups.py` L58-62  
**Current:** `deepcopy(dict(event))` for every event.  
**Fix:** Shallow copy suffices.

```python
# BEFORE
row = deepcopy(dict(event))

# AFTER
row = dict(event)  # shallow copy — no nested mutation occurs
```

---

### P2-8: Delete `_deprecated_stateful_engine.py`

**File:** `app/utils/_deprecated_stateful_engine.py` (460 lines)  
**Action:** `git rm` the file. History preserves it. No imports reference it.

---

### P2-9: TOTP Secret — Only Return During Initial Enrollment

**File:** `app/routes/account.py` L175  
**Fix:** Check if TOTP was already set up; if so, don't return the secret.

```python
# AFTER
if not user.get("totp_enabled"):
    # Initial enrollment — return secret for QR code
    return {"totp_secret": secret, "totp_uri": uri}
else:
    # Already enrolled — never expose secret again
    return {"message": "TOTP already configured", "totp_enabled": True}
```

---

### P2-10: Stream Large Exports

**File:** `app/routes/compliance.py` ~L1301  
**Current:** Loads 50K docs, serializes, sends single response.  
**Fix:** Use `StreamingResponse`.

```python
# AFTER
from fastapi.responses import StreamingResponse

async def _chunked_export(db, tenant_id, limit):
    cursor = db.peca_evidence.find(
        {"tenant_id": tenant_id}
    ).limit(limit).batch_size(500)
    first = True
    yield "["
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        prefix = "" if first else ","
        first = False
        yield prefix + json.dumps(doc, default=str)
    yield "]"

@router.get("/export")
async def export_evidence(...):
    return StreamingResponse(
        _chunked_export(db, tenant_id, limit=50000),
        media_type="application/json"
    )
```

---

## P3 — Architecture Improvements (Long-Term)

### P3-1: Decompose `siem_logic.py` (2,308 lines)

**Target structure:**
```
app/utils/siem/
├── __init__.py           # Re-exports for backward compatibility
├── brute_force.py        # Brute-force correlation logic
├── port_scan.py          # Port scan detection
├── threat_intel.py       # Threat intelligence matching
├── mitigation.py         # Auto-mitigation / SOAR
├── aggregation.py        # Alert aggregation & grouping
└── scoring.py            # Risk scoring engine
```

### P3-2: Decompose `main.py` (759 lines)

**Target structure:**
```
app/
├── main.py               # Minimal — imports and registers everything
├── lifespan.py            # Startup/shutdown lifecycle (Redis, MongoDB, schema boot)
├── middleware.py           # MemoryLimitMiddleware, RequestIDMiddleware, etc.
├── websocket.py           # WebSocket endpoint + Redis pub/sub bridge
├── exception_handlers.py  # Custom exception handlers
└── router_registry.py     # Router registration
```

### P3-3: Add Schema Version Tracking

**File:** `app/db/init_db.py`  
**Fix:** Add version check at the top of `init_compliance_db()`.

```python
SCHEMA_VERSION = "2026.08.27"

async def init_compliance_db(db):
    migration_doc = await db.system_migrations.find_one({"_id": "schema_version"})
    if migration_doc and migration_doc.get("version") == SCHEMA_VERSION:
        logger.info(f"Schema already at version {SCHEMA_VERSION}, skipping index creation")
        return

    # ... existing index creation ...

    await db.system_migrations.update_one(
        {"_id": "schema_version"},
        {"$set": {"version": SCHEMA_VERSION, "applied_at": datetime.now(timezone.utc)}},
        upsert=True,
    )
```

### P3-4: Add Composite Indexes for Dashboard Queries

**File:** `app/db/init_db.py`  
**Add:**
```python
await _aggressive_create_index(db.security_incidents,
    [("tenant_id", 1), ("status", 1), ("severity", 1), ("created_at", -1)],
    name="idx_incidents_tenant_status_severity_time"
)
await _aggressive_create_index(db.security_alerts,
    [("tenant_id", 1), ("status", 1), ("severity", 1), ("timestamp", -1)],
    name="idx_alerts_tenant_status_severity_time"
)
```

---

## Execution Order

| Phase | Items | Estimated Time | Risk |
|-------|-------|---------------|------|
| **Phase 1** (Day 1) | P0-1 through P0-7 | 4-6 hours | Low (isolated fixes) |
| **Phase 2** (Day 2-3) | P1-1 (RBAC cache), P1-6 (gzip), P1-2 (Fernet cache) | 3-4 hours | Low |
| **Phase 3** (Day 3-4) | P1-3 (`_PACK_ALIASES`), P1-4 (`$facet`), P1-5 (`.limit()`) | 4-5 hours | Medium |
| **Phase 4** (Day 4-5) | P1-7 (backfill skip), P1-8 (parallel indexes), P1-9 (VT cache), P1-10 (limiter) | 4-5 hours | Medium |
| **Phase 5** (Week 2) | P2-1 through P2-10 | 8-12 hours | Low-Medium |
| **Phase 6** (Week 3+) | P3-1 through P3-4 | 2-3 days | Medium (refactoring) |

---

## Testing Strategy

| Fix Category | Test Approach |
|-------------|--------------|
| P0 worker fixes | Unit test: simulate failure → verify message NOT acked / buffer NOT cleared |
| P0 syslog tenant_id | Integration test: send TCP syslog → verify `tenant_id` present in Redis stream |
| P1 RBAC cache | Benchmark: measure MongoDB queries for 100 concurrent dashboard loads (before/after) |
| P1 gzip | `curl -H "Accept-Encoding: gzip"` → verify `Content-Encoding: gzip` header |
| P1 `$facet` | Verify single aggregation returns same counts as 5 sequential calls |
| P2 sync I/O | Load test: concurrent requests during file upload → verify no latency spike |
| P2 shared MotorClient | Verify `db.client.topology_description` shows single pool across workers |

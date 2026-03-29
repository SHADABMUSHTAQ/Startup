# WarSOC Backend — Comprehensive Code Audit

> **Date**: 2026-03-18 | **Scope**: Full backend codebase review  
> **Files reviewed**: 20+ source files across `app/`, [agent/](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/routes/auth.py#219-266), `scripts/`, and root

---

## Executive Summary

The WarSOC backend is a **FastAPI-based SIEM platform** with multi-tenant isolation, a Redis-backed real-time alerting pipeline, a background worker, and a downloadable Windows agent. The architecture is generally sound, but there are **critical security vulnerabilities**, several code quality issues, and reliability concerns that should be addressed before any production deployment.

| Category | 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low |
|---|---|---|---|---|
| Security | 4 | 3 | 2 | 1 |
| Reliability | 0 | 2 | 3 | 1 |
| Code Quality | 0 | 1 | 3 | 4 |
| **Totals** | **4** | **6** | **8** | **6** |

---

## 🔴 CRITICAL Findings

### 1. Secrets Committed to Source Control

> [!CAUTION]
> The root [.env](file:///c:/Users/Lenovo/Desktop/Startup-backend/.env) file contains **production secrets in plaintext** and, despite being listed in [.gitignore](file:///c:/Users/Lenovo/Desktop/Startup-backend/.gitignore), the [agent/.env](file:///c:/Users/Lenovo/Desktop/Startup-backend/agent/.env) file is **not gitignored** and contains the agent master secret.

**Files**: [.env](file:///c:/Users/Lenovo/Desktop/Startup-backend/.env), [agent/.env](file:///c:/Users/Lenovo/Desktop/Startup-backend/agent/.env)

```
# Root .env — hardcoded production credentials:
MONGO_PASSWORD=W4rS0c_M0ng0_S3cur3_2026!
REDIS_PASSWORD=W4rS0c_R3d1s_S3cur3_2026!
JWT_SECRET_KEY=W4rS0c_JWT_Pr0d_K3y_2026!_x9Fq2mZvR8
AGENT_MASTER_SECRET=W4rS0c_Ag3nt_M4st3r_2026!_k7Lp5nBwS1
```

```
# agent/.env — NOT gitignored:
AGENT_MASTER_SECRET=warsoc_enterprise_agent_key_2026
```

**Impact**: Full database, cache, and auth compromise if repo is exposed.  
**Fix**: Rotate all secrets immediately. Add [agent/.env](file:///c:/Users/Lenovo/Desktop/Startup-backend/agent/.env) to [.gitignore](file:///c:/Users/Lenovo/Desktop/Startup-backend/.gitignore). Use a secrets manager (Vault, AWS Secrets Manager, etc.) for production.

---

### 2. Hardcoded Fallback Secrets in Source Code

> [!CAUTION]
> Multiple files contain fallback default secrets directly in Python source.

**Files**: [config.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/config/config.py), [auth.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/routes/auth.py)

```python
# config.py:13-14
jwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "warsoc_secret_key_dev_only")
agent_master_secret: str = os.getenv("AGENT_MASTER_SECRET", "warsoc_enterprise_agent_key_2026")
secret_key: str = os.getenv("SECRET_KEY", "warsoc_secret_key_dev_only")

# auth.py:20-21
SECRET_KEY = getattr(settings, 'jwt_secret_key', "warsoc_secret_key_change_this_in_production")
AGENT_MASTER_SECRET = getattr(settings, 'agent_master_secret', "warsoc_enterprise_agent_key_2026")
```

**Impact**: If env vars aren't set, the app silently uses known, guessable secrets.  
**Fix**: Remove all default secret values. Fail fast (raise an error) if required secrets aren't provided.

---

### 3. No File Size Limit on CSV Upload

> [!CAUTION]
> The upload endpoint streams a file to disk without any file size validation.

**File**: [upload.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/routes/upload.py#L96-L112)

```python
# upload.py:110-112 — Streams the ENTIRE file, no size cap
async with aiofiles.open(file_path, "wb") as buffer:
    while chunk := await file.read(1024 * 1024):
        await buffer.write(chunk)
```

**Impact**: An attacker can upload a multi-GB file to exhaust disk space (DoS).  
**Fix**: Enforce `max_file_size_mb` from config (currently defined but never checked). Track bytes written and abort if exceeded.

---

### 4. Path Traversal Risk in File Upload

**File**: [upload.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/routes/upload.py#L105-L107)

```python
secure_original_name = os.path.basename(file.filename or "")
safe_filename = f"WarSOC_{secure_tenant_id}_{file_id}_{secure_original_name}"
file_path = os.path.join(UPLOAD_DIR, safe_filename)
```

While `os.path.basename()` is used (good), the `tenant_id` value comes from the JWT and is interpolated directly into the filename. If a tenant ID contains path separators or special characters, it could escape the upload directory.  
**Fix**: Sanitize `secure_tenant_id` to strip any `/`, `\`, `..`, or null characters before using it in file paths.

---

## 🟠 HIGH Findings

### 5. No Rate Limiting on Upload Endpoint

**File**: [upload.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/routes/upload.py#L96)

The `/api/v1/upload/analyze` endpoint has no `@limiter.limit()` decorator, unlike auth endpoints. A user could submit hundreds of large CSV files.

**Fix**: Add rate limiting, e.g., `@limiter.limit("5/minute")`.

---

### 6. Error Responses Leak Internal Details

**Files**: [upload.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/routes/upload.py#L228), [data.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/routes/data.py#L79), [main.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/main.py#L182)

```python
# upload.py:228
raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")

# data.py:79
raise HTTPException(status_code=500, detail=str(e))

# main.py:182
return {"status": "error", "message": str(e)}
```

**Impact**: Stack traces, database errors, and internal state could be returned to clients.  
**Fix**: Log errors server-side. Return generic error messages to clients.

---

### 7. WebSocket Lacks Proper Close on Auth Failure

**File**: [main.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/main.py#L186-L220)

```python
if not token:
    print("❌ WebSocket Rejected: No token provided in URL.")
    return  # Drop unauthenticated connection cleanly
```

Returning without calling `websocket.close()` after `websocket.accept()` is never called, which is technically okay, but the WebSocket protocol expects a close handshake. Some clients will hang.

**Fix**: Either accept-then-close with a proper close code (4001), or ensure the connection is never accepted (current behavior is borderline acceptable but could be cleaner).

---

### 8. Duplicate `redis.asyncio` Import

**File**: [threat_intel.py (routes)](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/routes/threat_intel.py#L12-L18)

```python
import redis.asyncio as aioredis  # Line 12
...
import redis.asyncio as aioredis  # Line 18 — duplicate
```

**Fix**: Remove the duplicate import on line 18.

---

## 🟡 MEDIUM Findings

### 9. [get_settings()](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/config/config.py#36-38) Creates a New Instance Every Call

**File**: [config.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/config/config.py#L36-L37)

```python
def get_settings():
    return Settings()
```

Every call re-reads env vars and re-instantiates the Settings object. This is called from many modules at import time.

**Fix**: Use `@lru_cache()` to cache the singleton instance:
```python
from functools import lru_cache

@lru_cache()
def get_settings():
    return Settings()
```

---

### 10. Bare `except` Clauses Swallow Errors

Multiple files use bare `except:` or `except Exception` blocks that silently pass:

| File | Line(s) | Issue |
|---|---|---|
| [main.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/main.py#L57) | 57 | `except: pass` in Redis cleanup |
| [main.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/main.py#L81) | 81 | `except: pass` in Redis retry |
| [data.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/routes/data.py#L55-L56) | 55-56 | `except: pass` in timestamp parsing |
| [threat_intel.py (utils)](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/utils/threat_intel.py#L114) | 114 | `except: continue` in CIDR check |

**Fix**: At minimum, log the exception. Prefer `except Exception as e: logger.warning(...)`.

---

### 11. Mutable Default Arguments in Pydantic Models

**File**: [models.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/models.py#L30), [ingest_pulse.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/routes/ingest_pulse.py#L23)

```python
# models.py:30
source_ips: Optional[List[str]] = []  # Mutable default

# ingest_pulse.py:23
raw_data: Union[dict, str] = {}  # Mutable default
```

Pydantic v2 handles this correctly, but it's a code smell and will break if used with plain dataclasses or older Pydantic.

**Fix**: Use `Field(default_factory=list)` or `Field(default_factory=dict)`.

---

### 12. `DatabaseManager.__getattr__` Is a Dangerous Magic Method

**File**: [database.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/database.py#L42-L45)

```python
def __getattr__(self, name):
    if self.db is not None:
        return getattr(self.db, name)
    raise AttributeError(...)
```

This proxies **any** attribute access to the underlying MongoDB database. It makes the code harder to understand, debug, and type-check. IDE autocompletion won't work. Typos like `db.usrs` silently create new collection references.

**Fix**: Use explicit collection accessor methods or properties.

---

### 13. Inconsistent Database Access Patterns

Across the routes, [db](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/database.py#109-114) is accessed in three different ways:
1. `db.users` — relying on [__getattr__](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/database.py#42-46) magic
2. `db.db["collection_name"]` — direct dictionary-style access
3. [getattr(db, "db", db)](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/database.py#42-46) — defensive pattern

This inconsistency creates confusion about what [db](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/database.py#109-114) actually is.

**Fix**: Standardize on one access pattern throughout the codebase.

---

### 14. Docker Exposes MongoDB Port to Host

**File**: [docker-compose.yml](file:///c:/Users/Lenovo/Desktop/Startup-backend/docker-compose.yml#L9-L10)

```yaml
ports:
  - "27017:27017"  # Expose for local testing only
```

The comment says "local testing only" but it will be exposed in any environment using this compose file.

**Fix**: Remove the port mapping or use a separate `docker-compose.override.yml` for development.

---

## 🔵 LOW Findings

### 15. `update-plan` Endpoint IDOR Risk

**File**: [auth.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/routes/auth.py#L267-L292)

The [PlanUpdate](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/routes/auth.py#35-38) model accepts a `username` field from the request body, but the route correctly uses `current_user["username"]` instead. The `data.username` field is unused — this is **good security**, but the dead parameter in the model should be removed to avoid confusion.

---

### 16. No Input Validation on IP Addresses in Ban/Unban

**File**: [threat_intel.py (routes)](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/routes/threat_intel.py#L58-L111)

The `BanRequest.ip` field accepts any string. An attacker could submit garbage data that gets stored in MongoDB and pushed to Redis.

**Fix**: Add Pydantic validation — `ip: constr(regex=r'^\d{1,3}...')` or use `ipaddress.ip_address()`.

---

### 17. Uploaded Files Are Never Cleaned Up

**File**: [upload.py](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/routes/upload.py#L107)

CSV files are written to `uploaded_files/` but never deleted, even when the analysis is deleted via the DELETE endpoint. Over time this will consume disk space.

**Fix**: Delete the physical file in the [delete_log](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/routes/upload.py#281-297) handler, or add a periodic cleanup job.

---

### 18. No HTTPS/TLS Configuration

The entire stack runs over plain HTTP. `BACKEND_PUBLIC_URL` defaults to `http://127.0.0.1:8000`. The WebSocket endpoint passes JWT tokens in query parameters — these will be visible in server logs and browser history without HTTPS.

**Fix**: Add TLS termination via a reverse proxy (nginx/Caddy) in production.

---

### 19. [docker-compose.yml](file:///c:/Users/Lenovo/Desktop/Startup-backend/docker-compose.yml) Embeds Fallback Secrets

```yaml
MONGO_INITDB_ROOT_PASSWORD: ${MONGO_PASSWORD:-W4rS0c_M0ng0_S3cur3_2026!}
```

Even with the [.env](file:///c:/Users/Lenovo/Desktop/Startup-backend/.env) file, the hardcoded fallback passwords in the compose file are a risk if the [.env](file:///c:/Users/Lenovo/Desktop/Startup-backend/.env) file is missing.

---

### 20. Dockerfile Runs as Root

**File**: [Dockerfile](file:///c:/Users/Lenovo/Desktop/Startup-backend/Dockerfile)

No `USER` directive is specified, so the container runs all processes as root.

**Fix**: Add a non-root user:
```dockerfile
RUN adduser --disabled-password --gecos '' appuser
USER appuser
```

---

## Architectural Observations

### ✅ Things Done Well
- **Multi-tenant isolation** is consistently enforced via `tenant_id` across all routes and the worker
- **Token blacklist** for logout is correctly implemented with TTL-based Redis keys
- **Rate limiting** is applied to auth endpoints
- **Async architecture** with proper use of `motor`, `redis.asyncio`, and FastAPI's async patterns
- **Chunked CSV processing** with batch inserts prevents OOM on large files
- **Stateful threat engine** with Redis-backed sliding windows is well designed
- **Agent download** generates per-tenant ZIP packages with hashed secrets

### 🔧 Improvement Suggestions
1. **Add structured logging** — replace `print()` calls with `logging` module throughout (currently inconsistent)
2. **Add health check endpoint** — `/health` for load balancer probes
3. **Add request ID tracking** — for log correlation across API→Worker→WebSocket pipeline
4. **Add database migrations** — currently relies on `create_index` at startup; consider a migration framework
5. **Add API versioning strategy** — legacy routes (`/firewall`, `/upload`, `/auth`) should have a deprecation timeline
6. **Consider connection pooling tuning** — Motor's default pool size may be insufficient under load

---

## Priority Action Items

| Priority | Action | Effort |
|---|---|---|
| 🔴 P0 | Rotate all secrets, remove hardcoded defaults, fail-fast on missing secrets | 2 hrs |
| 🔴 P0 | Add file size limit enforcement on CSV upload | 30 min |
| 🔴 P0 | Add [agent/.env](file:///c:/Users/Lenovo/Desktop/Startup-backend/agent/.env) to [.gitignore](file:///c:/Users/Lenovo/Desktop/Startup-backend/.gitignore) | 5 min |
| 🟠 P1 | Sanitize error responses (stop leaking `str(e)` to clients) | 1 hr |
| 🟠 P1 | Add rate limiting to upload endpoint | 15 min |
| 🟠 P1 | Add non-root user to Dockerfile | 10 min |
| 🟡 P2 | Standardize database access patterns | 2 hrs |
| 🟡 P2 | Replace `print()` with structured logging | 2 hrs |
| 🟡 P2 | Add IP validation on ban/unban endpoints | 30 min |
| 🔵 P3 | Add uploaded file cleanup | 1 hr |
| 🔵 P3 | Remove MongoDB port exposure from docker-compose | 5 min |
| 🔵 P3 | Cache [get_settings()](file:///c:/Users/Lenovo/Desktop/Startup-backend/app/config/config.py#36-38) with `@lru_cache` | 5 min |
